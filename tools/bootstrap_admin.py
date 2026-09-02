"""Create (or rotate) the first SENTINEL admin account — Phase-1 deploy-blocker #1.

db_setup.sql used to seed a super_admin row unconditionally (username=admin,
password=admin123, a static-salt hash checked into git history). That seed has
been removed — see db_setup.sql and migration_remove_default_admin.sql, which
neutralizes any already-seeded row on an existing database. This script is how
an operator creates the first real admin instead, once db_setup.sql (and the
rest of the migration order in CLAUDE.md) has been applied.

Usage:
    python -m tools.bootstrap_admin --username admin --name "Ops Admin"
    python -m tools.bootstrap_admin --username admin --name "Ops Admin" --password 'a-strong-passphrase-1'
    python -m tools.bootstrap_admin --username admin --name "Ops Admin" --force   # rotate an existing row
    python -m tools.bootstrap_admin --username admin --name "Ops Admin" --google-email someone@example.com

If --password is omitted, a random password meeting the platform's password
policy (see password_problem() in app.py — same policy user signup/password-
change already enforces, not a separate one invented here) is generated and
printed to stdout exactly once. It is never logged, never written anywhere
else, and cannot be recovered after this process exits — write it down before
closing the terminal.

--google-email is an ALLOW-LIST ENTRY, not registration: it authorizes one
already-existing address to use the "Sign in with Google" button on /admin by
recording it on this admin row (admin_users.google_email). Only an address
recorded here this way can ever sign in with Google — the OAuth callback in
app.py looks up an existing row by verified email and refuses the login on no
match; it never creates an admin row on its own. Passing --google-email
without --password leaves this admin with no usable password (a placeholder
hash that can never match any input), i.e. Google-only. Combine both to give
an admin both doors.

By default this refuses to touch a username that already exists, so it can't
silently clobber a live admin's credential. Pass --force to rotate an
existing row's password (and reactivate it, and clear its lockout counters) —
useful for recovering access to an account that lost its password, or for
finishing the neutralization of the old seeded 'admin' row by giving it a
real credential instead of leaving it disabled.

This does not touch role enforcement: the created row's `role` is a data
value only (RBAC's role_required() decorator is deliberately applied to
nothing — see CLAUDE.md), same as it always was for the seeded row.
"""
import argparse
import secrets
import sys

ROLE_CHOICES = ("super_admin", "manager", "support")


def _generate_password(app_module) -> str:
    """A random password that satisfies password_problem() on the first try
    in the overwhelming common case, with a bounded retry as a backstop
    rather than a hand-rolled character-class guarantee."""
    for _ in range(5):
        candidate = secrets.token_urlsafe(24)
        if app_module.password_problem(candidate) is None:
            return candidate
    # Should be unreachable — token_urlsafe(24) is base64-url alphabet, which
    # contains both letters and digits with overwhelming probability well
    # under 5 attempts. Fail loudly rather than hand back something unvetted.
    raise RuntimeError("could not generate a policy-compliant password")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Create or rotate the first SENTINEL admin account.",
    )
    parser.add_argument("--username", default="admin", help="admin_users.username (default: admin)")
    parser.add_argument("--name", default="Super Admin", help="admin_users.name (default: 'Super Admin')")
    parser.add_argument("--role", default="super_admin", choices=ROLE_CHOICES,
                         help="admin_users.role (default: super_admin). Data value only — "
                              "RBAC enforcement is deliberately not wired up (see CLAUDE.md).")
    parser.add_argument("--password", default=None,
                         help="password to set. Omit to auto-generate one, printed once.")
    parser.add_argument("--google-email", default=None,
                         help="Google account authorized to sign in as this admin. This is an "
                              "allow-list entry, not a registration: only an address listed here "
                              "can use the Google button. Implies no password is needed.")
    parser.add_argument("--force", action="store_true",
                         help="rotate an existing row with this username instead of refusing.")
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    import app as app_module  # deferred: importing app.py triggers its fail-fast
                               # secrets check and DB config load, which only makes
                               # sense once real CLI args have already parsed cleanly.

    username = args.username.strip()
    if not username:
        parser.error("--username must not be empty")

    google_email = (args.google_email or "").strip().lower() or None
    if google_email and "@" not in google_email:
        parser.error("--google-email must be an email address")

    if args.password is not None:
        problem = app_module.password_problem(args.password)
        if problem:
            parser.error(f"--password rejected: {problem}")
        password = args.password
        generated = False
    elif google_email:
        # Google-only admin: deliberately leave no usable password rather than
        # generating one nobody will ever type. password_hash is NOT NULL, so it
        # gets a placeholder that cannot match any input — check_password_hash()
        # returns False for a malformed hash rather than raising, so the password
        # door simply answers "invalid credentials" for this account.
        password = None
        generated = False
    else:
        password = _generate_password(app_module)
        generated = True

    conn = app_module.get_db()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM admin_users WHERE username=%s", (username,))
        existing = cursor.fetchone()
        if existing and not args.force:
            print(
                f"Refusing to touch existing admin '{username}' (id={existing['id']}) "
                f"without --force.",
                file=sys.stderr,
            )
            return 1

        password_hash = (
            app_module.generate_password_hash(password)
            if password is not None
            else "google-oauth-only:not-a-valid-login"
        )
        if existing:
            cursor.execute(
                """
                UPDATE admin_users
                SET name=%s, password_hash=%s, role=%s, is_active=1,
                    google_email=%s, failed_login_count=0, locked_until=NULL
                WHERE id=%s
                """,
                (args.name, password_hash, args.role, google_email, existing["id"]),
            )
            admin_id = existing["id"]
            action = "admin_bootstrap_rotated"
        else:
            cursor.execute(
                "INSERT INTO admin_users (name, username, password_hash, role, is_active, google_email) "
                "VALUES (%s,%s,%s,%s,1,%s)",
                (args.name, username, password_hash, args.role, google_email),
            )
            admin_id = cursor.lastrowid
            action = "admin_bootstrapped"
        conn.commit()
    finally:
        conn.close()

    app_module.log_activity(
        admin_id, action,
        f"Admin '{username}' ({args.role}) provisioned via tools/bootstrap_admin.py",
    )

    print(f"Admin '{username}' (id={admin_id}, role={args.role}) is ready.")
    if google_email:
        print(f"Google sign-in authorized for: {google_email}")
        if password is None:
            print("No password set — this admin signs in with Google only.")
    if generated:
        print(f"Generated password (shown once, not recoverable after this): {password}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
