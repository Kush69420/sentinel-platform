"""Encrypt and store a credential in the `integrations` table.

Run this from inside the app's own environment — it needs `ENCRYPTION_KEY`
from .env to encrypt the value (via app.py's `encrypt_text()`) and the same
`DB_CONFIG` app.py uses to reach the database. Typically run right after
tools/extract_ghunt_token.py has printed a master token on the machine that
holds GHunt's session.

The credential value is never accepted as a CLI argument — that would leave
it sitting in shell history — it is read from a hidden prompt (`getpass`)
and asked for twice to catch typos. Nothing sensitive is echoed back; the
confirmation message only shows the last few characters.

Usage:
    python3 -m tools.set_integration_credential --name google_master_token

`--name google_master_token` is the credential sentinel_modules/gaia_resolver.py
reads back (email_lookup module, Step A). The script itself is written
generically against the existing `integrations` table (db_setup.sql, ~line 211)
so it can store any integration's credential the same way — matching an
existing row by `name`, updating only `api_key`/`is_enabled`, or creating a
new row with `--category`/`--description` if none exists yet.
"""
import argparse
import getpass
import sys


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Encrypt and store a credential in the integrations table.",
    )
    parser.add_argument(
        "--name", required=True,
        help="integrations.name to update (e.g. google_master_token). "
             "A new row is created if none exists yet.",
    )
    parser.add_argument(
        "--category", default="google",
        help="integrations.category for a newly created row (default: google). "
             "Ignored if a row with this --name already exists.",
    )
    parser.add_argument(
        "--description", default=None,
        help="integrations.description for a newly created row. "
             "Ignored if a row with this --name already exists.",
    )
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    name = args.name.strip()
    if not name:
        parser.error("--name must not be empty")

    value = getpass.getpass(f"Value to store for integrations.name='{name}' (hidden, not echoed): ")
    if not value:
        print("Empty value entered — nothing was stored.", file=sys.stderr)
        return 1
    confirm = getpass.getpass("Re-enter to confirm: ")
    if value != confirm:
        print("Values did not match — nothing was stored.", file=sys.stderr)
        return 1

    # Deferred: importing app.py triggers its fail-fast secrets/DB checks,
    # which only makes sense once real CLI args have already parsed cleanly
    # and we actually have a value worth encrypting.
    import app as app_module

    encrypted = app_module.encrypt_text(value)

    conn = app_module.get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO integrations (name, category, description, api_key, is_enabled)
            VALUES (%s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                api_key = VALUES(api_key),
                is_enabled = 1,
                updated_at = CURRENT_TIMESTAMP
            """,
            (name, args.category, args.description, encrypted),
        )
        conn.commit()
        cursor.close()
    finally:
        conn.close()

    masked = value[-4:] if len(value) > 4 else value
    print(f"Stored credential for integrations.name='{name}' (…{masked}), is_enabled=1.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
