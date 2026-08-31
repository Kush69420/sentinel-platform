"""STATIC-SOURCE REGRESSION TRIPWIRE — NOT FUNCTIONAL COVERAGE.

REMEDIATION-PLAN.md §2.2: every assertion in this file is a substring/ordering
match against APP_SOURCE, the raw *text* of app.py (or a template file) — it
never imports Flask's test_client() and passes with zero runtime dependencies
installed. That makes it good at one narrow thing (catching a known-bad
pattern, e.g. a fallback dev password string, from silently reappearing in the
source) and useless at the thing it was previously *treated* as: proof that
payments, LEA approval, or IDOR guards actually behave correctly at runtime.
For example, the webhook checks below only assert that the string
"verify_webhook(" appears at a lower string INDEX than "credit_payment_order("
— satisfied even by an empty guard body or by dead code containing those two
tokens in that order, regardless of what either function actually does.

Real test_client()-based coverage for those three areas now lives in:
  - tests/test_payments_webhook.py         (webhook signature + idempotent credit)
  - tests/test_lea_application_approval.py (admin-only approve/reject + DB transitions)
  - tests/test_password_reset_flow.py      (issue/consume, single-use, TTL, hashed-at-rest)

Keep this file — it still catches a regressed dead-code pattern before those
tests would even run — but do not add new assertions here to "cover" a
behavior; add a real test_client() test in one of the files above instead.

Everything below this point is unchanged from before the audit and documents
the specific defects fixed on day 1:

  1. Approved accounts were created with no ``password_hash``, and login treated
     an empty hash as "accept the literal string ``dev123``".
  2. ``loadUsers()`` in the admin UI interpolated registration data straight into
     ``innerHTML`` — the same stored-XSS class as the already-fixed
     ``loadVerification()``, reachable through a different tab.
  3. Every gate in ``run_tool_generic`` was written ``if service and ...``, so a
     tool code with no ``services`` row skipped all of them and ran uncharged.
  4. ``_client_ip()`` returned a client-supplied header, defeating the login rate
     limit and the lockout counter.

Most assertions are made against the source rather than a live server because
these are absence-of-a-pattern properties: the point is that the dangerous shape
never comes back, anywhere, not that one call site currently behaves.
"""
import os
import re
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

APP_SOURCE = open(os.path.join(BASE, "app.py"), encoding="utf-8").read()


def template(name):
    with open(os.path.join(BASE, "templates", name), encoding="utf-8") as fh:
        return fh.read()


class NoFallbackPasswordTest(unittest.TestCase):
    """An account with no usable credential must fail closed."""

    def test_dev_password_fallback_is_gone(self):
        self.assertNotIn("DEV_USER_PASSWORD", APP_SOURCE,
                         "the shared development password fallback is back in app.py")
        self.assertNotIn("dev123", APP_SOURCE)

    def test_login_requires_a_stored_hash(self):
        self.assertIn("password_ok = bool(stored_hash) and check_password_hash(stored_hash, password)",
                      APP_SOURCE, "login no longer requires a stored password hash")

    def test_approval_never_creates_an_account(self):
        """Approval grants clearance; it must not mint a passwordless row."""
        start = APP_SOURCE.index("def approve_lea_application")
        body = APP_SOURCE[start:start + 2600]
        self.assertNotIn("INSERT INTO bot_users", body,
                         "approve_lea_application creates accounts again — those rows have no password")

    def test_signup_hashes_the_chosen_password(self):
        start = APP_SOURCE.index("def user_signup")
        body = APP_SOURCE[start:start + 3000]
        self.assertIn("generate_password_hash(password)", body)

    def test_password_change_will_not_accept_a_missing_hash(self):
        start = APP_SOURCE.index("def user_password_change")
        body = APP_SOURCE[start:start + 1800]
        self.assertNotIn("getenv(\"DEV_USER_PASSWORD\"", body)


class ResetTokenTest(unittest.TestCase):
    """The admin reset endpoint used to return success and do nothing at all."""

    def test_admin_reset_issues_a_real_token(self):
        start = APP_SOURCE.index("def admin_password_reset")
        body = APP_SOURCE[start:start + 1800]
        self.assertIn("issue_reset_token(", body,
                      "admin_password_reset is a stub again")

    def test_tokens_are_stored_hashed(self):
        start = APP_SOURCE.index("def issue_reset_token")
        body = APP_SOURCE[start:start + 1200]
        self.assertIn("generate_password_hash(token)", body,
                      "reset tokens must not be stored in plaintext")

    def test_consuming_a_token_burns_it(self):
        start = APP_SOURCE.index("def consume_reset_token")
        body = APP_SOURCE[start:start + 1200]
        self.assertIn("SET used_at=NOW()", body, "reset tokens must be single-use")


class FailClosedServiceGateTest(unittest.TestCase):
    """A missing ``services`` row is not permission."""

    def test_unknown_tool_code_is_rejected(self):
        start = APP_SOURCE.index("def run_tool_generic")
        body = APP_SOURCE[start:start + 4000]
        self.assertIn("if not service:", body,
                      "run_tool_generic no longer fails closed on an unknown tool code")

    def test_gates_are_not_conditional_on_the_row_existing(self):
        start = APP_SOURCE.index("def run_tool_generic")
        body = APP_SOURCE[start:start + 4000]
        for skipped in ("if service and not service.get(\"is_enabled\")",
                        "if service and service.get(\"maintenance_mode\")",
                        "if service and service.get(\"status\")"):
            self.assertNotIn(skipped, body,
                             "gate is skippable by using a tool code with no services row")

    def test_subscriber_lookup_is_no_longer_an_untracked_alias(self):
        self.assertNotIn('"subscriber_lookup"', APP_SOURCE.replace(
            "# ran uncharged — which is exactly how `subscriber_lookup` became a free,", ""),
            "subscriber_lookup is wired up again without a services row")

    def test_lookup_is_behind_the_clearance_decorator(self):
        start = APP_SOURCE.index('@app.route("/api/tools/run"')
        self.assertIn("@verified_required", APP_SOURCE[start:start + 200],
                      "the tool runner must require LEA clearance, not just a session")

    def test_a_hit_is_billed_and_logged(self):
        start = APP_SOURCE.index("def charge_for_lookup")
        body = APP_SOURCE[start:start + 1600]
        self.assertIn("INSERT INTO search_logs", body)
        self.assertIn("INSERT INTO credit_transactions", body)
        self.assertIn("AND credits >= %s", body,
                      "the debit must not be able to drive a balance negative")


class ClientIpTest(unittest.TestCase):
    def test_forwarded_header_is_not_read_directly(self):
        start = APP_SOURCE.index("def _client_ip")
        body = APP_SOURCE[start:start + 700]
        # The docstring names the header; only a real read of it is a defect.
        self.assertNotIn('request.headers.get("X-Forwarded-For")', body,
                         "_client_ip trusts a client-supplied header again")
        self.assertIn("request.remote_addr", body)

    def test_proxy_fix_is_wired_with_an_explicit_hop_count(self):
        self.assertIn("ProxyFix(", APP_SOURCE)
        self.assertIn("TRUSTED_PROXY_COUNT", APP_SOURCE)


class InnerHtmlEscapingTest(unittest.TestCase):
    """Generic guard against the stored-XSS class, not just the two known sites.

    Anything an unauthenticated or unverified person can put in the database —
    their name, phone, department, a search query, an uploaded filename — must be
    escaped before it reaches ``innerHTML``. This scans every render function so
    a third instance cannot be introduced quietly.
    """

    # Field expressions carrying user-supplied text. The trailing lookahead skips
    # comparisons like ${u.status==='blocked'?'red':''} — those branch on the
    # value and emit a fixed literal, they never write the value into the page.
    TAINTED = re.compile(
        r"""\$\{\s*(
            [aucbxtjs]\.(full_name|name|phone|department|designation|official_email|unit
                        |jurisdiction|status|title|case_reference|query|record_key
                        |uploaded_by|source_type|admin_name|action|description|provider_name
                        |model_name|base_url|last_error|text|label|detail|source|tag)
            |workspace\.batch\.original_filename
        )
        (?!\s*(===|==|!==|!=|\.(includes|indexOf|startsWith)))""",
        re.VERBOSE,
    )

    TEMPLATES = ("admin.html", "dashboard.html", "workspace.html")

    def test_no_tainted_field_reaches_innerhtml_unescaped(self):
        offenders = []
        for name in self.TEMPLATES:
            for lineno, line in enumerate(template(name).split("\n"), 1):
                if "innerHTML" not in line:
                    continue
                for match in self.TAINTED.finditer(line):
                    offenders.append(f"{name}:{lineno}: {match.group(0)}")
        self.assertEqual([], offenders,
                         "user-controlled values interpolated into innerHTML without esc():\n"
                         + "\n".join(offenders))

    def test_every_template_that_renders_defines_an_escaper(self):
        for name in self.TEMPLATES:
            body = template(name)
            if "innerHTML" not in body:
                continue
            self.assertIn("function esc(", body,
                          f"{name} renders HTML but defines no esc() helper")

    def test_escaper_is_null_safe(self):
        """A bare s.replace() throws on a number or null and silently breaks a table."""
        for name in self.TEMPLATES:
            body = template(name)
            match = re.search(r"function esc\(s\)\{return ([^;]*?)\.replace", body)
            if not match:
                continue
            self.assertIn("String(", match.group(1),
                          f"{name}'s esc() is not null-safe")

    def test_the_two_known_regressions_specifically(self):
        admin = template("admin.html")
        users_line = next(l for l in admin.split("\n") if "usersBody.innerHTML" in l)
        for field in ("u.name", "u.phone", "u.department", "u.status"):
            self.assertIn("esc(" + field, users_line,
                          f"loadUsers() interpolates {field} raw — this is the known Critical")


class RouteGuardTest(unittest.TestCase):
    """Every route that touches data must state its own guard."""

    def guard_for(self, route):
        start = APP_SOURCE.index(f'@app.route("{route}"')
        return APP_SOURCE[start:APP_SOURCE.index("def ", start)]

    def test_lea_verification_is_authenticated(self):
        guard = self.guard_for("/api/lea/register")
        self.assertIn("@user_required", guard,
                      "LEA verification upload is unauthenticated again")
        self.assertIn("@rate_limit", guard)

    def test_signup_is_rate_limited(self):
        self.assertIn("@rate_limit", self.guard_for("/api/user/signup"))

    def test_uploads_require_admin(self):
        self.assertIn("@admin_required", self.guard_for("/uploads/<filename>"))

    def test_payment_endpoints_require_a_session(self):
        self.assertIn("@user_required", self.guard_for("/api/payments/checkout"))
        self.assertIn("@admin_required", self.guard_for("/api/admin/payments/orders"))


class PaymentSeamTest(unittest.TestCase):
    """Crediting must happen in exactly one place, and be replay-safe."""

    def test_provider_is_swappable(self):
        for name in ("class PaymentProvider", "class ManualProvider", "class RazorpayProvider"):
            self.assertIn(name, APP_SOURCE)
        self.assertIn("PAYMENT_PROVIDERS = {", APP_SOURCE)

    def test_webhook_verifies_a_signature_before_crediting(self):
        start = APP_SOURCE.index("def payments_webhook")
        body = APP_SOURCE[start:start + 2000]
        verify_at = body.index("verify_webhook(")
        credit_at = body.index("credit_payment_order(")
        self.assertLess(verify_at, credit_at,
                        "the webhook credits before verifying the signature")

    def test_razorpay_signature_uses_a_constant_time_compare(self):
        start = APP_SOURCE.index("class RazorpayProvider")
        body = APP_SOURCE[start:start + 4000]
        self.assertIn("hmac.compare_digest", body)

    def test_crediting_is_idempotent(self):
        start = APP_SOURCE.index("def credit_payment_order")
        body = APP_SOURCE[start:start + 1600]
        self.assertIn("if order_row[\"status\"] == \"paid\":", body)
        self.assertIn("AND status<>'paid'", body,
                      "a replayed webhook could credit the same order twice")

    def test_buying_credits_does_not_grant_clearance(self):
        """Money buys credits; the gov-ID review buys access. Keep them separate."""
        start = APP_SOURCE.index("def credit_payment_order")
        body = APP_SOURCE[start:start + 1600]
        self.assertNotIn("verification_status", body)


class MigrationTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(BASE, "migration_selfserve_auth.sql"), encoding="utf-8") as fh:
            self.sql = fh.read()

    def test_email_is_unique(self):
        self.assertIn("UNIQUE KEY uniq_official_email", self.sql,
                      "login matches on email, so duplicates would pick an arbitrary account")

    def test_blank_emails_are_normalised_before_the_unique_index(self):
        self.assertLess(self.sql.index("SET official_email = NULL WHERE official_email = ''"),
                        self.sql.index("uniq_official_email"))

    def test_clearance_has_its_own_column(self):
        self.assertIn("verification_status", self.sql)

    def test_order_uniqueness_prevents_double_credit(self):
        self.assertIn("UNIQUE KEY uniq_provider_order", self.sql)

    def test_targets_the_settings_table_that_actually_exists(self):
        self.assertIn("INSERT INTO app_settings", self.sql)
        self.assertNotIn("INSERT INTO settings ", self.sql)


if __name__ == "__main__":
    unittest.main()
