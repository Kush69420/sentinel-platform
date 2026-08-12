"""Security-debt Critical #1 — stored XSS in the admin LEA verification queue.

loadVerification() in templates/admin.html builds each application card via
innerHTML, interpolating fields ('full_name', 'department', 'designation',
'official_email', 'unit', 'jurisdiction', 'phone', ...) that come straight from
the public, unauthenticated /api/lea/register form. Every interpolated field in
that template literal must go through the file's esc() helper, same as the rest
of admin.html already does; a raw ${a.field} reintroduces the hole.

This can't be exercised through a browser DOM in this sandbox, so it asserts
directly against the served template source: every field loadVerification()
reads from the applications API must be esc()-wrapped, and no raw interpolation
of those fields may remain.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class LoadVerificationXssTests(unittest.TestCase):
    FIELDS = [
        "application_id", "full_name", "status", "department", "designation",
        "phone", "official_email", "unit", "jurisdiction",
    ]

    def setUp(self):
        import app as app_module
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def _load_verification_body(self):
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        match = re.search(r"async function loadVerification\(\)\{.*?\}catch\(e\)\{verifList\.innerHTML='Failed'\}\}", html)
        self.assertIsNotNone(match, "loadVerification() not found in served admin.html")
        return match.group(0)

    def test_every_applicant_controlled_field_is_escaped(self):
        body = self._load_verification_body()
        for field in self.FIELDS:
            with self.subTest(field=field):
                self.assertIn(
                    f"esc(a.{field}", body,
                    f"${{a.{field}}} must be routed through esc() in loadVerification()",
                )
                self.assertNotRegex(
                    body, rf"\$\{{a\.{field}(?!\w)(?:\|\|'')?\}}",
                    f"found a raw, unescaped ${{a.{field}}} interpolation in loadVerification()",
                )


if __name__ == "__main__":
    unittest.main()
