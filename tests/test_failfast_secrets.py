"""Day 2 (a) — SECRET_KEY / ENCRYPTION_KEY / DB_USER / DB_PASSWORD must fail fast
outside dev.

Before this fix, `app.py` fell back to a hardcoded `SECRET_KEY` and generated a
throwaway `ENCRYPTION_KEY` at every restart if the env vars were unset — silently
insecure in the first case, silently and permanently destructive (bricks every
encrypted gov-ID upload / 2FA secret / API key) in the second. Neither failure was
visible until something broke later.

DB_USER / DB_PASSWORD got the same treatment later (same file, same mechanism):
`DB_CONFIG` used to default to `root` / empty password, a plausible-looking real
local MySQL account rather than an obviously-broken placeholder, so a missing or
typo'd credential would not fail loudly — it would connect to the wrong database
silently, or pass the (DB-free) container healthcheck and 500 on the first request
that actually touches the database.

`app` is a singleton module already imported by every other test file in this
suite (with the dev fallback active, via `tests/__init__.py` setting
FLASK_ENV=development), so re-importing it in-process with different env vars
would not re-run its module-level code. These tests exercise the actual startup
path as a subprocess instead.

FLASK_ENV/SECRET_KEY/ENCRYPTION_KEY/DB_USER/DB_PASSWORD are forced to the empty
string rather than simply removed from the child environment: this worktree is
nested inside a checkout that has its own real `.env` with FLASK_ENV=development
(and real DB_USER/DB_PASSWORD values) for local dev, and python-dotenv's
`load_dotenv()` walks parent directories to find it. Because `load_dotenv()`
defaults to `override=False`, a variable that is already present (even empty) in
the environment is left alone, which is what makes these subprocess environments
deterministic regardless of what's on disk above this checkout.
"""
import os
import subprocess
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_import(extra_env):
    env = dict(os.environ)
    env["FLASK_ENV"] = ""
    env["SECRET_KEY"] = ""
    env["ENCRYPTION_KEY"] = ""
    env["DB_USER"] = ""
    env["DB_PASSWORD"] = ""
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=BASE,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class FailFastSecretKeyTest(unittest.TestCase):
    def test_missing_secret_key_outside_dev_raises(self):
        result = _run_import({})
        self.assertNotEqual(result.returncode, 0, "app.py imported despite no SECRET_KEY outside dev")
        self.assertIn("SECRET_KEY is not set", result.stderr)

    def test_flask_env_unset_defaults_to_production_in_source(self):
        """Merely leaving FLASK_ENV unset (not =production) must still fail closed.

        Asserted against source rather than a subprocess: this worktree is nested
        inside a checkout with its own dev `.env` (FLASK_ENV=development), and
        python-dotenv walks parent directories to find it — so a subprocess with
        FLASK_ENV genuinely absent from its environ is not reproducible here. The
        default itself is a one-line, unambiguous read.
        """
        import re
        with open(os.path.join(BASE, "app.py"), encoding="utf-8") as fh:
            src = fh.read()
        match = re.search(r'FLASK_ENV\s*=\s*os\.getenv\("FLASK_ENV",\s*"([^"]+)"\)', src)
        self.assertIsNotNone(match, "could not find the FLASK_ENV default in app.py")
        self.assertEqual(match.group(1), "production",
                         "an unset FLASK_ENV must default to production-like (fail closed), not open")

    def test_dev_env_falls_back_without_raising(self):
        result = _run_import({"FLASK_ENV": "development"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_secret_key_present_outside_dev_succeeds(self):
        # DB_USER/DB_PASSWORD must also be supplied here: app.py checks them
        # before ENCRYPTION_KEY (module order), so leaving them empty would make
        # this fail on the DB check instead of the one this test targets.
        result = _run_import({
            "SECRET_KEY": "a-real-production-secret",
            "DB_USER": "sentinel_user1",
            "DB_PASSWORD": "a-real-db-password",
            "ENCRYPTION_KEY": "",
        })
        # ENCRYPTION_KEY is still missing, so this must fail on that check instead.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENCRYPTION_KEY is not set", result.stderr)
        self.assertNotIn("SECRET_KEY is not set", result.stderr)
        self.assertNotIn("DB_USER", result.stderr)
        self.assertNotIn("DB_PASSWORD", result.stderr)


class FailFastEncryptionKeyTest(unittest.TestCase):
    def test_missing_encryption_key_outside_dev_raises(self):
        result = _run_import({
            "SECRET_KEY": "a-real-production-secret",
            "DB_USER": "sentinel_user1",
            "DB_PASSWORD": "a-real-db-password",
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENCRYPTION_KEY is not set", result.stderr)

    def test_both_present_outside_dev_succeeds(self):
        # Must be a syntactically valid Fernet key (32 url-safe base64-encoded
        # bytes) — app.py constructs a real Fernet() instance at import time.
        # DB_USER/DB_PASSWORD are also supplied so this exercises a fully clean
        # startup, not an early exit on the DB check.
        result = _run_import({
            "SECRET_KEY": "a-real-production-secret",
            "ENCRYPTION_KEY": "KlG7epulWd75wuSmn0yhB8trSvald3SSHbDcnvgRsIw=",
            "DB_USER": "sentinel_user1",
            "DB_PASSWORD": "a-real-db-password",
        })
        self.assertEqual(result.returncode, 0, result.stderr)


class FailFastDbCredentialsTest(unittest.TestCase):
    """DB_USER / DB_PASSWORD get the same fail-fast treatment as the secrets

    above — see app.py, DB_CONFIG. Every case here also supplies SECRET_KEY and
    ENCRYPTION_KEY so the assertions land on the DB check, not an earlier one.
    """

    _SECRETS = {
        "SECRET_KEY": "a-real-production-secret",
        "ENCRYPTION_KEY": "KlG7epulWd75wuSmn0yhB8trSvald3SSHbDcnvgRsIw=",
    }

    def test_missing_db_user_outside_dev_raises(self):
        result = _run_import({**self._SECRETS, "DB_PASSWORD": "a-real-db-password"})
        self.assertNotEqual(result.returncode, 0, "app.py imported despite no DB_USER outside dev")
        self.assertIn("DB_USER", result.stderr)
        self.assertIn("not set", result.stderr)

    def test_missing_db_password_outside_dev_raises(self):
        result = _run_import({**self._SECRETS, "DB_USER": "sentinel_user1"})
        self.assertNotEqual(result.returncode, 0, "app.py imported despite no DB_PASSWORD outside dev")
        self.assertIn("DB_PASSWORD", result.stderr)
        self.assertIn("not set", result.stderr)

    def test_missing_both_db_vars_outside_dev_raises_naming_both(self):
        result = _run_import(self._SECRETS)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DB_USER", result.stderr)
        self.assertIn("DB_PASSWORD", result.stderr)

    def test_dev_env_falls_back_on_db_vars_without_raising(self):
        # Mirrors test_dev_env_falls_back_without_raising above, but confirms the
        # DB defaults specifically (root / empty password) still work in dev.
        result = _run_import({"FLASK_ENV": "development"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_db_vars_present_outside_dev_succeeds(self):
        result = _run_import({
            **self._SECRETS,
            "DB_USER": "sentinel_user1",
            "DB_PASSWORD": "a-real-db-password",
        })
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
