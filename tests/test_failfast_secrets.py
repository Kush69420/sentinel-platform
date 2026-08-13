"""Day 2 (a) — SECRET_KEY / ENCRYPTION_KEY must fail fast outside dev.

Before this fix, `app.py` fell back to a hardcoded `SECRET_KEY` and generated a
throwaway `ENCRYPTION_KEY` at every restart if the env vars were unset — silently
insecure in the first case, silently and permanently destructive (bricks every
encrypted gov-ID upload / 2FA secret / API key) in the second. Neither failure was
visible until something broke later.

`app` is a singleton module already imported by every other test file in this
suite (with the dev fallback active, via `tests/__init__.py` setting
FLASK_ENV=development), so re-importing it in-process with different env vars
would not re-run its module-level code. These tests exercise the actual startup
path as a subprocess instead.

FLASK_ENV/SECRET_KEY/ENCRYPTION_KEY are forced to the empty string rather than
simply removed from the child environment: this worktree is nested inside a
checkout that has its own real `.env` with FLASK_ENV=development for local dev,
and python-dotenv's `load_dotenv()` walks parent directories to find it. Because
`load_dotenv()` defaults to `override=False`, a variable that is already present
(even empty) in the environment is left alone, which is what makes these
subprocess environments deterministic regardless of what's on disk above this
checkout.
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
        result = _run_import({"SECRET_KEY": "a-real-production-secret", "ENCRYPTION_KEY": ""})
        # ENCRYPTION_KEY is still missing, so this must fail on that check instead.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENCRYPTION_KEY is not set", result.stderr)
        self.assertNotIn("SECRET_KEY is not set", result.stderr)


class FailFastEncryptionKeyTest(unittest.TestCase):
    def test_missing_encryption_key_outside_dev_raises(self):
        result = _run_import({"SECRET_KEY": "a-real-production-secret"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENCRYPTION_KEY is not set", result.stderr)

    def test_both_present_outside_dev_succeeds(self):
        # Must be a syntactically valid Fernet key (32 url-safe base64-encoded
        # bytes) — app.py constructs a real Fernet() instance at import time.
        result = _run_import({
            "SECRET_KEY": "a-real-production-secret",
            "ENCRYPTION_KEY": "KlG7epulWd75wuSmn0yhB8trSvald3SSHbDcnvgRsIw=",
        })
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
