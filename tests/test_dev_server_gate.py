"""The `if __name__ == "__main__"` block in app.py must not start Werkzeug's
interactive dev server (debug=True, bound to 0.0.0.0) outside FLASK_ENV=development.

Background: `python app.py` run directly on a server is dead code in the real deploy
path (gunicorn via wsgi.py — see the Dockerfile CMD), but a human running it "just to
check something" would otherwise get Werkzeug's interactive debugger, which is remote
code execution for anyone who can reach it. The SECRET_KEY/ENCRYPTION_KEY/DB_USER/
DB_PASSWORD fail-fast checks (see test_failfast_secrets.py) already catch most
accidental production-like runs earlier, at import time — but only when one of those
is actually missing. These tests cover the backstop: what happens when all of them
*are* set and execution actually reaches the bottom of the file.

These exercise `python app.py` as a real subprocess (not `import app`, and not calling
app.run() in-process) for the same reason test_failfast_secrets.py does: `app` is a
singleton already imported by every other test in this suite, and the `__main__`
block only runs when the file is executed directly, not on import. FLASK_ENV/
SECRET_KEY/ENCRYPTION_KEY/DB_USER/DB_PASSWORD are forced to real-looking values (or
explicitly to "") rather than removed from the child environment, for the same
load_dotenv(override=False)-vs-parent-.env reason documented there.
"""
import os
import subprocess
import sys
import time
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_REAL_SECRETS = {
    "SECRET_KEY": "a-real-production-secret",
    "ENCRYPTION_KEY": "KlG7epulWd75wuSmn0yhB8trSvald3SSHbDcnvgRsIw=",
    "DB_USER": "sentinel_user1",
    "DB_PASSWORD": "a-real-db-password",
}


def _base_env(extra):
    env = dict(os.environ)
    env["FLASK_ENV"] = ""
    env["SECRET_KEY"] = ""
    env["ENCRYPTION_KEY"] = ""
    env["DB_USER"] = ""
    env["DB_PASSWORD"] = ""
    env.update(extra)
    return env


class DevServerGateTest(unittest.TestCase):
    def test_refuses_outside_dev_even_with_all_secrets_present(self):
        """The case this fix actually targets: nothing is missing, so the
        import-time fail-fast checks all pass, and the `__main__` block itself
        must still refuse to call app.run() outside FLASK_ENV=development.
        """
        env = _base_env(_REAL_SECRETS)
        result = subprocess.run(
            [sys.executable, "app.py"],
            cwd=BASE,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(
            result.returncode, 0,
            "app.py ran the Werkzeug dev server outside FLASK_ENV=development",
        )
        self.assertIn("Refusing to start", result.stderr)
        self.assertIn("gunicorn", result.stderr)
        # Confirm it got past the earlier fail-fast checks (i.e. this is the
        # __main__-block refusal, not an early import-time exit for an unrelated
        # missing var).
        self.assertNotIn("SECRET_KEY is not set", result.stderr)
        self.assertNotIn("ENCRYPTION_KEY is not set", result.stderr)
        self.assertNotIn("DB_USER", result.stderr)

    def test_starts_in_dev(self):
        """FLASK_ENV=development must still reach app.run() as before this fix."""
        env = _base_env({"FLASK_ENV": "development"})
        proc = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=BASE,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            # Give it a moment to either bind and block (the expected outcome) or
            # exit (a regression, or an unrelated environment problem like the port
            # already being in use).
            time.sleep(2)
            still_running = proc.poll() is None
            if not still_running:
                _, stderr = proc.communicate(timeout=5)
                self.fail(
                    "app.py exited instead of starting the dev server in "
                    f"FLASK_ENV=development (returncode={proc.returncode}):\n{stderr}"
                )
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
