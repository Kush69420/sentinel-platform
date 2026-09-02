-- SENTINEL migration — neutralize the seeded default admin credential
-- Safe to run multiple times.
-- Run AFTER db_setup.sql, migration_admin_customization.sql, migration_fix_import_errors.sql,
-- migration_selfserve_auth.sql, migration_activity_log_actor.sql.
-- Run: mysql -u sentinel_user1 -p sentinel_db < migration_remove_default_admin.sql
--
-- What this changes, and why:
--   db_setup.sql used to unconditionally seed a super_admin row on every fresh
--   install: username=admin, password=admin123, hashed with a static salt
--   that has been sitting in git history since the initial commit. The INSERT
--   has now been removed from db_setup.sql (see that file), so it can never
--   appear on a NEW database again — tools/bootstrap_admin.py is how the
--   first real admin gets created instead.
--
--   Removing the INSERT from db_setup.sql does nothing for a database that
--   was already initialised by the OLD db_setup.sql: CREATE TABLE IF NOT
--   EXISTS is a no-op there, so the old INSERT simply never runs again, and
--   the already-seeded row sits untouched with a credential that ships in
--   the repo. This migration is what actually closes that hole on such a
--   database.
--
--   The row is disabled (is_active=0) and its password_hash overwritten with
--   an unusable placeholder, rather than deleted outright: deleting it would
--   either violate the admin_users(id) FK held by any existing activity_log
--   rows tied to that id, or leave a gap another idempotent script might
--   reintroduce. Disabling is sufficient on its own — _perform_admin_login()
--   in app.py filters `WHERE username=%s AND is_active=1`, so a disabled row
--   can never authenticate again no matter what password_hash holds.
--
--   Only the EXACT seeded row is touched: username='admin' AND password_hash
--   still equal to the literal hash db_setup.sql used to insert. An operator
--   who already noticed this seed and rotated its password themselves keeps
--   whatever they set — this must not clobber a real admin's live credential
--   just because the username still happens to be 'admin'. That also makes
--   this migration self-idempotent: after the first run the hash no longer
--   matches, so a second run matches zero rows.

USE sentinel_db;

UPDATE admin_users
SET is_active = 0,
    password_hash = 'disabled-by-migration_remove_default_admin:not-a-valid-login'
WHERE username = 'admin'
  AND password_hash = 'pbkdf2:sha256:600000$sentinelsalt1234$759d3c0805511946c952611fa5ce9b5f7b6b339fc60d70a80ee32657a174546a';

SELECT 'migration_remove_default_admin.sql applied' AS status;
