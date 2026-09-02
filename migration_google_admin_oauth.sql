-- SENTINEL migration — Google sign-in for the admin console
-- Safe to run multiple times.
-- Run AFTER db_setup.sql, migration_admin_customization.sql, migration_fix_import_errors.sql,
-- migration_selfserve_auth.sql, migration_activity_log_actor.sql, migration_remove_default_admin.sql.
-- Run: mysql -u sentinel_user1 -p sentinel_db < migration_google_admin_oauth.sql
--
-- What this changes, and why:
--   Admin authentication moves from a local username/password to "Sign in with
--   Google". `google_email` is the link between a Google account and an
--   admin_users row, and it is an ALLOW-LIST, not a registration mechanism:
--   app.py looks up an existing row by this column and refuses the login if
--   there is no match. A Google account that nobody has explicitly authorized
--   here can never become an admin, which is the whole security property —
--   auto-creating an admin row on first Google login would hand super_admin to
--   anyone on the internet with a Google account.
--
--   NULL means "this admin cannot use Google sign-in" (password only). The
--   UNIQUE index therefore has to tolerate multiple NULLs — which MySQL's
--   UNIQUE does, by design: NULLs are never equal to each other, so any number
--   of password-only admins can coexist. What it does prevent is two admin rows
--   claiming the same Google identity, which would make the login lookup
--   ambiguous and its outcome depend on row order.
--
--   Emails are stored lowercased. Google treats the local part as
--   case-insensitive and returns a consistent casing, but the comparison in
--   app.py lowercases both sides anyway rather than trusting that.

USE sentinel_db;

DELIMITER $$
DROP PROCEDURE IF EXISTS add_col_if_missing $$
CREATE PROCEDURE add_col_if_missing(IN tbl VARCHAR(64), IN col VARCHAR(64), IN ddl TEXT)
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND COLUMN_NAME = col
  ) THEN
    SET @s = CONCAT('ALTER TABLE `', tbl, '` ADD COLUMN ', ddl);
    PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
  END IF;
END $$

DROP PROCEDURE IF EXISTS add_idx_if_missing $$
CREATE PROCEDURE add_idx_if_missing(IN tbl VARCHAR(64), IN idx VARCHAR(64), IN ddl TEXT)
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND INDEX_NAME = idx
  ) THEN
    SET @s = CONCAT('ALTER TABLE `', tbl, '` ADD ', ddl);
    PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
  END IF;
END $$
DELIMITER ;

CALL add_col_if_missing('admin_users', 'google_email',
  'google_email VARCHAR(255) NULL COMMENT ''Verified Google account authorized to sign in as this admin. NULL = password login only.''');

CALL add_idx_if_missing('admin_users', 'uniq_google_email',
  'UNIQUE KEY uniq_google_email (google_email)');

DROP PROCEDURE IF EXISTS add_col_if_missing;
DROP PROCEDURE IF EXISTS add_idx_if_missing;

SELECT 'migration_google_admin_oauth.sql applied' AS status;
