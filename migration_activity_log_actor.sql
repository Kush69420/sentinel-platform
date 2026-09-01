-- SENTINEL migration — activity_log polymorphic actor
-- Safe to run multiple times.
-- Run AFTER db_setup.sql and migration_admin_customization.sql.
-- Run: mysql -u sentinel_user1 -p sentinel_db < migration_activity_log_actor.sql
--
-- What this changes, and why:
--   `activity_log.admin_id` has a foreign key to `admin_users(id)`, but twelve
--   call sites pass a `bot_users.id` — signup, login, failed login, account
--   lockout, recovery-code use, logout, password reset request/confirm,
--   password change, LEA verification submission, payment order created and
--   payment captured. MySQL rejects each of those inserts with error 1452
--   (foreign key constraint fails), and because log_activity() wraps the insert
--   in try/except the failure is printed and swallowed. The audit entry simply
--   never exists. There is no user-side audit trail at all today.
--
--   The fix does NOT need new columns: `actor_type` and `actor_id` already
--   exist, added by migration_admin_customization.sql, and carry no FK. The
--   application change routes user actors through those with `admin_id` left
--   NULL, which the FK permits. This file exists to (a) guarantee those columns
--   are present on any database that somehow skipped that migration, and
--   (b) add the index that makes the resulting rows queryable.
--
--   Without the index, "show me everything user 2 did" is a full table scan of
--   activity_log — the one query the fix is meant to enable.
--
--   NOT changed on purpose: the `admin_id` FK stays exactly as it is. Dropping
--   it to make one column serve both actor kinds would silently un-protect the
--   admin audit trail, which is the half that currently works.

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

-- ─────────────────────────────────────────────
-- 1. ACTOR COLUMNS — no-ops where migration_admin_customization.sql already ran
-- ─────────────────────────────────────────────
CALL add_col_if_missing('activity_log', 'actor_type', 'actor_type VARCHAR(40) DEFAULT ''admin''');
CALL add_col_if_missing('activity_log', 'actor_id',   'actor_id INT NULL');
CALL add_col_if_missing('activity_log', 'ip_address', 'ip_address VARCHAR(80)');

-- ─────────────────────────────────────────────
-- 2. INDEX — makes per-actor audit queries usable
--
-- Composite and in this order because actor_id alone is ambiguous: admin 2 and
-- user 2 are different people. Every lookup is "this kind of actor, this id".
-- ─────────────────────────────────────────────
CALL add_idx_if_missing('activity_log', 'idx_actor',
  'INDEX idx_actor (actor_type, actor_id)');

DROP PROCEDURE IF EXISTS add_col_if_missing;
DROP PROCEDURE IF EXISTS add_idx_if_missing;

-- ─────────────────────────────────────────────
-- Backfill is deliberately NOT attempted.
--
-- The rows this fix would have written were rejected outright, so there is
-- nothing to migrate — no historical user activity exists to repair. Existing
-- rows are all admin actions and already have actor_type='admin' by column
-- default; leaving actor_id NULL on them is honest, since admin_id already
-- carries that identity for those rows.
-- ─────────────────────────────────────────────
