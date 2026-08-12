-- SENTINEL migration — self-serve signup, LEA verification gate, payments scaffolding
-- Safe to run multiple times.
-- Run AFTER db_setup.sql and migration_admin_customization.sql.
-- Run: mysql -u sentinel_user1 -p sentinel_db < migration_selfserve_auth.sql
--
-- What this changes, and why:
--   Before, an account only existed once an admin approved an LEA application, and
--   it was created with no password_hash at all. Now anyone can sign up with their
--   own password; the account exists immediately but holds no data clearance.
--   `status` therefore means "is this account usable at all" and the new
--   `verification_status` means "has this operator been cleared for lookups".
--   Those are two orthogonal facts and must not share a column.

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
-- 1. BOT USERS — separate account state from data clearance
-- ─────────────────────────────────────────────
CALL add_col_if_missing('bot_users', 'verification_status',
  "verification_status ENUM('unverified','pending','approved','rejected') NOT NULL DEFAULT 'unverified' AFTER status");
CALL add_col_if_missing('bot_users', 'verification_note',
  "verification_note TEXT NULL AFTER verification_status");
CALL add_col_if_missing('bot_users', 'verified_at',
  "verified_at TIMESTAMP NULL AFTER verification_note");
CALL add_col_if_missing('bot_users', 'password_set_at',
  "password_set_at TIMESTAMP NULL AFTER password_hash");
CALL add_col_if_missing('bot_users', 'updated_at',
  "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");

-- Email is a login identifier, so it must be unique. Blank strings would collide
-- under a UNIQUE index, so normalise them to NULL first (MySQL permits many NULLs).
UPDATE bot_users SET official_email = NULL WHERE official_email = '';

-- Drop the old non-unique index if present, then add the unique one.
DROP PROCEDURE IF EXISTS drop_idx_if_present;
DELIMITER $$
CREATE PROCEDURE drop_idx_if_present(IN tbl VARCHAR(64), IN idx VARCHAR(64))
BEGIN
  IF EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND INDEX_NAME = idx
  ) THEN
    SET @s = CONCAT('ALTER TABLE `', tbl, '` DROP INDEX `', idx, '`');
    PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
  END IF;
END $$
DELIMITER ;

CALL drop_idx_if_present('bot_users', 'idx_email');
CALL add_idx_if_missing('bot_users', 'uniq_official_email',
  'UNIQUE KEY uniq_official_email (official_email)');

-- Any account that predates this migration and was already approved keeps its
-- clearance; it was approved through the LEA queue by hand.
UPDATE bot_users SET verification_status = 'approved', verified_at = COALESCE(verified_at, NOW())
  WHERE status = 'approved' AND verification_status = 'unverified' AND lea_application_id IS NOT NULL;

-- ─────────────────────────────────────────────
-- 2. LEA APPLICATIONS — link back to the account that submitted them
-- ─────────────────────────────────────────────
CALL add_col_if_missing('lea_applications', 'user_id',
  'user_id INT NULL AFTER id');
CALL add_idx_if_missing('lea_applications', 'idx_user',
  'INDEX idx_user (user_id)');

-- ─────────────────────────────────────────────
-- 3. PASSWORD RESET / ACTIVATION TOKENS
--    Tokens are stored hashed. A leaked DB must not yield usable reset links.
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    purpose ENUM('reset','activation') NOT NULL DEFAULT 'reset',
    issued_by VARCHAR(100),
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES bot_users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
);

-- ─────────────────────────────────────────────
-- 4. PAYMENT ORDERS
--    Provider-agnostic. `provider='manual'` is an admin-confirmed bank transfer;
--    a real gateway later writes the same rows and reuses the same crediting path.
--    provider_order_id is UNIQUE so a replayed webhook cannot double-credit.
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payment_orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_ref VARCHAR(40) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    phone VARCHAR(20) NOT NULL,
    plan_id INT NULL,
    plan_name VARCHAR(50),
    credits INT NOT NULL,
    amount_inr INT NOT NULL,
    provider VARCHAR(30) NOT NULL DEFAULT 'manual',
    provider_order_id VARCHAR(120) NULL,
    provider_payment_id VARCHAR(120) NULL,
    status ENUM('pending','paid','failed','cancelled') NOT NULL DEFAULT 'pending',
    credited_at TIMESTAMP NULL,
    confirmed_by VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES bot_users(id) ON DELETE CASCADE,
    FOREIGN KEY (plan_id) REFERENCES recharge_plans(id) ON DELETE SET NULL,
    UNIQUE KEY uniq_provider_order (provider, provider_order_id),
    INDEX idx_status (status),
    INDEX idx_user (user_id)
);

-- ─────────────────────────────────────────────
-- 5. RECHARGE PLANS — admin-editable presentation fields
-- ─────────────────────────────────────────────
CALL add_col_if_missing('recharge_plans', 'description',
  'description VARCHAR(255) NULL AFTER price_inr');
CALL add_col_if_missing('recharge_plans', 'sort_order',
  'sort_order INT DEFAULT 0');
CALL add_col_if_missing('recharge_plans', 'is_featured',
  'is_featured TINYINT DEFAULT 0');

UPDATE recharge_plans SET sort_order = 1 WHERE name = 'Basic' AND sort_order = 0;
UPDATE recharge_plans SET sort_order = 2, is_featured = 1 WHERE name = 'Pro' AND sort_order = 0;
UPDATE recharge_plans SET sort_order = 3 WHERE name = 'Elite' AND sort_order = 0;
UPDATE recharge_plans SET sort_order = 4 WHERE name = 'Enterprise' AND sort_order = 0;

-- ─────────────────────────────────────────────
-- 6. SETTINGS — admin-tunable credit grants
-- ─────────────────────────────────────────────
INSERT INTO app_settings (setting_key, setting_value) VALUES
  ('signup_free_credits', '0'),
  ('lea_approval_free_credits', '20'),
  ('payments_provider', 'manual')
ON DUPLICATE KEY UPDATE setting_key = setting_key;

DROP PROCEDURE IF EXISTS add_col_if_missing;
DROP PROCEDURE IF EXISTS add_idx_if_missing;
DROP PROCEDURE IF EXISTS drop_idx_if_present;

SELECT 'migration_selfserve_auth.sql applied' AS status;
