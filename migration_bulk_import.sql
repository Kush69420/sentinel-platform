-- Support columns for tools/bulk_import.py (plans/DATA_POPULATION_PLAN.md, step 4:
-- "Make it resumable"). Extends import_batches so a --resume run can find where a
-- previous run of the same file left off, without a separate progress table.
--
-- Idempotent: MODIFY COLUMN is safe to re-run (same definition each time), and the
-- add_col_if_missing helper procedure (defined identically in
-- migration_admin_customization.sql) guards the new columns.
--
-- NOT yet added to the "apply in dependency order" list in CLAUDE.md — that list
-- documents a *deployed* order and no MySQL instance exists yet (see CLAUDE.md's
-- top-of-file pending-work note). Whoever runs the real apply should add this file
-- after migration_selfserve_auth.sql.

USE sentinel_db;

ALTER TABLE import_batches
    MODIFY COLUMN status ENUM('previewed','imported','rolled_back','failed','in_progress')
        DEFAULT 'imported';

DELIMITER $$
DROP PROCEDURE IF EXISTS add_col_if_missing $$
CREATE PROCEDURE add_col_if_missing(IN tbl VARCHAR(64), IN col VARCHAR(64), IN ddl TEXT)
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND COLUMN_NAME = col
  ) THEN
    SET @s = CONCAT('ALTER TABLE `', tbl, '` ADD COLUMN ', ddl);
    PREPARE stmt FROM @s;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
  END IF;
END $$
DELIMITER ;

-- rows_committed is updated in the same transaction as each executemany() chunk, so it
-- can never drift from what's actually durable — see import_file() in
-- tools/bulk_import.py.
CALL add_col_if_missing('import_batches', 'rows_committed', 'rows_committed INT DEFAULT 0');

-- source_file + file_checksum together identify "the same file as last run" for
-- --resume matching. file_checksum here is a (size, mtime) fingerprint, not a content
-- hash — see file_fingerprint() in tools/bulk_import.py for why.
CALL add_col_if_missing('import_batches', 'source_file', 'source_file VARCHAR(500) NULL');
CALL add_col_if_missing('import_batches', 'file_checksum', 'file_checksum VARCHAR(64) NULL');

CALL add_col_if_missing('import_batches', 'updated_at',
    'updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');

DELIMITER $$
DROP PROCEDURE IF EXISTS add_index_if_missing $$
CREATE PROCEDURE add_index_if_missing(IN tbl VARCHAR(64), IN idx VARCHAR(64), IN ddl TEXT)
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND INDEX_NAME = idx
  ) THEN
    SET @s = CONCAT('CREATE INDEX `', idx, '` ON `', tbl, '` (', ddl, ')');
    PREPARE stmt FROM @s;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
  END IF;
END $$
DELIMITER ;

CALL add_index_if_missing('import_batches', 'idx_import_batches_resume',
    'source_type, source_file(255), file_checksum');
