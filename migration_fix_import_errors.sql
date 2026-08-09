-- Fix for MySQL/MariaDB error near row_number in import_errors table
-- Run this only if migration_admin_customization.sql failed at import_errors.

USE sentinel_db;

CREATE TABLE IF NOT EXISTS import_errors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id INT,
    row_no INT,
    row_data JSON,
    error_type VARCHAR(80),
    message TEXT,
    severity ENUM('warning','error') DEFAULT 'error',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_batch (batch_id)
);
