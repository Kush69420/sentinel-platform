-- SENTINEL migration for Admin Customization / Security / API Management
-- Safe to run multiple times.
-- Run: mysql -u sentinel_user1 -p sentinel_db < migration_admin_customization.sql

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
    PREPARE stmt FROM @s;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
  END IF;
END $$
DELIMITER ;

CALL add_col_if_missing('admin_users','failed_login_count','failed_login_count INT DEFAULT 0');
CALL add_col_if_missing('admin_users','locked_until','locked_until TIMESTAMP NULL');
CALL add_col_if_missing('admin_users','last_login_at','last_login_at TIMESTAMP NULL');
CALL add_col_if_missing('admin_users','twofa_enabled','twofa_enabled TINYINT DEFAULT 0');
CALL add_col_if_missing('admin_users','twofa_secret','twofa_secret TEXT');
CALL add_col_if_missing('admin_users','recovery_codes_hash','recovery_codes_hash TEXT');

CALL add_col_if_missing('bot_users','official_email','official_email VARCHAR(120)');
CALL add_col_if_missing('bot_users','password_hash','password_hash VARCHAR(255)');
CALL add_col_if_missing('bot_users','failed_login_count','failed_login_count INT DEFAULT 0');
CALL add_col_if_missing('bot_users','locked_until','locked_until TIMESTAMP NULL');
CALL add_col_if_missing('bot_users','last_login_at','last_login_at TIMESTAMP NULL');
CALL add_col_if_missing('bot_users','twofa_enabled','twofa_enabled TINYINT DEFAULT 0');
CALL add_col_if_missing('bot_users','twofa_secret','twofa_secret TEXT');
CALL add_col_if_missing('bot_users','recovery_codes_hash','recovery_codes_hash TEXT');

CALL add_col_if_missing('integrations','usage_limit_daily','usage_limit_daily INT DEFAULT 0');
CALL add_col_if_missing('integrations','credits_per_call','credits_per_call INT DEFAULT 0');

DROP PROCEDURE IF EXISTS add_col_if_missing;

CREATE TABLE IF NOT EXISTS cases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_reference VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(180) NOT NULL,
    status ENUM('open','pending','closed','archived') DEFAULT 'open',
    priority ENUM('low','medium','high','critical') DEFAULT 'medium',
    created_by_user_id INT,
    assigned_to VARCHAR(100),
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_user_id) REFERENCES bot_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS case_notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    note TEXT NOT NULL,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS case_activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    action VARCHAR(80),
    description TEXT,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS integration_usage_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    integration_id INT NOT NULL,
    user_id INT,
    endpoint VARCHAR(180),
    credits_charged INT DEFAULT 0,
    status ENUM('success','failed') DEFAULT 'success',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES bot_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS ai_providers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    provider_name VARCHAR(80) NOT NULL,
    model_name VARCHAR(120) NOT NULL,
    base_url VARCHAR(255),
    api_key TEXT,
    is_enabled TINYINT DEFAULT 0,
    is_default TINYINT DEFAULT 0,
    config_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT INTO app_settings (setting_key, setting_value) VALUES
('app_name','SENTINEL'),
('support_whatsapp','+91 98000 00000'),
('session_timeout_min','60'),
('inactivity_timeout_min','15'),
('failed_login_limit','3'),
('lockout_hours','2'),
('login_title','SENTINEL ADMIN'),
('login_notice','Restricted admin access only.'),
('allowed_email_domains','gov.in,police.gov.in,nic.in')
ON DUPLICATE KEY UPDATE setting_key=setting_key;

-- Unlock default admin after migration. Password is NOT changed here.
UPDATE admin_users SET failed_login_count=0, locked_until=NULL WHERE username='admin';

-- Generic admin-uploaded master data: tower/BTS/address/subscriber/custom records
CREATE TABLE IF NOT EXISTS master_data_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_type VARCHAR(80) NOT NULL,
    record_key VARCHAR(180),
    data_json JSON,
    uploaded_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source_type (source_type),
    INDEX idx_record_key (record_key)
);

-- Seed Gemini provider row if missing. Add API key from Admin → AI Integration.
INSERT INTO ai_providers (provider_name, model_name, base_url, is_enabled, is_default)
SELECT 'Google Gemini', 'gemini-1.5-flash', 'https://generativelanguage.googleapis.com/v1beta', 0, 0
WHERE NOT EXISTS (SELECT 1 FROM ai_providers WHERE provider_name='Google Gemini' AND model_name='gemini-1.5-flash');

-- Enterprise status/sync/audit columns
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

CALL add_col_if_missing('integrations','last_status','last_status ENUM(''unknown'',''working'',''failed'') DEFAULT ''unknown''');
CALL add_col_if_missing('integrations','last_error','last_error TEXT');
CALL add_col_if_missing('integrations','last_test_at','last_test_at TIMESTAMP NULL');
CALL add_col_if_missing('integrations','last_sync_at','last_sync_at TIMESTAMP NULL');

CALL add_col_if_missing('services','maintenance_mode','maintenance_mode TINYINT DEFAULT 0');

CALL add_col_if_missing('activity_log','old_value','old_value TEXT');
CALL add_col_if_missing('activity_log','new_value','new_value TEXT');
CALL add_col_if_missing('activity_log','ip_address','ip_address VARCHAR(80)');
CALL add_col_if_missing('activity_log','actor_type','actor_type VARCHAR(40) DEFAULT ''admin''');
CALL add_col_if_missing('activity_log','actor_id','actor_id INT NULL');

CREATE TABLE IF NOT EXISTS import_batches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_type VARCHAR(80) NOT NULL,
    original_filename VARCHAR(255),
    total_rows INT DEFAULT 0,
    imported_by VARCHAR(100),
    status ENUM('previewed','imported','rolled_back','failed') DEFAULT 'imported',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rolled_back_at TIMESTAMP NULL
);

CALL add_col_if_missing('master_data_records','import_batch_id','import_batch_id INT NULL');

INSERT INTO integrations (name, category, description, base_url, is_enabled, show_on_dashboard)
SELECT 'Google Gemini', 'gemini', 'Google Gemini AI API', 'https://generativelanguage.googleapis.com/v1beta', 0, 0
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name='Google Gemini');
INSERT INTO integrations (name, category, description, base_url, is_enabled, show_on_dashboard)
SELECT 'OpenAI API', 'openai', 'OpenAI API', 'https://api.openai.com/v1', 0, 0
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name='OpenAI API');
INSERT INTO integrations (name, category, description, base_url, is_enabled, show_on_dashboard)
SELECT 'VirusTotal', 'virustotal', 'VirusTotal threat intelligence', 'https://www.virustotal.com/api/v3', 0, 1
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name='VirusTotal');
INSERT INTO integrations (name, category, description, base_url, is_enabled, show_on_dashboard)
SELECT 'AbuseIPDB', 'abuseipdb', 'AbuseIPDB IP reputation', 'https://api.abuseipdb.com/api/v2', 0, 1
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name='AbuseIPDB');
INSERT INTO integrations (name, category, description, base_url, is_enabled, show_on_dashboard)
SELECT 'Twilio API', 'twilio', 'Twilio SMS/WhatsApp API', 'https://api.twilio.com/2010-04-01', 0, 0
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name='Twilio API');

INSERT INTO app_settings (setting_key, setting_value) VALUES
('twofa_grace_days','7'),
('twofa_enforcement_enabled','0')
ON DUPLICATE KEY UPDATE setting_key=setting_key;

DROP PROCEDURE IF EXISTS add_col_if_missing;
INSERT INTO integrations (name, category, description, base_url, is_enabled, show_on_dashboard)
SELECT 'SMTP API', 'smtp', 'SMTP email delivery configuration status', '', 0, 0
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name='SMTP API');

-- Sentinel Database Import & Correlation Engine normalized tables
CREATE TABLE IF NOT EXISTS subscriber_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mobile_number VARCHAR(20) NOT NULL UNIQUE,
    subscriber_name VARCHAR(150),
    father_name VARCHAR(150),
    address TEXT,
    district VARCHAR(100),
    state VARCHAR(100),
    operator VARCHAR(80),
    sim_type VARCHAR(40),
    activation_date DATE NULL,
    status VARCHAR(50),
    alternate_number VARCHAR(20),
    email VARCHAR(150),
    id_type VARCHAR(50),
    id_number VARCHAR(100),
    import_batch_id INT NULL,
    raw_json JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_mobile (mobile_number),
    INDEX idx_name (subscriber_name)
);

CREATE TABLE IF NOT EXISTS vehicle_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    registration_number VARCHAR(30) NOT NULL UNIQUE,
    owner_name VARCHAR(150),
    father_name VARCHAR(150),
    address TEXT,
    vehicle_class VARCHAR(80),
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    engine_number VARCHAR(120),
    chassis_number VARCHAR(120),
    fuel_type VARCHAR(50),
    registration_date DATE NULL,
    fitness_validity DATE NULL,
    insurance_validity DATE NULL,
    district VARCHAR(100),
    import_batch_id INT NULL,
    raw_json JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_reg (registration_number),
    INDEX idx_owner (owner_name)
);

CREATE TABLE IF NOT EXISTS bts_tower_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    lac VARCHAR(40) NOT NULL,
    cell_id VARCHAR(40) NOT NULL,
    operator VARCHAR(80),
    tower_id VARCHAR(100),
    tower_name VARCHAR(150),
    latitude DECIMAL(10,7) NULL,
    longitude DECIMAL(10,7) NULL,
    full_address TEXT,
    district VARCHAR(100),
    state VARCHAR(100),
    technology VARCHAR(50),
    azimuth DECIMAL(8,2) NULL,
    import_batch_id INT NULL,
    raw_json JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_lac_cell (lac, cell_id),
    INDEX idx_tower (tower_id),
    INDEX idx_operator (operator)
);

CREATE TABLE IF NOT EXISTS cdr_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_reference VARCHAR(100),
    calling_number VARCHAR(20),
    called_number VARCHAR(20),
    start_time DATETIME NULL,
    end_time DATETIME NULL,
    duration INT DEFAULT 0,
    imei VARCHAR(40),
    imsi VARCHAR(40),
    lac VARCHAR(40),
    cell_id VARCHAR(40),
    tower_address TEXT,
    tower_latitude DECIMAL(10,7) NULL,
    tower_longitude DECIMAL(10,7) NULL,
    tower_district VARCHAR(100),
    import_batch_id INT NULL,
    raw_json JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_case (case_reference),
    INDEX idx_calling (calling_number),
    INDEX idx_called (called_number),
    INDEX idx_time (start_time),
    INDEX idx_lac_cell (lac, cell_id)
);

CREATE TABLE IF NOT EXISTS ipdr_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_reference VARCHAR(100),
    subscriber_number VARCHAR(20),
    source_ip VARCHAR(80),
    destination_ip VARCHAR(80),
    timestamp DATETIME NULL,
    session_duration INT DEFAULT 0,
    lac VARCHAR(40),
    cell_id VARCHAR(40),
    tower_address TEXT,
    tower_coordinates VARCHAR(80),
    import_batch_id INT NULL,
    raw_json JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_case (case_reference),
    INDEX idx_subscriber (subscriber_number),
    INDEX idx_source_ip (source_ip),
    INDEX idx_dest_ip (destination_ip),
    INDEX idx_time (timestamp),
    INDEX idx_lac_cell (lac, cell_id)
);

CREATE TABLE IF NOT EXISTS custom_schemas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(120) NOT NULL UNIQUE,
    description TEXT,
    lookup_enabled TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS custom_schema_fields (
    id INT AUTO_INCREMENT PRIMARY KEY,
    schema_id INT NOT NULL,
    column_name VARCHAR(120) NOT NULL,
    data_type ENUM('text','number','date','datetime','email','mobile','json') DEFAULT 'text',
    searchable TINYINT DEFAULT 0,
    mandatory TINYINT DEFAULT 0,
    sort_order INT DEFAULT 0,
    FOREIGN KEY (schema_id) REFERENCES custom_schemas(id) ON DELETE CASCADE,
    UNIQUE KEY unique_schema_col (schema_id, column_name)
);

CREATE TABLE IF NOT EXISTS custom_records_v2 (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    schema_id INT NULL,
    record_key VARCHAR(180),
    data_json JSON,
    import_batch_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (schema_id) REFERENCES custom_schemas(id) ON DELETE SET NULL,
    INDEX idx_record_key (record_key)
);

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

CREATE TABLE IF NOT EXISTS correlation_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_reference VARCHAR(100),
    batch_id INT,
    module VARCHAR(40),
    report_json JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_case (case_reference),
    INDEX idx_batch (batch_id)
);

-- Tool Management System columns
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

CALL add_col_if_missing('services','tool_category','tool_category ENUM(''OSINT'',''Analyzer'') DEFAULT ''OSINT''');
CALL add_col_if_missing('services','tool_type','tool_type ENUM(''API Based'',''Database Lookup'',''Internal Engine'',''External Tool'') DEFAULT ''API Based''');
CALL add_col_if_missing('services','api_dependency','api_dependency VARCHAR(120)');
CALL add_col_if_missing('services','search_limit','search_limit INT DEFAULT 0');
CALL add_col_if_missing('services','status','status ENUM(''enabled'',''disabled'',''upcoming'') DEFAULT ''enabled''');
CALL add_col_if_missing('services','visible_to_users','visible_to_users TINYINT DEFAULT 1');

UPDATE services SET tool_category='Analyzer' WHERE category IN ('telecom','financial','digital_forensics','mapping','graph','timeline','fraud','analyzer');
UPDATE services SET tool_category='OSINT' WHERE category IN ('osint','identity','domain','network','email','phone','registry','social');
UPDATE services SET status='disabled' WHERE is_enabled=0;
UPDATE services SET status='enabled' WHERE is_enabled=1 AND (status IS NULL OR status='disabled');

DROP PROCEDURE IF EXISTS add_col_if_missing;

-- Data retention / privacy-first deletion engine
CREATE TABLE IF NOT EXISTS deletion_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    batch_id INT,
    file_type VARCHAR(40),
    upload_date TIMESTAMP NULL,
    deletion_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deletion_method ENUM('automatic','manual','admin_force') DEFAULT 'manual',
    metadata_json JSON,
    INDEX idx_user (user_id),
    INDEX idx_batch (batch_id),
    INDEX idx_deletion_date (deletion_date)
);

INSERT INTO app_settings (setting_key, setting_value) VALUES
('auto_deletion_enabled','1'),
('cdr_ipdr_retention_days','7'),
('privacy_first_mode','0'),
('notify_before_deletion_hours','24')
ON DUPLICATE KEY UPDATE setting_key=setting_key;

-- Tool CLI worker columns + jobs
DELIMITER $$
DROP PROCEDURE IF EXISTS add_col_if_missing $$
CREATE PROCEDURE add_col_if_missing(IN tbl VARCHAR(64), IN col VARCHAR(64), IN ddl TEXT)
BEGIN
  IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=tbl AND COLUMN_NAME=col) THEN
    SET @s = CONCAT('ALTER TABLE `', tbl, '` ADD COLUMN ', ddl);
    PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
  END IF;
END $$
DELIMITER ;
CALL add_col_if_missing('services','external_command','external_command TEXT');
CALL add_col_if_missing('services','timeout_seconds','timeout_seconds INT DEFAULT 60');
CALL add_col_if_missing('services','allow_cli_execution','allow_cli_execution TINYINT DEFAULT 0');
DROP PROCEDURE IF EXISTS add_col_if_missing;

CREATE TABLE IF NOT EXISTS external_tool_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_id INT,
    user_id INT,
    command TEXT,
    status ENUM('queued','running','success','failed','timeout') DEFAULT 'queued',
    exit_code INT NULL,
    stdout MEDIUMTEXT,
    stderr MEDIUMTEXT,
    runtime_ms INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP NULL,
    finished_at TIMESTAMP NULL,
    INDEX idx_service (service_id),
    INDEX idx_user (user_id),
    INDEX idx_status (status)
);
