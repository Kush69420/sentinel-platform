-- ════════════════════════════════════════════════
-- SENTINEL PLATFORM — DATABASE SCHEMA
-- Run:
--   mysql -u root -p < db_setup.sql
-- ════════════════════════════════════════════════
CREATE DATABASE IF NOT EXISTS sentinel_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sentinel_db;

-- ── ADMIN USERS ──
CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin','manager','support') DEFAULT 'support',
    is_active TINYINT DEFAULT 1,
    failed_login_count INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    last_login_at TIMESTAMP NULL,
    twofa_enabled TINYINT DEFAULT 0,
    twofa_secret TEXT,
    recovery_codes_hash TEXT,
    -- Verified Google account authorized to sign in as this admin (allow-list,
    -- not registration — see migration_google_admin_oauth.sql). NULL means this
    -- admin can only use password login. UNIQUE tolerates many NULLs.
    google_email VARCHAR(255) NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- No default admin is seeded here on purpose. A checked-into-git credential
-- (this file used to insert username=admin / password=admin123 with a static
-- salt) means everyone who ever cloned the repo can log in as super_admin on
-- any deployment that forgot to change it — and nothing enforced that change.
-- Create the first admin explicitly instead, after this file has run:
--   python -m tools.bootstrap_admin --username admin --name "Ops Admin"
-- (omit --password to have it generate one and print it once). See that
-- script's docstring, and CLAUDE.md's deploy checklist, for details.
--
-- Upgrading a database that was already initialised by the OLD version of
-- this file: removing the INSERT here does nothing for you, since
-- CREATE TABLE IF NOT EXISTS above is a no-op on an existing table and the
-- old INSERT simply never runs again. Run migration_remove_default_admin.sql
-- — it neutralizes that already-seeded row explicitly.

-- ── LEA APPLICATIONS ──
CREATE TABLE IF NOT EXISTS lea_applications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    official_email VARCHAR(100),
    department VARCHAR(100) NOT NULL,
    designation VARCHAR(100) NOT NULL,
    service_id VARCHAR(50) NOT NULL,
    unit VARCHAR(150) NOT NULL,
    jurisdiction VARCHAR(100) NOT NULL,
    notes TEXT,
    id_proof_path VARCHAR(255) NOT NULL,
    dept_id_path VARCHAR(255) NOT NULL,
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP NULL,
    rejection_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_phone (phone)
);

-- ── RECHARGE PLANS ──
CREATE TABLE IF NOT EXISTS recharge_plans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE,
    credits INT NOT NULL,
    price_inr INT NOT NULL,
    is_active TINYINT DEFAULT 1
);

INSERT INTO recharge_plans (name, credits, price_inr) VALUES
('Basic', 50, 49),
('Pro', 150, 99),
('Elite', 500, 249),
('Enterprise', 2000, 799)
ON DUPLICATE KEY UPDATE credits=VALUES(credits), price_inr=VALUES(price_inr);

-- ── BOT USERS / APPROVED LEA PERSONNEL ──
CREATE TABLE IF NOT EXISTS bot_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    phone VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(100),
    department VARCHAR(100),
    official_email VARCHAR(120),
    password_hash VARCHAR(255),
    credits INT DEFAULT 0,
    plan_id INT DEFAULT NULL,
    status ENUM('pending','approved','rejected','blocked','inactive') DEFAULT 'pending',
    block_reason TEXT,
    lea_application_id INT,
    failed_login_count INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    last_login_at TIMESTAMP NULL,
    twofa_enabled TINYINT DEFAULT 0,
    twofa_secret TEXT,
    recovery_codes_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lea_application_id) REFERENCES lea_applications(id) ON DELETE SET NULL,
    FOREIGN KEY (plan_id) REFERENCES recharge_plans(id) ON DELETE SET NULL,
    INDEX idx_status (status),
    INDEX idx_email (official_email)
);

-- ── CREDIT TRANSACTIONS ──
CREATE TABLE IF NOT EXISTS credit_transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    phone VARCHAR(20) NOT NULL,
    type ENUM('debit','credit') NOT NULL,
    amount INT NOT NULL,
    reason VARCHAR(150),
    razorpay_order_id VARCHAR(100),
    status ENUM('success','pending','failed') DEFAULT 'success',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_phone (phone)
);

-- ── SEARCH LOGS ──
CREATE TABLE IF NOT EXISTS search_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    phone VARCHAR(20) NOT NULL,
    search_type VARCHAR(30),
    query_value VARCHAR(255),
    case_reference VARCHAR(100),
    credits_used INT DEFAULT 2,
    sources_queried TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES bot_users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_created (created_at)
);

-- ── CASE MANAGEMENT ──
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

CREATE TABLE IF NOT EXISTS evidence_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT,
    original_name VARCHAR(255),
    encrypted_path VARCHAR(255),
    sha256_hash VARCHAR(128),
    uploaded_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
);

-- ── SUPPORT TICKETS ──
CREATE TABLE IF NOT EXISTS support_tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    phone VARCHAR(20),
    subject VARCHAR(200),
    message TEXT,
    status ENUM('open','urgent','resolved','closed') DEFAULT 'open',
    admin_reply TEXT,
    replied_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL
);

-- ── ADMIN ACTIVITY LOG ──
CREATE TABLE IF NOT EXISTS activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT,
    action VARCHAR(80),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE SET NULL,
    INDEX idx_created (created_at),
    INDEX idx_action (action)
);

-- ── API / OSINT INTEGRATIONS ──
CREATE TABLE IF NOT EXISTS integrations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL,
    description VARCHAR(255),
    base_url VARCHAR(255),
    api_key TEXT,
    api_secret TEXT,
    config_json TEXT,
    usage_limit_daily INT DEFAULT 0,
    credits_per_call INT DEFAULT 0,
    is_enabled TINYINT DEFAULT 0,
    show_on_dashboard TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_enabled (is_enabled)
);

INSERT INTO integrations (name, category, description, base_url, is_enabled, show_on_dashboard) VALUES
('Google Custom Search', 'google', 'Google Dorking / indexed search results', 'https://www.googleapis.com/customsearch/v1', 0, 1),
('Hunter.io', 'email', 'Email verification and discovery', 'https://api.hunter.io/v2', 0, 1),
('HaveIBeenPwned', 'breach', 'Breach and exposure lookup', 'https://haveibeenpwned.com/api/v3', 0, 1),
('Shodan', 'domain', 'IP / infrastructure intelligence', 'https://api.shodan.io', 0, 1),
('WhoisJSON', 'domain', 'WHOIS and domain lookup', 'https://www.whoisjsonapi.com/v1', 0, 1),
('Google Maps Geocoding', 'maps', 'Address geocoding and map pins', 'https://maps.googleapis.com/maps/api', 0, 1),
('IP-API', 'network', 'IP geolocation lookup', 'http://ip-api.com/json', 0, 1),
('Vehicle/RC Lookup', 'registry', 'Vehicle registration lookup', '', 0, 1)
ON DUPLICATE KEY UPDATE name=name;

CREATE TABLE IF NOT EXISTS integration_usage_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    integration_id INT NOT NULL,
    user_id INT,
    endpoint VARCHAR(180),
    credits_charged INT DEFAULT 0,
    status ENUM('success','failed') DEFAULT 'success',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES bot_users(id) ON DELETE SET NULL,
    INDEX idx_integration_created (integration_id, created_at)
);

-- ── AI PROVIDERS ──
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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_enabled_default (is_enabled, is_default),
    UNIQUE KEY unique_provider_model (provider_name, model_name)
);

INSERT INTO ai_providers (provider_name, model_name, base_url, is_enabled, is_default) VALUES
('OpenAI', 'gpt-4.1-mini', 'https://api.openai.com/v1', 0, 1),
('Anthropic', 'claude-3-5-sonnet-latest', 'https://api.anthropic.com/v1', 0, 0),
('In-House Model', 'sentinel-local', 'http://localhost:8000/v1', 0, 0)
ON DUPLICATE KEY UPDATE provider_name=provider_name;

-- ── SERVICES CATALOG ──
CREATE TABLE IF NOT EXISTS services (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL,
    description VARCHAR(255),
    icon VARCHAR(10) DEFAULT '🔧',
    credits_per_use INT DEFAULT 5,
    is_free TINYINT DEFAULT 0,
    is_enabled TINYINT DEFAULT 1,
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_category (category)
);

INSERT INTO services (code, name, category, description, icon, credits_per_use, sort_order) VALUES
('mobile_lookup','Mobile Lookup','osint','Lookup mobile number intelligence','📱',2,1),
('email_lookup','Email Lookup','osint','Email intelligence workflow','✉️',2,2),
('username_lookup','Username Lookup','osint','Public username footprint','👤',2,3),
('vehicle_lookup','Vehicle Lookup','osint','Vehicle registration intelligence','🚗',3,4),
('ip_lookup','IP Lookup','osint','IP reputation and geo intelligence','🌐',2,5),
('domain_lookup','Domain Lookup','osint','WHOIS, DNS and infrastructure','◎',2,6),
('social_media_lookup','Social Media Lookup','osint','Public social profile intelligence','🔗',4,7),
('breach_search','Data Breach Search','osint','Breach exposure indicators','⚠️',4,8),
('reverse_image','Reverse Image Search','osint','Image intelligence workflow','🖼️',3,9),
('address_osint','Address OSINT','osint','Address and map intelligence','📍',2,10),
('aadhaar_validator','Aadhaar Validator','identity','Checksum/format validation only','🪪',1,11),
('cdr_processor','CDR Analysis','telecom','Call Detail Record CSV analysis','📞',10,12),
('ipdr_analysis','IPDR Analysis','telecom','Internet Protocol Detail Record CSV analysis','📶',10,13),
('bank_statement','Bank Statement Analysis','financial','Bank statement analytics','🏦',15,14),
('call_pattern','Call Pattern Analysis','telecom','Detect calling anomalies','📈',8,15),
('tower_dump','Tower Dump Analysis','telecom','Tower dump correlation','📡',15,16),
('contact_correlation','Contact Correlation','graph','Find common contacts','🕸️',8,17),
('communication_analysis','Communication Analysis','telecom','Communication graph and stats','💬',8,18),
('timeline_analysis','Timeline Analysis','timeline','Build investigation chronology','🕒',5,19),
('geo_analysis','Geo Analysis','mapping','Movement and location insights','🗺️',8,20)
ON DUPLICATE KEY UPDATE code=code;

CREATE TABLE IF NOT EXISTS plan_services (
    id INT AUTO_INCREMENT PRIMARY KEY,
    plan_id INT NOT NULL,
    service_id INT NOT NULL,
    included_free TINYINT DEFAULT 1,
    monthly_quota INT DEFAULT NULL,
    FOREIGN KEY (plan_id) REFERENCES recharge_plans(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    UNIQUE KEY unique_plan_service (plan_id, service_id)
);

CREATE TABLE IF NOT EXISTS user_service_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    service_id INT NOT NULL,
    access_type ENUM('granted','revoked') DEFAULT 'granted',
    granted_by VARCHAR(100),
    notes VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES bot_users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_service (user_id, service_id)
);

CREATE TABLE IF NOT EXISTS service_usage_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    service_id INT NOT NULL,
    case_reference VARCHAR(100),
    input_summary VARCHAR(255),
    credits_charged INT DEFAULT 0,
    output_file_path VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES bot_users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_service (service_id)
);

-- ── SETTINGS: SMTP, security, frontend content, etc. ──
CREATE TABLE IF NOT EXISTS app_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT INTO app_settings (setting_key, setting_value) VALUES
('credits_per_search', '2'),
('new_user_free_credits', '20'),
('low_credit_threshold', '4'),
('maintenance_mode', '0'),
('max_searches_per_hour', '10'),
('max_searches_per_day', '50'),
('session_timeout_min', '60'),
('inactivity_timeout_min', '15'),
('failed_login_limit', '3'),
('lockout_hours', '2'),
('smtp_host', ''),
('smtp_port', '587'),
('smtp_username', ''),
('smtp_password', ''),
('smtp_security', 'tls'),
('allowed_email_domains', 'gov.in,police.gov.in,nic.in')
ON DUPLICATE KEY UPDATE setting_key=setting_key;
