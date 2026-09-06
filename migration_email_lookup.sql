-- SENTINEL migration — email_lookup module
-- Safe to run multiple times.
-- Run AFTER db_setup.sql, migration_admin_customization.sql, migration_fix_import_errors.sql,
-- migration_selfserve_auth.sql, migration_activity_log_actor.sql, migration_remove_default_admin.sql,
-- migration_google_admin_oauth.sql.
-- Run: mysql -u sentinel_user1 -p sentinel_db < migration_email_lookup.sql
--
-- This file will grow as the rest of the email_lookup module (Step B, PDF
-- report, catalog wiring) lands — add new tables/columns below with their
-- own comment rather than starting a new migration file, per repo convention
-- (see migration_admin_customization.sql).
--
-- ── Step A: email -> GAIA id resolution cache ──
--   sentinel_modules/gaia_resolver.py resolves a Gmail address to a Google
--   GAIA id via a pre-obtained Android master token (stored encrypted in
--   `integrations`, name='google_master_token' — see
--   tools/set_integration_credential.py). That credential is fragile (can
--   die from a password change, security flag, or ToS action on the source
--   account), so every resolution is cached here permanently: a dead
--   credential then only blocks *new* addresses, and every
--   previously-resolved email — and any report already generated from it —
--   keeps working.
CREATE TABLE IF NOT EXISTS email_gaia_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    gaia_id VARCHAR(64) NOT NULL,
    resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email)
);

-- ── Step B fallback: SerpApi monthly usage quota ──
--   sentinel_modules/serpapi_fallback.py is the paid fallback for Step B
--   (GAIA id -> profile + reviews), used only when google_osint.py's
--   unauthenticated direct-scrape path raises GoogleOsintError. It is
--   hard-capped at 250 calls/month (MONTHLY_QUOTA_LIMIT in that module) so a
--   Google-outage-triggered fallback storm can't turn into a surprise bill.
--   One row per calendar month (year_month, e.g. '2026-09'); request_count is
--   incremented atomically with an UPDATE ... WHERE request_count < <limit>
--   guard (see _reserve_quota_slot() in that module) BEFORE each SerpApi
--   call is made, the same optimistic-concurrency idiom app.py's
--   charge_for_lookup() uses for bot_users.credits.
-- `year_month` is quoted throughout: YEAR_MONTH is a reserved MySQL keyword
-- (the INTERVAL unit in expressions like INTERVAL '1-2' YEAR_MONTH), so the
-- bare identifier is a syntax error on a real server — this only ever ran
-- against mocked cursors in tests, never actual MySQL, until this fix.
CREATE TABLE IF NOT EXISTS serpapi_usage_quota (
    id INT AUTO_INCREMENT PRIMARY KEY,
    `year_month` VARCHAR(7) NOT NULL UNIQUE, -- e.g. '2026-09'
    request_count INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_year_month (`year_month`)
);

-- ── Catalog flip: bring email_lookup out of "Coming Soon" ──
-- Mirrors migration_coming_soon.sql's own convention for bringing a
-- module live (see that file's header comment).
-- Idempotent — safe to run against a database where this has already
-- been applied.
UPDATE services SET status='enabled', is_enabled=1 WHERE code='email_lookup';

SELECT 'migration_email_lookup.sql applied' AS status;
