-- ============================================================
-- Monitor Suite Database Schema
-- ============================================================
-- This schema works on BOTH SQLite (desktop) and PostgreSQL (cloud)
-- with only minor dialect differences handled in the wrapper code.
--
-- Design principles:
--   1. Every user-owned row has a `user_id` — enforces isolation
--      when we go multi-tenant in the cloud (Phase 3).
--   2. Timestamps are stored as ISO-8601 TEXT — human-readable
--      in DB browsers, easy to compare, timezone-safe.
--   3. Foreign keys use ON DELETE CASCADE — delete a user, all
--      their data goes with them (right thing for our use case).
--   4. Every table has created_at — audit trail comes free.
--   5. History tables are append-only — never UPDATE or DELETE
--      individual check results, only INSERT and bulk-purge.
-- ============================================================


-- ---------- USERS ----------
-- Replaces users.json entirely.
-- One row per registered account.
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE,   -- login identifier, lowercased
    username        TEXT    NOT NULL,          -- display name (not unique)
    password_hash   TEXT    NOT NULL,          -- Werkzeug scrypt hash — never plaintext
    is_guest        INTEGER NOT NULL DEFAULT 0,-- 1 for auto-created guest accounts
    created_at      TEXT    NOT NULL,
    last_login_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);


-- ---------- SETTINGS ----------
-- Per-user preferences — scan intervals, theme, cloud sync API key, etc.
-- One row per user. Uses JSON blob so we can add settings without
-- schema migrations.
CREATE TABLE IF NOT EXISTS settings (
    user_id         INTEGER PRIMARY KEY,
    data_json       TEXT    NOT NULL DEFAULT '{}',
    updated_at      TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


-- ---------- API KEYS ----------
-- Used in Phase 5 when the desktop agent pushes to cloud.
-- Each user can have multiple keys (one per PC they run the agent on).
CREATE TABLE IF NOT EXISTS api_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    key_hash        TEXT    NOT NULL UNIQUE,   -- we store hash, not the key itself
    label           TEXT,                       -- "Home laptop", "Office desktop"
    created_at      TEXT    NOT NULL,
    last_used_at    TEXT,
    revoked_at      TEXT,                       -- NULL = active
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);


-- ============================================================
-- SERVER MONITOR TABLES
-- Replaces the in-memory _servers dict in registry.py.
-- Kills bug D1/C1 — servers now survive restarts.
-- ============================================================


-- ---------- SERVERS ----------
-- One row per server the user has added to monitor.
-- Maps 1:1 to the Server dataclass in registry.py.
CREATE TABLE IF NOT EXISTS servers (
    id              TEXT    PRIMARY KEY,       -- uuid4 hex[:12] — same as before
    user_id         INTEGER NOT NULL,
    name            TEXT    NOT NULL,
    ip              TEXT    NOT NULL,
    ip_version      INTEGER NOT NULL,          -- 4 or 6
    created_at      TEXT    NOT NULL,

    -- monitoring configuration
    monitoring_enabled              INTEGER NOT NULL DEFAULT 0,
    monitoring_interval_seconds     INTEGER NOT NULL DEFAULT 60,
    authorized_ports_json           TEXT    NOT NULL DEFAULT '[]',
    monitoring_started_at           TEXT,

    -- live status snapshot (last known state)
    current_status                  TEXT,        -- 'UP' | 'DOWN' | NULL
    current_latency_ms              REAL,
    last_checked_at                 TEXT,
    consecutive_failures            INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, ip)   -- can't add the same IP twice per user
);

CREATE INDEX IF NOT EXISTS idx_servers_user ON servers(user_id);


-- ---------- SERVER INTELLIGENCE ----------
-- Cached WHOIS/geo/RDNS/ports snapshot from _gather_intelligence().
-- Split out from the servers table because it can be re-fetched
-- independently and is a chunky JSON blob.
-- One row per server (1:1).
CREATE TABLE IF NOT EXISTS server_intelligence (
    server_id       TEXT    PRIMARY KEY,
    data_json       TEXT    NOT NULL,          -- the whole intelligence dict as JSON
    fetched_at      TEXT    NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);


-- ---------- SERVER HISTORY ----------
-- Append-only log of every monitoring check result.
-- This is what powers "show uptime graph for the last 24 hours".
-- Rows are never updated — only inserted, or bulk-deleted when old.
CREATE TABLE IF NOT EXISTS server_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id       TEXT    NOT NULL,
    checked_at      TEXT    NOT NULL,
    status          TEXT    NOT NULL,          -- 'UP' | 'DOWN'
    latency_ms      REAL,
    note            TEXT,                       -- error message if DOWN
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_server_history_server_time
    ON server_history(server_id, checked_at DESC);


-- ---------- SERVER DOMAINS ----------
-- Domains discovered per server (from CT logs, TLS certs, user hints).
-- One row per domain per server.
CREATE TABLE IF NOT EXISTS server_domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id       TEXT    NOT NULL,
    domain          TEXT    NOT NULL,
    status          TEXT    NOT NULL,          -- 'Candidate' | 'DNS Associated' | 'DNS Verified' | 'Verified Website'
    discovered_via  TEXT,                       -- 'ct_log' | 'tls_cert' | 'user_provided' | 'rdns'
    discovered_at   TEXT    NOT NULL,
    last_verified_at TEXT,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    UNIQUE (server_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_server_domains_server ON server_domains(server_id);


-- ============================================================
-- WEB MONITOR TABLES
-- Persists the domains/URLs your users are tracking for uptime.
-- ============================================================


-- ---------- MONITORED WEBSITES ----------
-- One row per URL the user is monitoring.
CREATE TABLE IF NOT EXISTS monitored_websites (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    url             TEXT    NOT NULL,
    label           TEXT,
    check_interval_seconds  INTEGER NOT NULL DEFAULT 300,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, url)
);

CREATE INDEX IF NOT EXISTS idx_monitored_websites_user ON monitored_websites(user_id);


-- ---------- WEBSITE CHECKS ----------
-- Append-only log of each HTTP/HTTPS check for a monitored website.
CREATE TABLE IF NOT EXISTS website_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    website_id      INTEGER NOT NULL,
    checked_at      TEXT    NOT NULL,
    status_code     INTEGER,
    response_time_ms REAL,
    ok              INTEGER NOT NULL,          -- 1 if 2xx/3xx, 0 otherwise
    error_message   TEXT,
    ssl_expires_at  TEXT,
    FOREIGN KEY (website_id) REFERENCES monitored_websites(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_website_checks_site_time
    ON website_checks(website_id, checked_at DESC);


-- ============================================================
-- SIGNAL MONITOR TABLES
-- Replaces the standalone signalwatch_history.db from your
-- signal_monitor code. Same shape, now unified with the rest.
-- ============================================================


-- ---------- SIGNAL DEVICES ----------
-- Devices seen on the user's LAN.
CREATE TABLE IF NOT EXISTS signal_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    mac             TEXT    NOT NULL,
    ip              TEXT,
    hostname        TEXT,
    vendor          TEXT,
    ssid            TEXT,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    online          INTEGER NOT NULL DEFAULT 1,
    active_seconds_today    INTEGER NOT NULL DEFAULT 0,
    active_day      TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, mac)
);

CREATE INDEX IF NOT EXISTS idx_signal_devices_user ON signal_devices(user_id);


-- ---------- SIGNAL EVENTS ----------
-- New-device / offline alerts.
CREATE TABLE IF NOT EXISTS signal_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    mac             TEXT,
    ip              TEXT,
    hostname        TEXT,
    event_type      TEXT    NOT NULL,          -- 'new_device' | 'device_offline'
    timestamp       TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_signal_events_user_time
    ON signal_events(user_id, timestamp DESC);


-- ---------- BANDWIDTH SAMPLES ----------
-- This-machine bandwidth counters (from psutil).
CREATE TABLE IF NOT EXISTS bandwidth_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    timestamp       TEXT    NOT NULL,
    bytes_sent      INTEGER NOT NULL,
    bytes_recv      INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_bandwidth_user_time
    ON bandwidth_samples(user_id, timestamp DESC);


-- ============================================================
-- SYNC QUEUE (Phase 5)
-- Buffers records the desktop agent hasn't been able to push to
-- cloud yet (offline, cloud down, etc.).
-- ============================================================
CREATE TABLE IF NOT EXISTS sync_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT    NOT NULL,          -- 'server_check' | 'signal_scan' | 'web_check'
    payload_json    TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    last_error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_sync_queue_created ON sync_queue(created_at);


-- ============================================================
-- WEB MONITOR SCAN HISTORY (Phase 1.8)
-- ============================================================
-- Two-table design:
--   website_scans          -- one row per scan run (parent)
--   website_scan_results   -- one row per target checked (child)
--
-- Design decisions:
--   - "Watched" domains still live in monitored_websites (Phase 1.2).
--     A scan can happen against a watched domain OR against a
--     one-off domain the user typed but didn't add to their
--     watchlist — hence root_domain is text, not a FK.
--   - Retention: last 100 scans per user (enforced by app code
--     after each insert, not by the schema — see registry.py
--     pattern from Phase 1.5 for how bounded history works).
--   - website_checks (Phase 1.2) is UNUSED by Phase 1.8. It was
--     designed for the future "background recurring checker"
--     feature. Left in place; do NOT drop.


-- ---------- WEBSITE SCANS ----------
-- One row per "user pressed Check Domain" event.
CREATE TABLE IF NOT EXISTS website_scans (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL,
    root_domain         TEXT    NOT NULL,
    started_at          TEXT    NOT NULL,
    completed_at        TEXT,
    total_targets       INTEGER NOT NULL DEFAULT 0,
    up_count            INTEGER NOT NULL DEFAULT 0,
    down_count          INTEGER NOT NULL DEFAULT 0,
    degraded_count      INTEGER NOT NULL DEFAULT 0,
    -- Subdomain-discovery meta: which source(s) succeeded, whether
    -- degraded, warning text. Small JSON blob.
    discovery_json      TEXT    NOT NULL DEFAULT '{}',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_website_scans_user_time
    ON website_scans(user_id, started_at DESC);


-- ---------- WEBSITE SCAN RESULTS ----------
-- One row per target (root domain or subdomain) checked in a scan.
CREATE TABLE IF NOT EXISTS website_scan_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             INTEGER NOT NULL,
    target              TEXT    NOT NULL,          -- the domain/subdomain
    ip                  TEXT,
    dns_status          TEXT,                       -- 'UP' | 'FAILED'
    server_status       TEXT,                       -- 'UP' | 'DOWN' | 'REACHABLE_VIA_HTTP' | 'UNKNOWN'
    server_port         INTEGER,
    server_response_time_ms REAL,
    website_status      TEXT,                       -- 'UP' | 'DEGRADED' | 'DOWN'
    protocol            TEXT,                       -- 'HTTPS' | 'HTTP'
    http_status         INTEGER,
    response_time_ms    REAL,
    overall_status      TEXT    NOT NULL,           -- 'UP' | 'DEGRADED' | 'WEBSITE_DOWN' | 'SERVER_DOWN' | 'DNS_FAILED'
    final_url           TEXT,
    error_message       TEXT,
    FOREIGN KEY (scan_id) REFERENCES website_scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_website_scan_results_scan
    ON website_scan_results(scan_id);

CREATE INDEX IF NOT EXISTS idx_website_scan_results_target
    ON website_scan_results(target);