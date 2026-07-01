-- SOC Platform Database Schema

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'analyst',
    avatar_color TEXT DEFAULT '#00d4ff',
    badge TEXT DEFAULT 'Junior Analyst',
    last_login TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,  -- critical, high, medium, low, info
    status TEXT DEFAULT 'open',  -- open, in_progress, closed
    source TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    hostname TEXT,
    username TEXT,
    host_info TEXT,   -- JSON
    user_info TEXT,   -- JSON
    mitre_mapping TEXT,  -- JSON
    expected_verdict TEXT,  -- true_positive / false_positive / escalated
    points INTEGER DEFAULT 100,
    hint TEXT,
    solution_explanation TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id),
    log_type TEXT,  -- windows_event, linux_syslog, firewall, web, email, edr
    timestamp TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    username TEXT,
    event_id TEXT,
    raw_log TEXT NOT NULL,
    highlighted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id),
    ioc_type TEXT,   -- ip, domain, hash, email, url, filename
    value TEXT NOT NULL,
    description TEXT,
    malicious INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id),
    event_time TEXT,
    event_type TEXT,
    description TEXT,
    source TEXT,
    severity TEXT DEFAULT 'medium'
);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id),
    analyst_id INTEGER REFERENCES users(id),
    status TEXT DEFAULT 'in_progress',   -- in_progress, completed
    verdict TEXT,    -- true_positive, false_positive, escalated
    analyst_notes TEXT,
    ioc_confirmed TEXT,   -- JSON list
    score INTEGER DEFAULT 0,
    started_at TEXT,
    completed_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS incident_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER REFERENCES investigations(id),
    title TEXT,
    executive_summary TEXT,
    findings TEXT,
    evidence TEXT,
    recommendations TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
