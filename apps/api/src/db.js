import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export function openDatabase(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  migrate(db);
  return db;
}

export function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'owner',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      owner TEXT NOT NULL,
      status TEXT NOT NULL,
      address TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      upstream_url TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      removed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      evidence TEXT NOT NULL,
      observed_facts TEXT NOT NULL,
      estimate TEXT,
      event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
      device_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
      source TEXT NOT NULL,
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      evidence TEXT NOT NULL,
      observed_source_ip TEXT NOT NULL DEFAULT '',
      request_details TEXT NOT NULL DEFAULT '',
      process_details TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL DEFAULT 'info',
      method TEXT NOT NULL DEFAULT '',
      request_path TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      response_status INTEGER NOT NULL DEFAULT 0,
      detection_rule TEXT NOT NULL DEFAULT 'none',
      device_id TEXT,
      source_event_id TEXT,
      false_positive INTEGER NOT NULL DEFAULT 0,
      reviewed_by TEXT,
      reviewed_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS gateway_request_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
      observed_at TEXT NOT NULL,
      duration_ms REAL NOT NULL,
      upstream_error INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      detail TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS revoked_sessions (
      session_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, revoked_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS gateway_rules (
      asset_id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
      enabled INTEGER NOT NULL DEFAULT 1,
      mode TEXT NOT NULL DEFAULT 'observe',
      failure_mode TEXT NOT NULL DEFAULT 'open',
      rate_limit_count INTEGER NOT NULL DEFAULT 120,
      window_seconds INTEGER NOT NULL DEFAULT 60,
      sensitive_paths_enabled INTEGER NOT NULL DEFAULT 1,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS gateway_allowlist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      ip TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(asset_id, ip)
    );

    CREATE TABLE IF NOT EXISTS gateway_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      trusted_proxies TEXT NOT NULL DEFAULT '[]',
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS agent_credentials (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      token_hash TEXT NOT NULL,
      token_ciphertext TEXT NOT NULL,
      token_iv TEXT NOT NULL,
      token_tag TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS asset_credentials (
      asset_id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE, token_hash TEXT NOT NULL,
      token_ciphertext TEXT NOT NULL, token_iv TEXT NOT NULL, token_tag TEXT NOT NULL,
      updated_at TEXT NOT NULL, revoked_at TEXT
    );
    CREATE TABLE IF NOT EXISTS website_gateway_status (
      asset_id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
      gateway_version TEXT NOT NULL, last_heartbeat TEXT NOT NULL, health_status TEXT NOT NULL DEFAULT 'healthy'
    );

    CREATE TABLE IF NOT EXISTS device_agents (
      device_id TEXT PRIMARY KEY, name TEXT NOT NULL, hostname TEXT NOT NULL,
      os_version TEXT NOT NULL, agent_version TEXT NOT NULL, credential_hash TEXT NOT NULL,
      enrolled_at TEXT NOT NULL, last_heartbeat TEXT, health_status TEXT NOT NULL DEFAULT 'unknown',
      revoked_at TEXT, health_detail TEXT NOT NULL DEFAULT '', collection_processes INTEGER NOT NULL DEFAULT 1,
      collection_connections INTEGER NOT NULL DEFAULT 1, collection_interval_seconds INTEGER NOT NULL DEFAULT 30,
      outbound_connection_threshold INTEGER NOT NULL DEFAULT 40, retained_days INTEGER NOT NULL DEFAULT 30,
      is_demo INTEGER NOT NULL DEFAULT 0,
      backend_addresses TEXT NOT NULL DEFAULT '[]',
      config_version INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS device_snapshots (
      device_id TEXT PRIMARY KEY REFERENCES device_agents(device_id) ON DELETE CASCADE,
      captured_at TEXT NOT NULL, processes_json TEXT NOT NULL, connections_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS device_config_updates (
      id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES device_agents(device_id) ON DELETE CASCADE,
      version INTEGER NOT NULL, config_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_attempt_at TEXT, applied_at TEXT, detail TEXT NOT NULL DEFAULT '',
      UNIQUE(device_id,version)
    );
    CREATE TABLE IF NOT EXISTS firewall_rules (
      id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES device_agents(device_id),
      remote_cidr TEXT NOT NULL, protocol TEXT NOT NULL, local_port INTEGER NOT NULL,
      reason TEXT NOT NULL, evidence TEXT NOT NULL, expires_at TEXT NOT NULL,
      status TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, preview_hash TEXT NOT NULL,
      created_by TEXT NOT NULL, created_at TEXT NOT NULL, approved_by TEXT, approved_at TEXT,
      applied_at TEXT, actual_state TEXT NOT NULL DEFAULT '', failure TEXT NOT NULL DEFAULT '',
      rollback_at TEXT, updated_at TEXT NOT NULL,
      incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS firewall_settings (
      id INTEGER PRIMARY KEY CHECK(id=1), management_addresses TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS firewall_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, actor TEXT NOT NULL,
      action TEXT NOT NULL, evidence TEXT NOT NULL, exact_rule TEXT NOT NULL, result TEXT NOT NULL,
      expires_at TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incident_settings (
      id INTEGER PRIMARY KEY CHECK(id=1), correlation_threshold INTEGER NOT NULL DEFAULT 3,
      correlation_window_minutes INTEGER NOT NULL DEFAULT 10, raw_event_days INTEGER NOT NULL DEFAULT 90,
      report_days INTEGER NOT NULL DEFAULT 30, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY, correlation_key TEXT NOT NULL, asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
      device_id TEXT, observed_ip TEXT NOT NULL, detection_rule TEXT NOT NULL, severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
      event_count INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incident_events (
      incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      linked_at TEXT NOT NULL, PRIMARY KEY(incident_id,event_id)
    );
    CREATE TABLE IF NOT EXISTS incident_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      actor TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incident_reports (
      id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, actor TEXT NOT NULL,
      payload_json TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS action_settings (
      id INTEGER PRIMARY KEY CHECK(id=1), emergency_paused INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS action_policies (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
      mode TEXT NOT NULL DEFAULT 'suggestion-only', asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      detection_rule TEXT NOT NULL DEFAULT '*', minimum_severity TEXT NOT NULL DEFAULT 'high',
      minimum_event_count INTEGER NOT NULL DEFAULT 5, window_minutes INTEGER NOT NULL DEFAULT 10,
      target_type TEXT NOT NULL, target_id TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'TCP',
      local_port INTEGER NOT NULL DEFAULT 443, duration_minutes INTEGER NOT NULL DEFAULT 30,
      created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS proposed_actions (
      id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
      policy_id TEXT NOT NULL REFERENCES action_policies(id) ON DELETE CASCADE,
      incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
      target_type TEXT NOT NULL, target_id TEXT NOT NULL, target_address TEXT NOT NULL,
      target_protocol TEXT NOT NULL DEFAULT 'TCP', target_port INTEGER NOT NULL DEFAULT 443,
      expected_effect TEXT NOT NULL, evidence_json TEXT NOT NULL, expires_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'proposed', created_at TEXT NOT NULL,
      approved_by TEXT, approved_at TEXT, firewall_rule_id TEXT, failure TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS gateway_ip_blocks (
      action_id TEXT PRIMARY KEY REFERENCES proposed_actions(id) ON DELETE CASCADE,
      asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      ip TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
      UNIQUE(asset_id,ip)
    );
  `);
  addColumn(db, "assets", "address", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "assets", "description", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "assets", "upstream_url", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "gateway_rules", "failure_mode", "TEXT NOT NULL DEFAULT 'open'");
  addColumn(db, "assets", "removed_at", "TEXT");
  addColumn(db, "admins", "role", "TEXT NOT NULL DEFAULT 'owner'");
  addColumn(db, "device_agents", "config_version", "INTEGER NOT NULL DEFAULT 1");
  addColumn(db, "alerts", "event_id", "INTEGER REFERENCES events(id) ON DELETE SET NULL");
  addColumn(db, "alerts", "device_id", "TEXT");
  addColumn(db, "device_agents", "health_detail", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "device_agents", "backend_addresses", "TEXT NOT NULL DEFAULT '[]'");
  addColumn(db, "device_agents", "asset_id", "INTEGER REFERENCES assets(id) ON DELETE SET NULL");
  addColumn(db, "firewall_rules", "incident_id", "TEXT REFERENCES incidents(id) ON DELETE SET NULL");
  addColumn(db, "firewall_rules", "action_id", "TEXT REFERENCES proposed_actions(id) ON DELETE SET NULL");
  addColumn(db, "events", "observed_source_ip", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "events", "request_details", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "events", "process_details", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "events", "severity", "TEXT NOT NULL DEFAULT 'info'");
  addColumn(db, "events", "method", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "events", "request_path", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "events", "user_agent", "TEXT NOT NULL DEFAULT ''");
  addColumn(db, "events", "response_status", "INTEGER NOT NULL DEFAULT 0");
  addColumn(db, "events", "detection_rule", "TEXT NOT NULL DEFAULT 'none'");
  addColumn(db, "events", "device_id", "TEXT");
  addColumn(db, "events", "source_event_id", "TEXT");
  addColumn(db, "events", "false_positive", "INTEGER NOT NULL DEFAULT 0");
  addColumn(db, "events", "reviewed_by", "TEXT");
  addColumn(db, "events", "reviewed_at", "TEXT");
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_device_event ON events(device_id, source_event_id)
    WHERE device_id IS NOT NULL AND source_event_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_events_device_time ON events(device_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_alerts_device_time ON alerts(device_id, created_at);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
    CREATE INDEX IF NOT EXISTS idx_gateway_metrics_time ON gateway_request_metrics(observed_at);
    CREATE INDEX IF NOT EXISTS idx_gateway_metrics_asset_time ON gateway_request_metrics(asset_id,observed_at);
    CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_incident_reports_created_at ON incident_reports(created_at);`);
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_event ON events(source_event_id) WHERE source_event_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_incident_correlation ON incidents(correlation_key,last_seen,status);
    CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id);
    CREATE INDEX IF NOT EXISTS idx_incident_reports_expiry ON incident_reports(expires_at);
    CREATE INDEX IF NOT EXISTS idx_actions_status_expiry ON proposed_actions(status,expires_at);
    CREATE INDEX IF NOT EXISTS idx_gateway_blocks_asset_ip ON gateway_ip_blocks(asset_id,ip,expires_at);`);
  db.prepare("INSERT OR IGNORE INTO gateway_settings (id, trusted_proxies, updated_at) VALUES (1, '[]', ?)").run(new Date().toISOString());
  db.prepare("INSERT OR IGNORE INTO firewall_settings (id, management_addresses, updated_at) VALUES (1, '[]', ?)").run(new Date().toISOString());
  db.prepare("INSERT OR IGNORE INTO incident_settings (id,updated_at) VALUES (1,?)").run(new Date().toISOString());
  db.prepare("INSERT OR IGNORE INTO action_settings (id,updated_at) VALUES (1,?)").run(new Date().toISOString());
  db.exec(`INSERT OR IGNORE INTO gateway_rules (asset_id, updated_at)
    SELECT id, created_at FROM assets WHERE type = 'website'`);
}

function addColumn(db, table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some((entry) => entry.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

export function seedDemoData(db) {
  const existing = db.prepare("SELECT COUNT(*) AS count FROM assets").get();
  if (existing.count > 0) {
    return;
  }

  const now = Date.now();
  const iso = (minutesAgo) => new Date(now - minutesAgo * 60_000).toISOString();
  const insertAsset = db.prepare("INSERT INTO assets (name, type, owner, status, address, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
  const insertAlert = db.prepare(`INSERT INTO alerts
    (asset_id, title, severity, status, evidence, observed_facts, estimate, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  const insertEvent = db.prepare(`INSERT INTO events
    (asset_id, source, category, action, reason, evidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`);

  db.exec("BEGIN");
  try {
    const website = Number(insertAsset.run("Marketing website", "website", "Web operations", "watch", "https://example.org", "Public company website", iso(360)).lastInsertRowid);
    const app = Number(insertAsset.run("Customer portal", "application", "Application team", "healthy", "https://portal.example.org", "Customer account application", iso(340)).lastInsertRowid);
    const pc = Number(insertAsset.run("Admin workstation", "computer", "Security admin", "healthy", "SG-ADMIN-01", "Security administration device", iso(320)).lastInsertRowid);
    db.prepare("INSERT INTO gateway_rules (asset_id, updated_at) VALUES (?, ?)").run(website, iso(360));

    insertAlert.run(
      website,
      "Repeated requests to sensitive paths",
      "medium",
      "open",
      "12 requests for /wp-admin and /.env within 4 minutes from one observed network endpoint.",
      "Gateway-observed source endpoint requested sensitive paths that are not used by this asset.",
      "Likely automated scanning based on path pattern and request rate.",
      iso(42)
    );
    insertAlert.run(
      app,
      "Authentication errors above baseline",
      "low",
      "investigating",
      "7 failed sign-in events recorded in 10 minutes for distinct usernames.",
      "Application emitted failed-authentication events with no successful follow-up for those usernames.",
      "Could be user error or credential stuffing; more evidence required.",
      iso(28)
    );

    insertEvent.run(website, "gateway", "request", "monitor", "Sensitive path observed", "GET /.env returned 404 in test mode.", iso(41));
    db.prepare("UPDATE events SET observed_source_ip = ?, request_details = ?, severity = ? WHERE rowid = last_insert_rowid()")
      .run("203.0.113.42", "GET /.env HTTP/1.1", "medium");
    insertEvent.run(website, "gateway", "request", "monitor", "Rate threshold would be exceeded", "14 GET requests to /login in 60 seconds.", iso(37));
    insertEvent.run(app, "application", "authentication", "record", "Failed login", "Application reported failed login for user alias ending in 42.", iso(25));
    insertEvent.run(pc, "agent", "device-status", "record", "Agent planned", "Milestone 3 will add explicit Windows agent telemetry.", iso(12));
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}
