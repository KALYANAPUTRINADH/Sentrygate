import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import test, { afterEach, beforeEach } from "node:test";
import { createServer } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { expireGatewayActions, validateActionTarget } from "../src/actions.js";
import { correlateEvent } from "../src/incidents.js";

let db;
let server;
let baseUrl;

beforeEach(async () => {
  const config = loadConfig({ dbPath: path.join(os.tmpdir(), `sentrygate-${randomUUID()}.db`), sessionSecret: "test-secret-for-sentrygate-suite-32", port: 0, webRoot: path.resolve("apps/web") });
  db = openDatabase(config.dbPath);
  server = createServer(db, config);
  await new Promise((resolve) => server.listen(0, resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

afterEach(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
});

async function jsonFetch(pathname, options = {}) {
  const response = await fetch(`${baseUrl}${pathname}`, { headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }, ...options });
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : null, cookie: response.headers.get("set-cookie")?.split(";")[0] };
}

async function setupAdmin() {
  return jsonFetch("/api/setup", { method: "POST", body: JSON.stringify({ email: "admin@example.com", password: "correct horse battery" }) });
}

test("creates the first administrator with a salted password hash and authenticated session", async () => {
  assert.equal((await jsonFetch("/api/session")).body.setupRequired, true);
  const setup = await setupAdmin();
  assert.equal(setup.response.status, 201);
  const admin = db.prepare("SELECT password_hash, password_salt FROM admins WHERE email = ?").get("admin@example.com");
  assert.notEqual(admin.password_hash, "correct horse battery");
  assert.ok(admin.password_hash.length > 40);
  assert.ok(admin.password_salt.length > 12);
  assert.match(setup.cookie, /^sentrygate_session=/);
});

test("rejects weak setup credentials and protects API data before login", async () => {
  const weak = await jsonFetch("/api/setup", { method: "POST", body: JSON.stringify({ email: "admin@example.com", password: "short" }) });
  assert.equal(weak.response.status, 400);
  assert.equal((await jsonFetch("/api/assets")).response.status, 401);
});

test("authenticates login and records failed and successful attempts", async () => {
  await setupAdmin();
  assert.equal((await jsonFetch("/api/login", { method: "POST", body: JSON.stringify({ email: "admin@example.com", password: "wrong" }) })).response.status, 401);
  const login = await jsonFetch("/api/login", { method: "POST", body: JSON.stringify({ email: "admin@example.com", password: "correct horse battery" }) });
  assert.equal(login.response.status, 200);
  const actions = db.prepare("SELECT action FROM audit_log ORDER BY id").all().map((row) => row.action);
  assert.ok(actions.includes("admin.login_failed"));
  assert.ok(actions.includes("admin.login"));
});

test("validates, creates and audits an asset", async () => {
  const session = await setupAdmin();
  const cookie = { Cookie: session.cookie };
  const invalid = await jsonFetch("/api/assets", { method: "POST", headers: cookie, body: JSON.stringify({ name: "Bad", type: "router", address: "x", description: "" }) });
  assert.equal(invalid.response.status, 400);
  const created = await jsonFetch("/api/assets", { method: "POST", headers: cookie, body: JSON.stringify({ name: "Docs site", type: "website", address: "https://example.test", description: "Public documentation" }) });
  assert.equal(created.response.status, 201);
  const assets = await jsonFetch("/api/assets", { headers: cookie });
  assert.equal(assets.body[0].name, "Docs site");
  assert.equal(assets.body[0].address, "https://example.test");
  assert.equal(db.prepare("SELECT action FROM audit_log WHERE action = 'asset.created'").get().action, "asset.created");
});

test("filters events by asset, severity, source IP, action, and date", async () => {
  const session = await setupAdmin();
  const asset = Number(db.prepare("INSERT INTO assets (name,type,owner,status,address,description,created_at) VALUES (?,?,?,?,?,?,?)")
    .run("Portal", "application", "admin@example.com", "healthy", "portal.local", "", new Date().toISOString()).lastInsertRowid);
  const insert = db.prepare(`INSERT INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,request_details,severity,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);
  insert.run(asset, "gateway", "request", "monitor", "Sensitive path", "Observed GET /admin", "192.0.2.10", "GET /admin", "high", "2026-06-15T12:00:00.000Z");
  insert.run(asset, "gateway", "request", "allow", "Normal page", "Observed GET /", "192.0.2.11", "GET /", "info", "2026-06-16T12:00:00.000Z");
  const filtered = await jsonFetch(`/api/events?assetId=${asset}&severity=high&sourceIp=192.0.2.10&action=monitor&from=2026-06-15&to=2026-06-15`, { headers: { Cookie: session.cookie } });
  assert.equal(filtered.response.status, 200);
  assert.equal(filtered.body.length, 1);
  assert.equal(filtered.body[0].requestDetails, "GET /admin");
  assert.equal(filtered.body[0].observedSourceIp, "192.0.2.10");
});

test("alert detail endpoint returns evidence for investigation", async () => {
  const session = await setupAdmin();
  const alertId = Number(db.prepare(`INSERT INTO alerts (title,severity,status,evidence,observed_facts,created_at) VALUES (?,?,?,?,?,?)`)
    .run("Test alert", "medium", "open", "Two observed attempts", "Two requests in logs", new Date().toISOString()).lastInsertRowid);
  const alert = await jsonFetch(`/api/alerts/${alertId}`, { headers: { Cookie: session.cookie } });
  assert.equal(alert.body.evidence, "Two observed attempts");
  assert.equal(alert.body.observedFacts, "Two requests in logs");
});

test("firewall preview requires authentication, rejects protected CIDRs, and audits management-address changes", async () => {
  const session = await setupAdmin(), cookie = { Cookie: session.cookie };
  const denied = await jsonFetch("/api/firewall/rules", { method: "GET" });
  assert.equal(denied.response.status, 401);
  const saved = await jsonFetch("/api/firewall/settings", { method: "PUT", headers: cookie, body: JSON.stringify({ managementAddresses: ["192.0.2.10"] }) });
  assert.equal(saved.response.status, 200);
  const enrollment = await jsonFetch("/api/devices/enroll", { method: "POST", headers: cookie, body: JSON.stringify({ name: "Test endpoint", hostname: "SG-TEST", osVersion: "Windows Test", agentVersion: "0.4.0" }) });
  db.prepare("UPDATE device_agents SET backend_addresses=? WHERE device_id=?").run(JSON.stringify(["203.0.113.88"]), enrollment.body.deviceId);
  const common = { deviceId: enrollment.body.deviceId, protocol: "TCP", localPort: 65000, reason: "Test containment", evidence: "Observed test evidence", expiresAt: new Date(Date.now() + 600000).toISOString(), idempotencyKey: randomUUID() };
  const loopback = await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify({ ...common, remoteCidr: "127.0.0.0/8" }) });
  assert.equal(loopback.response.status, 400);
  const backend = await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify({ ...common, remoteCidr: "203.0.113.88/32", idempotencyKey: randomUUID() }) });
  assert.equal(backend.response.status, 400);
  const management = await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify({ ...common, remoteCidr: "192.0.2.0/24" }) });
  assert.equal(management.response.status, 400);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM firewall_rules").get().count, 0);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action='firewall.management_addresses_updated'").get());
});

test("firewall proposal, explicit approval, duplicate request, agent failure, expiry and rollback are idempotent", async () => {
  const session = await setupAdmin(), cookie = { Cookie: session.cookie };
  const enrolled = await jsonFetch("/api/devices/enroll", { method: "POST", headers: cookie, body: JSON.stringify({ name: "Firewall test", hostname: "FW-TEST", osVersion: "Windows Test", agentVersion: "0.4.0" }) });
  const deviceId = enrolled.body.deviceId, credential = enrolled.body.credential;
  const body = { deviceId, remoteCidr: "198.51.100.25/32", protocol: "TCP", localPort: 65000, reason: "Temporary test block", evidence: "Observed synthetic probe SG-TEST-1", expiresAt: new Date(Date.now() + 600000).toISOString(), idempotencyKey: randomUUID() };
  const preview = await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify(body) });
  assert.equal(preview.response.status, 201);
  assert.equal(preview.body.rule.status, "proposed");
  assert.equal((await jsonFetch(`/api/firewall/rules/${preview.body.rule.id}/approve`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: false, previewToken: preview.body.previewToken }) })).response.status, 400);
  const repeated = await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify(body) });
  assert.equal(repeated.body.rule.id, preview.body.rule.id);
  assert.equal(repeated.body.previewToken, preview.body.previewToken);
  const keyConflict = await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify({ ...body, localPort: 65002 }) });
  assert.equal(keyConflict.response.status, 409);
  const approved = await jsonFetch(`/api/firewall/rules/${preview.body.rule.id}/approve`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: true, previewToken: preview.body.previewToken }) });
  assert.equal(approved.body.status, "approved");
  assert.equal(approved.body.approvedBy, "admin@example.com");
  assert.equal((await jsonFetch(`/api/firewall/rules/${preview.body.rule.id}/approve`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: true, previewToken: preview.body.previewToken }) })).response.status, 200);
  const managementConflict = await jsonFetch("/api/firewall/settings", { method: "PUT", headers: cookie, body: JSON.stringify({ managementAddresses: ["198.51.100.25"] }) });
  assert.equal(managementConflict.response.status, 409);
  const config = await jsonFetch(`/api/devices/${deviceId}/config`, { headers: { Authorization: `Bearer ${credential}` } });
  assert.equal(config.body.firewallRules[0].operation, "ensure");
  const unauthorizedState = await jsonFetch(`/api/devices/${deviceId}/firewall/state`, { method: "POST", body: JSON.stringify({ results: [] }) });
  assert.equal(unauthorizedState.response.status, 401);
  const failed = await jsonFetch(`/api/devices/${deviceId}/firewall/state`, { method: "POST", headers: { Authorization: `Bearer ${credential}` }, body: JSON.stringify({ results: [{ id: preview.body.rule.id, status: "failed", detail: "Mocked NetSecurity access denied", actualState: null }] }) });
  assert.equal(failed.response.status, 200);
  assert.equal((await jsonFetch("/api/firewall/rules", { headers: cookie })).body[0].status, "failed");
  const rollback = await jsonFetch(`/api/firewall/rules/${preview.body.rule.id}/rollback`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: true }) });
  assert.equal(rollback.body.status, "removing");
  const repeatedRollback = await jsonFetch(`/api/firewall/rules/${preview.body.rule.id}/rollback`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: true }) });
  assert.equal(repeatedRollback.body.status, "removing");
  const removals = await jsonFetch(`/api/devices/${deviceId}/config`, { headers: { Authorization: `Bearer ${credential}` } });
  assert.equal(removals.body.firewallRules[0].operation, "remove");
  await jsonFetch(`/api/devices/${deviceId}/firewall/state`, { method: "POST", headers: { Authorization: `Bearer ${credential}` }, body: JSON.stringify({ results: [{ id: preview.body.rule.id, status: "removed", detail: "Mocked owned-rule removal", actualState: null }] }) });
  assert.equal((await jsonFetch("/api/firewall/rules", { headers: cookie })).body[0].status, "removed");
  assert.ok(db.prepare("SELECT COUNT(*) AS count FROM firewall_history WHERE rule_id=?").get(preview.body.rule.id).count >= 4);
});

test("firewall expiry requires a future timestamp and reports automatic expiry", async () => {
  const session = await setupAdmin(), cookie = { Cookie: session.cookie };
  const enrolled = await jsonFetch("/api/devices/enroll", { method: "POST", headers: cookie, body: JSON.stringify({ name: "Expiry endpoint", hostname: "EXP-TEST", osVersion: "Windows Test", agentVersion: "0.4.0" }) });
  const body = { deviceId: enrolled.body.deviceId, remoteCidr: "198.51.100.30", protocol: "UDP", localPort: 65001, reason: "Expiry test", evidence: "Synthetic", expiresAt: new Date(Date.now() - 1000).toISOString(), idempotencyKey: randomUUID() };
  assert.equal((await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify(body) })).response.status, 400);
  body.expiresAt = new Date(Date.now() + 300000).toISOString();
  const preview = await jsonFetch("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify(body) });
  await jsonFetch(`/api/firewall/rules/${preview.body.rule.id}/approve`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: true, previewToken: preview.body.previewToken }) });
  db.prepare("UPDATE firewall_rules SET expires_at=? WHERE id=?").run(new Date(Date.now() - 1000).toISOString(), preview.body.rule.id);
  const rules = await jsonFetch("/api/firewall/rules", { headers: cookie });
  assert.equal(rules.body[0].status, "expired");
  assert.ok(db.prepare("SELECT 1 FROM firewall_history WHERE rule_id=? AND action='expired'").get(preview.body.rule.id));
});

test("correlates unique website and application evidence while separating endpoint, IP, rule, and window false positives", async () => {
  const session = await setupAdmin(), headers = { Cookie: session.cookie };
  const site = await jsonFetch("/api/assets", { method: "POST", headers, body: JSON.stringify({ name: "Incident test site", type: "website", address: "https://incident.test", description: "Test-owned site" }) });
  const computer = await jsonFetch("/api/assets", { method: "POST", headers, body: JSON.stringify({ name: "Incident test computer", type: "computer", address: "SG-INCIDENT-01", description: "Test endpoint" }) });
  const settings = await jsonFetch("/api/incidents/settings", { method: "PUT", headers, body: JSON.stringify({ correlationThreshold: 3, correlationWindowMinutes: 10, rawEventDays: 90, reportDays: 30 }) });
  assert.equal(settings.response.status, 200);
  const tokenResult = await jsonFetch("/api/agent/credential/rotate", { method: "POST", headers });
  const ingestion = { Authorization: `Bearer ${tokenResult.body.credential}` };
  const deviceResult = await jsonFetch("/api/devices/enroll", { method: "POST", headers, body: JSON.stringify({ name: "Correlated endpoint", hostname: "SG-INCIDENT-01", osVersion: "Windows Test", agentVersion: "0.4.0", assetId: computer.body.id }) });
  const ip = "203.0.113.77", baseTime = Date.now() - 60_000;
  const gatewayEvent = (index) => ({ eventId: randomUUID(), assetId: site.body.id, timestamp: new Date(baseTime + index * 5000).toISOString(), sourceIp: ip, method: "GET", path: `/.env?probe=${index}`, userAgent: "test-agent", responseStatus: 403, detectionRule: "sensitive_path", action: "blocked", reason: "Sensitive path matched", severity: "medium" });
  const informational = await jsonFetch("/api/agent/events", { method: "POST", headers: ingestion, body: JSON.stringify({ ...gatewayEvent(0), eventId: randomUUID(), severity: "info", timestamp: new Date(baseTime - 5000).toISOString() }) });
  assert.equal(informational.response.status, 201);
  assert.equal((await jsonFetch("/api/incidents", { headers })).body.length, 0, "informational evidence must not open an incident");
  const first = gatewayEvent(0), second = gatewayEvent(1), third = gatewayEvent(2);
  for (const event of [first, second, third]) assert.equal((await jsonFetch("/api/agent/events", { method: "POST", headers: ingestion, body: JSON.stringify(event) })).response.status, 201);
  const replay = await jsonFetch("/api/agent/events", { method: "POST", headers: ingestion, body: JSON.stringify(third) });
  assert.equal(replay.body.duplicate, true);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM events WHERE asset_id=? AND source='website-gateway'").get(site.body.id).count, 4);
  const incident = (await jsonFetch("/api/incidents", { headers })).body[0];
  assert.equal(incident.eventCount, 3);
  assert.equal(incident.observedIp, ip);
  assert.equal(incident.detectionRule, "sensitive_path");
  const applicationEvent = { eventId: randomUUID(), assetId: site.body.id, timestamp: new Date(baseTime + 15000).toISOString(), sourceIp: ip, rule: "sensitive_path", severity: "high", action: "recorded", category: "application-auth", reason: "Application observed repeated credential validation failures", evidence: "Application audit reference AUTH-24", requestDetails: "POST /login" };
  const appResponse = await jsonFetch("/api/application/events", { method: "POST", headers: ingestion, body: JSON.stringify(applicationEvent) });
  assert.equal(appResponse.response.status, 201);
  const filtered = await jsonFetch(`/api/incidents?ip=${ip}&websiteId=${site.body.id}&rule=sensitive_path&severity=high&status=open&from=${new Date(baseTime).toISOString().slice(0, 10)}&to=${new Date(baseTime).toISOString().slice(0, 10)}`, { headers });
  assert.equal(filtered.body.length, 1);
  assert.equal(filtered.body[0].eventCount, 4);
  const deviceEvents = Array.from({ length: 3 }, (_, index) => ({ eventId: randomUUID(), timestamp: new Date(baseTime + 10000 + index * 1000).toISOString(), rule: "sensitive_path", title: "Test endpoint signal", reason: "Synthetic endpoint signal for the same observed IP", evidence: { source: "mock" }, remoteAddress: ip, severity: "medium", category: "endpoint-detection" }));
  const deviceReport = { device: { deviceId: deviceResult.body.deviceId, hostname: "SG-INCIDENT-01", osVersion: "Windows Test", agentVersion: "0.4.0" }, timestamp: new Date().toISOString(), healthStatus: "healthy", processes: [], connections: [], events: deviceEvents };
  const devicePost = await jsonFetch(`/api/devices/${deviceResult.body.deviceId}/report`, { method: "POST", headers: { Authorization: `Bearer ${deviceResult.body.credential}` }, body: JSON.stringify(deviceReport) });
  assert.equal(devicePost.response.status, 200);
  const noFalsePositive = await jsonFetch("/api/application/events", { method: "POST", headers: ingestion, body: JSON.stringify({ ...applicationEvent, eventId: randomUUID(), assetId: computer.body.id, sourceIp: "203.0.113.88", timestamp: new Date(baseTime + 16000).toISOString() }) });
  assert.equal(noFalsePositive.response.status, 201);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM incidents").get().count, 2);
  const detail = await jsonFetch(`/api/incidents/${incident.id}`, { headers });
  assert.deepEqual(new Set(detail.body.events.map((event) => event.source)), new Set(["website-gateway", "application"]));
  assert.match(detail.body.observedFacts, /not a verified person's identity/);
  assert.match(detail.body.inference, /does not establish common authorship/);
  assert.equal((await jsonFetch(`/api/incidents/${incident.id}`)).response.status, 401);
});

test("incident notes, status audit, JSON/PDF exports, access control, and export retention work", async () => {
  const session = await setupAdmin(), headers = { Cookie: session.cookie };
  const asset = Number(db.prepare("INSERT INTO assets (name,type,owner,status,address,description,created_at) VALUES (?,?,?,?,?,?,?)").run("Report site", "website", "admin", "healthy", "https://report.test", "", new Date().toISOString()).lastInsertRowid);
  const now = new Date().toISOString(), ip = "198.51.100.90";
  for (let i = 0; i < 3; i++) {
    const eventId = Number(db.prepare(`INSERT INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,request_details,severity,detection_rule,created_at)
      VALUES (?,'website-gateway','http-request','blocked','Sensitive path','Observed probe evidence',?,'GET /\.env','medium','sensitive_path',?)`).run(asset, ip, new Date(Date.now() - 10000 + i * 1000).toISOString()).lastInsertRowid);
    const { correlateEvent } = await import("../src/incidents.js");
    correlateEvent(db, eventId);
  }
  const incident = db.prepare("SELECT id FROM incidents").get();
  assert.equal((await jsonFetch(`/api/incidents/${incident.id}/notes`, { method: "POST", body: JSON.stringify({ note: "Unauthenticated" }) })).response.status, 401);
  const note = await jsonFetch(`/api/incidents/${incident.id}/notes`, { method: "POST", headers, body: JSON.stringify({ note: "Reviewed evidence; continue monitoring." }) });
  assert.equal(note.response.status, 201);
  const status = await jsonFetch(`/api/incidents/${incident.id}/status`, { method: "PATCH", headers, body: JSON.stringify({ status: "investigating" }) });
  assert.equal(status.body.status, "investigating");
  const reportJson = await fetch(`${baseUrl}/api/incidents/${incident.id}/report?format=json`, { headers });
  assert.equal(reportJson.status, 200);
  const payload = await reportJson.json();
  assert.equal(payload.events.length, 3);
  assert.equal(payload.notes[0].note, "Reviewed evidence; continue monitoring.");
  assert.ok(payload.actions.length);
  assert.match(payload.limitations.join(" "), /does not identify a person/);
  const reportPdf = await fetch(`${baseUrl}/api/incidents/${incident.id}/report?format=pdf`, { headers });
  const pdf = Buffer.from(await reportPdf.arrayBuffer()).toString("ascii");
  assert.equal(reportPdf.status, 200);
  assert.ok(pdf.startsWith("%PDF-1.4"));
  assert.match(pdf, /Observed probe evidence/);
  assert.match(pdf, /does not identify a person/);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM incident_reports").get().count, 2);
  db.prepare("UPDATE incident_reports SET created_at='2020-01-01T00:00:00.000Z',expires_at='2020-01-01T00:00:00.000Z'").run();
  const cleanup = await jsonFetch("/api/retention/run", { method: "POST", headers, body: JSON.stringify({ days: 365, reportDays: 365 }) });
  assert.equal(cleanup.body.deletedReports, 2);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE target=? AND action='incident.status_changed'").get(`incident:${incident.id}`));
});

function addPolicyIncident(assetId, ip, { deviceId = null, severity = "high", rule = "sensitive_path", count = 3 } = {}) {
  const base = Date.now() - 20_000;
  for (let index = 0; index < count; index++) {
    const eventId = Number(db.prepare(`INSERT INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,request_details,severity,detection_rule,device_id,created_at)
      VALUES (?,'website-gateway','request','blocked','Policy test evidence','Synthetic repeat event',?,'GET /.env',?,?,?,?)`)
      .run(assetId, ip, severity, rule, deviceId, new Date(base + index * 1000).toISOString()).lastInsertRowid);
    correlateEvent(db, eventId);
  }
  return db.prepare("SELECT id FROM incidents WHERE asset_id=? AND observed_ip=? AND detection_rule=? ORDER BY created_at DESC LIMIT 1").get(assetId, ip, rule).id;
}

function policyRequest(assetId, targetType, targetId, overrides = {}) {
  return { name: "Repeated abuse response", assetId, detectionRule: "sensitive_path", minimumSeverity: "high", minimumEventCount: 3,
    windowMinutes: 10, targetType, targetId, protocol: "TCP", localPort: 443, durationMinutes: 30, ...overrides };
}

test("suggestion policies honor thresholds, suppress allowlisted evidence, and never auto-apply", async () => {
  const session = await setupAdmin(), headers = { Cookie: session.cookie };
  const site = Number(db.prepare("INSERT INTO assets (name,type,owner,status,address,created_at) VALUES ('Action site','website','admin','healthy','site.test',?)").run(new Date().toISOString()).lastInsertRowid);
  const ip = "203.0.113.61", incidentId = addPolicyIncident(site, ip);
  const under = await jsonFetch("/api/action-policies", { method: "POST", headers, body: JSON.stringify(policyRequest(site, "website", site, { name: "Threshold miss", minimumEventCount: 4 })) });
  assert.equal(under.response.status, 201);
  assert.equal((await jsonFetch("/api/actions", { headers })).body.length, 0);
  db.prepare("INSERT INTO gateway_allowlist (asset_id,ip,created_at) VALUES (?,?,?)").run(site, ip, new Date().toISOString());
  const protectedPolicy = await jsonFetch("/api/action-policies", { method: "POST", headers, body: JSON.stringify(policyRequest(site, "website", site, { name: "Allowlist suppress" })) });
  assert.equal(protectedPolicy.response.status, 201);
  assert.equal((await jsonFetch("/api/actions", { headers })).body.length, 0);
  const eligibleSite = Number(db.prepare("INSERT INTO assets (name,type,owner,status,address,created_at) VALUES ('Eligible action site','website','admin','healthy','eligible.test',?)").run(new Date().toISOString()).lastInsertRowid);
  const eligibleIncidentId = addPolicyIncident(eligibleSite, "203.0.113.62");
  const eligible = await jsonFetch("/api/action-policies", { method: "POST", headers, body: JSON.stringify(policyRequest(eligibleSite, "website", eligibleSite, { name: "Eligible suggestion" })) });
  assert.equal(eligible.body.mode, "suggestion-only");
  const actions = await jsonFetch("/api/actions", { headers });
  assert.equal(actions.body.length, 1);
  assert.equal(actions.body[0].incidentId, eligibleIncidentId);
  assert.equal(actions.body[0].status, "proposed");
  assert.equal(actions.body[0].evidence.qualifyingEventCount, 3);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM firewall_rules").get().count, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks").get().count, 0);
  assert.equal((await jsonFetch("/api/actions")).response.status, 401);
});

test("action proposals enforce protected addresses, explicit approval, idempotency, and one-click gateway rollback", async () => {
  const session = await setupAdmin(), headers = { Cookie: session.cookie };
  const site = Number(db.prepare("INSERT INTO assets (name,type,owner,status,address,created_at) VALUES ('Protected action site','website','admin','healthy','site.test',?)").run(new Date().toISOString()).lastInsertRowid);
  db.prepare("UPDATE firewall_settings SET management_addresses=? WHERE id=1").run(JSON.stringify(["10.20.0.4"]));
  db.prepare("UPDATE gateway_settings SET trusted_proxies=? WHERE id=1").run(JSON.stringify(["203.0.113.72"]));
  assert.match(validateActionTarget(db, { target_address: "127.0.0.1" }), /protected/);
  assert.match(validateActionTarget(db, { target_address: "10.20.0.4" }), /protected/);
  assert.match(validateActionTarget(db, { target_address: "203.0.113.72" }), /protected/);
  assert.match(validateActionTarget(db, { target_address: "203.0.113.73" }, ["203.0.113.73"]), /protected/);
  const allowIp = "203.0.113.74";
  db.prepare("INSERT INTO gateway_allowlist (asset_id,ip,created_at) VALUES (?,?,?)").run(site, allowIp, new Date().toISOString());
  assert.match(validateActionTarget(db, { target_address: allowIp }), /allowlist/);
  const ip = "203.0.113.75", incidentId = addPolicyIncident(site, ip);
  const policy = await jsonFetch("/api/action-policies", { method: "POST", headers, body: JSON.stringify(policyRequest(site, "website", site)) });
  const action = (await jsonFetch("/api/actions", { headers })).body[0];
  assert.equal(action.incidentId, incidentId);
  assert.equal((await jsonFetch(`/api/actions/${action.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: false }) })).response.status, 400);
  const paused = await jsonFetch("/api/actions/settings", { method: "PUT", headers, body: JSON.stringify({ emergencyPaused: true }) });
  assert.equal(paused.body.automaticBlockingEnabled, false);
  addPolicyIncident(site, "203.0.113.76");
  assert.equal((await jsonFetch("/api/actions", { headers })).body.length, 1, "pause must stop new proposals");
  assert.equal((await jsonFetch(`/api/actions/${action.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) })).response.status, 409);
  await jsonFetch("/api/actions/settings", { method: "PUT", headers, body: JSON.stringify({ emergencyPaused: false }) });
  assert.equal((await jsonFetch("/api/actions", { headers })).body.length, 2, "resume evaluates currently eligible open incidents");
  const approved = await jsonFetch(`/api/actions/${action.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) });
  assert.equal(approved.body.status, "active");
  assert.equal(approved.body.approvedBy, "admin@example.com");
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks WHERE action_id=?").get(action.id).count, 1);
  assert.equal((await jsonFetch(`/api/actions/${action.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) })).body.status, "active");
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks WHERE action_id=?").get(action.id).count, 1);
  const rolled = await jsonFetch(`/api/actions/${action.id}/rollback`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) });
  assert.equal(rolled.body.status, "rolled_back");
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks WHERE action_id=?").get(action.id).count, 0);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE target=? AND action='action.approved'").get(`action:${action.id}`));
  assert.ok(policy.body.enabled);
});

test("device actions wait for agent state, expire to removal, and alert on unverified removal failure", async () => {
  const session = await setupAdmin(), headers = { Cookie: session.cookie };
  const asset = Number(db.prepare("INSERT INTO assets (name,type,owner,status,address,created_at) VALUES ('Action device asset','computer','admin','healthy','SG-ACT-01',?)").run(new Date().toISOString()).lastInsertRowid);
  const enrolled = await jsonFetch("/api/devices/enroll", { method: "POST", headers, body: JSON.stringify({ name: "Action agent", hostname: "SG-ACT-01", osVersion: "Test Windows", agentVersion: "0.5.0", assetId: asset }) });
  const ip = "203.0.113.91", incidentId = addPolicyIncident(asset, ip, { deviceId: enrolled.body.deviceId, rule: "new_listening_port" });
  const policy = await jsonFetch("/api/action-policies", { method: "POST", headers, body: JSON.stringify(policyRequest(asset, "device", enrolled.body.deviceId, { detectionRule: "new_listening_port", minimumSeverity: "medium", localPort: 65001 })) });
  assert.equal(policy.response.status, 201);
  const action = (await jsonFetch("/api/actions", { headers })).body[0];
  assert.equal(action.status, "proposed");
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM firewall_rules").get().count, 0);
  const approved = await jsonFetch(`/api/actions/${action.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) });
  assert.equal(approved.body.status, "approved");
  assert.equal(approved.body.firewallStatus, "approved");
  assert.equal(approved.body.actualState, null, "agent disconnection must not be represented as OS application");
  await jsonFetch(`/api/actions/${action.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) });
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM firewall_rules WHERE action_id=?").get(action.id).count, 1);
  const ruleId = db.prepare("SELECT id FROM firewall_rules WHERE action_id=?").get(action.id).id;
  db.prepare("UPDATE proposed_actions SET expires_at=? WHERE id=?").run(new Date(Date.now() - 1000).toISOString(), action.id);
  db.prepare("UPDATE firewall_rules SET expires_at=? WHERE id=?").run(new Date(Date.now() - 1000).toISOString(), ruleId);
  const expired = await jsonFetch("/api/actions", { headers });
  assert.equal(expired.body[0].status, "expired");
  const config = await jsonFetch(`/api/devices/${enrolled.body.deviceId}/config`, { headers: { Authorization: `Bearer ${enrolled.body.credential}` } });
  assert.equal(config.body.firewallRules.find((rule) => rule.id === ruleId).operation, "remove");
  const failure = await jsonFetch(`/api/devices/${enrolled.body.deviceId}/firewall/state`, { method: "POST", headers: { Authorization: `Bearer ${enrolled.body.credential}` }, body: JSON.stringify({ results: [{ id: ruleId, status: "failed", detail: "Mock rule remained in operating system", actualState: { exists: true, group: "SentryGate" } }] }) });
  assert.equal(failure.response.status, 200);
  const failed = (await jsonFetch("/api/actions", { headers })).body[0];
  assert.equal(failed.status, "failed");
  assert.match(failed.failure, /remained/);
  assert.ok(db.prepare("SELECT 1 FROM alerts WHERE title='Temporary firewall rule removal failed' AND device_id=?").get(enrolled.body.deviceId));
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE target=? AND action='action.removal_failed'").get(`action:${action.id}`));
  assert.equal(incidentId, action.incidentId);
});

test("website action expiry removes the active gateway block", async () => {
  const session = await setupAdmin(), headers = { Cookie: session.cookie };
  const site = Number(db.prepare("INSERT INTO assets (name,type,owner,status,address,created_at) VALUES ('Expiring action site','website','admin','healthy','site.test',?)").run(new Date().toISOString()).lastInsertRowid);
  const ip = "203.0.113.101";
  addPolicyIncident(site, ip);
  await jsonFetch("/api/action-policies", { method: "POST", headers, body: JSON.stringify(policyRequest(site, "website", site, { durationMinutes: 1 })) });
  const action = (await jsonFetch("/api/actions", { headers })).body[0];
  await jsonFetch(`/api/actions/${action.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) });
  db.prepare("UPDATE gateway_ip_blocks SET expires_at=? WHERE action_id=?").run(new Date(Date.now() - 1000).toISOString(), action.id);
  expireGatewayActions(db);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks WHERE action_id=?").get(action.id).count, 0);
  assert.equal(db.prepare("SELECT status FROM proposed_actions WHERE id=?").get(action.id).status, "expired");
});

test("protects event ingestion with a rotatable credential stored as a verifier", async () => {
  const session = await setupAdmin();
  const assetId = Number(db.prepare(`INSERT INTO assets (name,type,owner,status,address,description,created_at)
    VALUES ('Gateway site','website','admin@example.com','healthy','local.test','',?)`).run(new Date().toISOString()).lastInsertRowid);
  const event = { assetId, timestamp: new Date().toISOString(), sourceIp: "192.0.2.50", method: "GET", path: "/.env", userAgent: "test", responseStatus: 403, detectionRule: "sensitive_path", action: "blocked", severity: "medium", reason: "Sensitive-path rule matched" };
  assert.equal((await jsonFetch("/api/agent/events", { method: "POST", body: JSON.stringify(event) })).response.status, 401);
  const rotated = await jsonFetch("/api/agent/credential/rotate", { method: "POST", headers: { Cookie: session.cookie } });
  assert.equal(rotated.response.status, 200);
  const credential = rotated.body.credential;
  const row = db.prepare("SELECT token_hash,token_ciphertext FROM agent_credentials WHERE id = 1").get();
  assert.notEqual(row.token_hash, credential);
  assert.notEqual(row.token_ciphertext, credential);
  const accepted = await jsonFetch("/api/agent/events", { method: "POST", headers: { Authorization: `Bearer ${credential}` }, body: JSON.stringify(event) });
  assert.equal(accepted.response.status, 201);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM alerts WHERE asset_id = ?").get(assetId).count, 1);
  const rotatedAgain = await jsonFetch("/api/agent/credential/rotate", { method: "POST", headers: { Cookie: session.cookie } });
  assert.equal(rotatedAgain.response.status, 200);
  assert.equal((await jsonFetch("/api/agent/events", { method: "POST", headers: { Authorization: `Bearer ${credential}` }, body: JSON.stringify(event) })).response.status, 401);
  const auditActions = db.prepare("SELECT action FROM audit_log").all().map((entry) => entry.action);
  assert.equal(auditActions.filter((action) => action === "agent.credential_rotated").length, 2);
});

test("audits protection, allowlist, and trusted-proxy configuration changes", async () => {
  const session = await setupAdmin();
  const cookie = { Cookie: session.cookie };
  const assetId = Number(db.prepare(`INSERT INTO assets (name,type,owner,status,address,description,created_at)
    VALUES ('Owned site','website','admin@example.com','healthy','owned.test','',?)`).run(new Date().toISOString()).lastInsertRowid);
  db.prepare("INSERT INTO gateway_rules (asset_id,updated_at) VALUES (?,?)").run(assetId, new Date().toISOString());
  const protection = await jsonFetch(`/api/assets/${assetId}/protection`, { method: "PUT", headers: cookie, body: JSON.stringify({
    upstreamUrl: "http://127.0.0.1:4320", enabled: true, mode: "block", rateLimitCount: 30, windowSeconds: 45,
    sensitivePathsEnabled: true, allowlist: ["192.0.2.8"]
  }) });
  assert.equal(protection.response.status, 200);
  const trusted = await jsonFetch("/api/gateway/settings", { method: "PUT", headers: cookie, body: JSON.stringify({ trustedProxies: ["127.0.0.1"] }) });
  assert.equal(trusted.response.status, 200);
  const actions = db.prepare("SELECT action FROM audit_log ORDER BY id").all().map((entry) => entry.action);
  assert.ok(actions.includes("protection.updated"));
  assert.ok(actions.includes("allowlist.updated"));
  assert.ok(actions.includes("trusted_proxies.updated"));
});

test("retention cleanup removes old events and audit rows", async () => {
  const session = await setupAdmin();
  const old = new Date(Date.now() - 90 * 86_400_000).toISOString();
  db.prepare("INSERT INTO events (source, category, action, reason, evidence, created_at) VALUES (?, ?, ?, ?, ?, ?)").run("test", "request", "record", "old event", "retention test", old);
  db.prepare("INSERT INTO audit_log (actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?)").run("test", "old.audit", "test", "retention test", old);
  const result = await jsonFetch("/api/retention/run", { method: "POST", headers: { Cookie: session.cookie }, body: JSON.stringify({ days: 30 }) });
  assert.equal(result.response.status, 200);
  assert.ok(result.body.deletedEvents >= 1);
  assert.ok(result.body.deletedAudit >= 1);
});

test("enrolls a unique device credential, authenticates reports, and prevents duplicate alerts", async () => {
  const session = await setupAdmin();
  const headers = { Cookie: session.cookie };
  const enroll = await jsonFetch("/api/devices/enroll", { method: "POST", headers, body: JSON.stringify({ name: "Workstation", hostname: "SG-WIN-01", osVersion: "Windows 11", agentVersion: "0.3.0" }) });
  assert.equal(enroll.response.status, 201);
  const { deviceId, credential } = enroll.body;
  const stored = db.prepare("SELECT credential_hash FROM device_agents WHERE device_id=?").get(deviceId);
  assert.notEqual(stored.credential_hash, credential);
  const timestamp = new Date().toISOString();
  const report = { device: { deviceId, hostname: "SG-WIN-01", osVersion: "Windows 11", agentVersion: "0.3.0" }, timestamp, healthStatus: "healthy",
    processes: [{ pid: 24, parentPid: 1, name: "worker.exe", startedAt: timestamp }],
    connections: [{ pid: 24, protocol: "TCP", state: "Listen", localAddress: "0.0.0.0", localPort: 9443, remoteAddress: "0.0.0.0", remotePort: 0, timestamp }],
    events: [{ eventId: "stable-demo-id", timestamp, category: "endpoint-detection", rule: "new_listening_port", title: "New listening TCP port", severity: "medium", reason: "Listener appeared at 0.0.0.0:9443", evidence: { endpoint: "0.0.0.0:9443", pid: 24 }, processDetails: "PID 24 worker.exe" }] };
  const invalid = await jsonFetch(`/api/devices/${deviceId}/report`, { method: "POST", body: JSON.stringify(report) });
  assert.equal(invalid.response.status, 401);
  const auth = { Authorization: `Bearer ${credential}` };
  assert.equal((await jsonFetch(`/api/devices/${deviceId}/report`, { method: "POST", headers: auth, body: JSON.stringify(report) })).response.status, 200);
  const replay = await jsonFetch(`/api/devices/${deviceId}/report`, { method: "POST", headers: auth, body: JSON.stringify(report) });
  assert.deepEqual(replay.body.acceptedEventIds, ["stable-demo-id"]);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM events WHERE source_event_id='stable-demo-id'").get().count, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM alerts WHERE device_id=?").get(deviceId).count, 1);
  const device = await jsonFetch(`/api/devices/${deviceId}`, { headers });
  assert.equal(device.body.processes[0].pid, 24);
  const filtered = await jsonFetch(`/api/events?deviceId=${deviceId}&severity=medium&from=${timestamp.slice(0, 10)}&to=${timestamp.slice(0, 10)}`, { headers });
  assert.equal(filtered.body.length, 1);
  const alertFiltered = await jsonFetch(`/api/alerts?deviceId=${deviceId}&severity=medium`, { headers });
  assert.equal(alertFiltered.body.length, 1);
  assert.equal(alertFiltered.body[0].deviceName, "Workstation");
  const rotated = await jsonFetch(`/api/devices/${deviceId}/credential/rotate`, { method: "POST", headers });
  assert.equal(rotated.response.status, 200);
  assert.equal((await jsonFetch(`/api/devices/${deviceId}/config`, { headers: auth })).response.status, 401);
  const revoke = await jsonFetch(`/api/devices/${deviceId}/credential/revoke`, { method: "POST", headers });
  assert.equal(revoke.response.status, 200);
  assert.equal((await jsonFetch(`/api/devices/${deviceId}/config`, { headers: { Authorization: `Bearer ${rotated.body.credential}` } })).response.status, 401);
  assert.ok(db.prepare("SELECT COUNT(*) AS count FROM audit_log WHERE action LIKE 'device.%'").get().count >= 3);
});

test("validates device enrollment and collection settings", async () => {
  const session = await setupAdmin();
  const headers = { Cookie: session.cookie };
  assert.equal((await jsonFetch("/api/devices/enroll", { method: "POST", headers, body: JSON.stringify({ name: "", hostname: "h", osVersion: "win", agentVersion: "x" }) })).response.status, 400);
  const enrolled = await jsonFetch("/api/devices/enroll", { method: "POST", headers, body: JSON.stringify({ name: "Desk", hostname: "desk", osVersion: "Windows", agentVersion: "0.3" }) });
  const settings = await jsonFetch(`/api/devices/${enrolled.body.deviceId}/settings`, { method: "PUT", headers, body: JSON.stringify({ collectProcesses: false, collectConnections: true, intervalSeconds: 5, outboundConnectionThreshold: 50, retainedDays: 30 }) });
  assert.equal(settings.response.status, 400);
});
