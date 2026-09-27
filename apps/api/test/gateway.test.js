import assert from "node:assert/strict";
import http from "node:http";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import test, { afterEach, beforeEach } from "node:test";
import { createServer as createApiServer } from "../src/app.js";
import { ensureAgentCredential } from "../src/agent-credentials.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { createGatewayServer } from "../src/gateway.js";

let db;
let config;
let api;
let gateway;
let upstream;
let apiUrl;
let gatewayUrl;
let upstreamUrl;
let assetId;
let upstreamHits;

beforeEach(async () => {
  config = loadConfig({ dbPath: path.join(os.tmpdir(), `sentrygate-gateway-${randomUUID()}.db`), sessionSecret: "gateway-test-session-secret-with-32-characters", host: "127.0.0.1", gatewayHost: "127.0.0.1", port: 0, gatewayPort: 0, webRoot: path.resolve("apps/web") });
  db = openDatabase(config.dbPath);
  ensureAgentCredential(db, config.sessionSecret);
  upstreamHits = 0;
  upstream = http.createServer(async (req, res) => {
    upstreamHits++;
    let bytes = 0;
    for await (const chunk of req) bytes += chunk.length;
    const body = JSON.stringify({ method: req.method, path: req.url, bytes, forwardedFor: req.headers["x-forwarded-for"], userAgent: req.headers["user-agent"] });
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), "X-Upstream": "sample" });
    res.end(body);
  });
  upstream.listen(0, "127.0.0.1");
  await new Promise((resolve) => upstream.once("listening", resolve));
  upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;
  api = createApiServer(db, config);
  api.listen(0, "127.0.0.1");
  await new Promise((resolve) => api.once("listening", resolve));
  apiUrl = `http://127.0.0.1:${api.address().port}`;
  config.apiBaseUrl = apiUrl;
  gateway = createGatewayServer(db, config);
  gateway.listen(0, "127.0.0.1");
  await new Promise((resolve) => gateway.once("listening", resolve));
  gatewayUrl = `http://127.0.0.1:${gateway.address().port}`;
  assetId = Number(db.prepare(`INSERT INTO assets (name,type,owner,status,address,description,upstream_url,created_at)
    VALUES ('Test site','website','test','healthy','local.test','','',?)`).run(new Date().toISOString()).lastInsertRowid);
  db.prepare("INSERT INTO gateway_rules (asset_id,updated_at) VALUES (?,?)").run(assetId, new Date().toISOString());
  setProtection({ upstreamUrl });
});

afterEach(async () => {
  await Promise.all([closeServer(gateway), closeServer(api), closeServer(upstream)]);
  db.close();
});

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

function setProtection({ mode = "observe", enabled = true, rateLimitCount = 120, windowSeconds = 60, allowlist = [], upstreamUrl: upstreamAddress = upstreamUrl, sensitivePathsEnabled = true } = {}) {
  db.prepare("UPDATE assets SET upstream_url = ? WHERE id = ?").run(upstreamAddress, assetId);
  db.prepare(`UPDATE gateway_rules SET enabled=?,mode=?,rate_limit_count=?,window_seconds=?,sensitive_paths_enabled=?,updated_at=? WHERE asset_id=?`)
    .run(enabled ? 1 : 0, mode, rateLimitCount, windowSeconds, sensitivePathsEnabled ? 1 : 0, new Date().toISOString(), assetId);
  db.prepare("DELETE FROM gateway_allowlist WHERE asset_id = ?").run(assetId);
  for (const ip of allowlist) db.prepare("INSERT INTO gateway_allowlist (asset_id,ip,created_at) VALUES (?,?,?)").run(assetId, ip, new Date().toISOString());
}

async function request(pathname, options = {}) {
  return fetch(`${gatewayUrl}/site/${assetId}${pathname}`, options);
}

async function waitForEvents(count) {
  for (let i = 0; i < 30; i++) {
    const found = db.prepare("SELECT COUNT(*) AS count FROM events WHERE asset_id = ?").get(assetId).count;
    if (found >= count) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail(`Expected ${count} gateway event(s)`);
}

test("forwards normal requests and streams uploads while recording request evidence", async () => {
  const response = await request("/health?check=1", { headers: { "User-Agent": "sentrygate-test-agent" } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-upstream"), "sample");
  const result = await response.json();
  assert.equal(result.path, "/health?check=1");
  assert.match(result.forwardedFor, /127\.0\.0\.1/);

  const bytes = Buffer.alloc(256 * 1024, 65);
  const upload = await request("/upload", { method: "POST", headers: { "Content-Type": "application/octet-stream", "Content-Length": String(bytes.length), "User-Agent": "upload-test-agent" }, body: bytes });
  assert.equal(upload.status, 200);
  assert.equal((await upload.json()).bytes, bytes.length);
  await waitForEvents(2);
  const event = db.prepare("SELECT * FROM events WHERE request_path = ? ORDER BY id DESC LIMIT 1").get("/site/" + assetId + "/upload");
  assert.equal(event.method, "POST");
  assert.equal(event.user_agent, "upload-test-agent");
  assert.equal(event.response_status, 200);
  assert.equal(event.detection_rule, "none");
  assert.equal(event.action, "forwarded");
  assert.equal(event.observed_source_ip, "127.0.0.1");
});

test("observe mode records sensitive path probes and passes them upstream", async () => {
  const response = await request("/.env");
  assert.equal(response.status, 200);
  assert.equal(upstreamHits, 1);
  await waitForEvents(1);
  const event = db.prepare("SELECT detection_rule,action,response_status FROM events WHERE asset_id = ?").get(assetId);
  assert.equal(event.detection_rule, "sensitive_path");
  assert.equal(event.action, "observed");
  assert.equal(event.response_status, 200);
});

test("block mode rejects sensitive path probes and creates an explainable alert", async () => {
  setProtection({ mode: "block" });
  const response = await request("/.git/config");
  assert.equal(response.status, 403);
  assert.equal(upstreamHits, 0);
  await waitForEvents(1);
  const event = db.prepare("SELECT detection_rule,action,reason,response_status FROM events WHERE asset_id = ?").get(assetId);
  assert.equal(event.detection_rule, "sensitive_path");
  assert.equal(event.action, "blocked");
  assert.equal(event.response_status, 403);
  const alert = db.prepare("SELECT title,observed_facts FROM alerts WHERE asset_id = ?").get(assetId);
  assert.match(alert.title, /Sensitive path/);
  assert.match(alert.observed_facts, /matches an enabled sensitive-path rule/);
});

test("detects percent-encoded sensitive path segments", async () => {
  setProtection({ mode: "block" });
  const response = await request("/%2eenv");
  assert.equal(response.status, 403);
  await waitForEvents(1);
  assert.equal(db.prepare("SELECT detection_rule FROM events WHERE asset_id = ?").get(assetId).detection_rule, "sensitive_path");
});

test("enforces a configurable per-IP rate limit in block mode", async () => {
  setProtection({ mode: "block", rateLimitCount: 2, windowSeconds: 60 });
  assert.equal((await request("/one")).status, 200);
  assert.equal((await request("/two")).status, 200);
  assert.equal((await request("/three")).status, 429);
  await waitForEvents(3);
  const event = db.prepare("SELECT detection_rule,action,response_status FROM events WHERE detection_rule = 'rate_limit'").get();
  assert.equal(event.action, "blocked");
  assert.equal(event.response_status, 429);
});

test("allowlisted IP bypasses sensitive-path and rate rules", async () => {
  setProtection({ mode: "block", rateLimitCount: 1, allowlist: ["127.0.0.1"] });
  const response = await request("/.git/config");
  assert.equal(response.status, 200);
  await waitForEvents(1);
  const event = db.prepare("SELECT detection_rule,action FROM events WHERE asset_id = ?").get(assetId);
  assert.equal(event.detection_rule, "allowlist");
  assert.equal(event.action, "allowlisted");
});

test("enforces an approved temporary gateway block and allows traffic after expiry", async () => {
  const now = new Date().toISOString(), incidentId = randomUUID(), policyId = randomUUID(), actionId = randomUUID();
  db.prepare(`INSERT INTO incidents (id,correlation_key,asset_id,observed_ip,detection_rule,severity,status,first_seen,last_seen,event_count,created_at,updated_at)
    VALUES (?,?,?,'127.0.0.1','sensitive_path','high','open',?,?,3,?,?)`).run(incidentId, `site:${assetId}`, assetId, now, now, now, now);
  db.prepare(`INSERT INTO action_policies (id,name,asset_id,minimum_severity,minimum_event_count,window_minutes,target_type,target_id,protocol,local_port,duration_minutes,created_by,created_at,updated_at)
    VALUES (?,'gateway test policy',?,'high',3,10,'website',?,'TCP',443,1,'test',?,?)`).run(policyId, assetId, String(assetId), now, now);
  db.prepare(`INSERT INTO proposed_actions (id,idempotency_key,policy_id,incident_id,target_type,target_id,target_address,expected_effect,evidence_json,expires_at,status,created_at,updated_at)
    VALUES (?,?,?,?, 'website',?,'127.0.0.1','Synthetic temporary block','{}',?,'active',?,?)`).run(actionId, `test:${actionId}`, policyId, incidentId, String(assetId), new Date(Date.now() + 60_000).toISOString(), now, now);
  db.prepare("INSERT INTO gateway_ip_blocks (action_id,asset_id,ip,expires_at,created_at) VALUES (?,?,?,?,?)").run(actionId, assetId, "127.0.0.1", new Date(Date.now() + 60_000).toISOString(), now);
  const denied = await request("/safe");
  assert.equal(denied.status, 403);
  await waitForEvents(1);
  const event = db.prepare("SELECT detection_rule,action,reason FROM events WHERE asset_id=?").get(assetId);
  assert.equal(event.detection_rule, "approved_block");
  assert.equal(event.action, "blocked");
  assert.match(event.reason, /administrator-approved/);
  db.prepare("UPDATE gateway_ip_blocks SET expires_at=? WHERE action_id=?").run(new Date(Date.now() - 1000).toISOString(), actionId);
  const restored = await request("/safe-again");
  assert.equal(restored.status, 200);
  assert.equal(db.prepare("SELECT status FROM proposed_actions WHERE id=?").get(actionId).status, "expired");
});

test("ignores forged forwarded IP headers from an untrusted connecting peer", async () => {
  const response = await request("/client", { headers: { "X-Forwarded-For": "198.51.100.99", "User-Agent": "forgery-test" } });
  assert.equal(response.status, 200);
  await waitForEvents(1);
  const event = db.prepare("SELECT observed_source_ip,user_agent FROM events WHERE asset_id = ?").get(assetId);
  assert.equal(event.observed_source_ip, "127.0.0.1");
  assert.equal(event.user_agent, "forgery-test");
});

test("uses the forwarded client IP only after the immediate peer is trusted", async () => {
  db.prepare("UPDATE gateway_settings SET trusted_proxies = ? WHERE id = 1").run(JSON.stringify(["127.0.0.1"]));
  const response = await request("/trusted", { headers: { "X-Forwarded-For": "203.0.113.8, 198.51.100.4" } });
  assert.equal(response.status, 200);
  await waitForEvents(1);
  const event = db.prepare("SELECT observed_source_ip FROM events WHERE asset_id = ?").get(assetId);
  assert.equal(event.observed_source_ip, "198.51.100.4");
});

test("returns 501 and records unsupported WebSocket upgrade attempts", async () => {
  const status = await new Promise((resolve, reject) => {
    const upgradeRequest = http.request(`${gatewayUrl}/site/${assetId}/socket`, { headers: { Connection: "Upgrade", Upgrade: "websocket" } });
    upgradeRequest.on("response", (response) => resolve(response.statusCode));
    upgradeRequest.on("upgrade", (response, socket) => { socket.destroy(); resolve(response.statusCode); });
    upgradeRequest.on("error", reject);
    upgradeRequest.end();
  });
  assert.equal(status, 501);
  await waitForEvents(1);
  const event = db.prepare("SELECT detection_rule,response_status,action FROM events WHERE asset_id = ?").get(assetId);
  assert.equal(event.detection_rule, "websocket_unsupported");
  assert.equal(event.response_status, 501);
  assert.equal(event.action, "unsupported");
});

test("reports unavailable upstream with 502 and event evidence", async () => {
  const unavailable = http.createServer();
  unavailable.listen(0, "127.0.0.1");
  await new Promise((resolve) => unavailable.once("listening", resolve));
  const unavailableUrl = `http://127.0.0.1:${unavailable.address().port}`;
  await closeServer(unavailable);
  setProtection({ upstreamUrl: unavailableUrl });
  const response = await request("/offline");
  assert.equal(response.status, 502);
  await waitForEvents(1);
  const event = db.prepare("SELECT detection_rule,action,response_status FROM events WHERE asset_id = ?").get(assetId);
  assert.equal(event.detection_rule, "upstream_unavailable");
  assert.equal(event.action, "upstream-error");
  assert.equal(event.response_status, 502);
});
