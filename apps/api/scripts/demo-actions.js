import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { createServer } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { correlateEvent } from "../src/incidents.js";

const db = openDatabase(":memory:");
const config = loadConfig({ dbPath: ":memory:", port: 0, gatewayPort: 0, sessionSecret: crypto.randomBytes(48).toString("base64url"), webRoot: path.resolve("apps/web") });
const server = createServer(db, config);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;

async function request(route, options = {}) {
  const response = await fetch(`${base}${route}`, { headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }, ...options });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null, cookie: response.headers.get("set-cookie")?.split(";")[0] };
}

try {
  const admin = await request("/api/setup", { method: "POST", body: JSON.stringify({ email: "demo@sentrygate.local", password: "ephemeral-in-memory-demo-password" }) });
  assert.equal(admin.status, 201);
  const headers = { Cookie: admin.cookie };
  const asset = await request("/api/assets", { method: "POST", headers, body: JSON.stringify({ name: "Synthetic action demo website", type: "website", address: "https://demo.invalid", description: "Synthetic in-memory demonstration only" }) });
  assert.equal(asset.status, 201);
  const ip = "198.51.100.42", now = Date.now();
  for (let index = 0; index < 3; index++) {
    const eventId = Number(db.prepare(`INSERT INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,severity,detection_rule,created_at)
      VALUES (?,'website-gateway','request','observed','Synthetic sensitive-path observation','Demo evidence only',?,'high','sensitive_path',?)`)
      .run(asset.body.id, ip, new Date(now - 10_000 + index * 1000).toISOString()).lastInsertRowid);
    correlateEvent(db, eventId);
  }
  const policy = await request("/api/action-policies", { method: "POST", headers, body: JSON.stringify({ name: "In-memory demo policy", assetId: asset.body.id, detectionRule: "sensitive_path", minimumSeverity: "high", minimumEventCount: 3, windowMinutes: 10, targetType: "website", targetId: asset.body.id, protocol: "TCP", localPort: 443, durationMinutes: 5 }) });
  assert.equal(policy.status, 201);
  const queue = await request("/api/actions", { headers });
  const proposal = queue.body[0];
  assert.equal(proposal.status, "proposed");
  console.log(`PROPOSED: ${proposal.id} | ${proposal.evidence.qualifyingEventCount} synthetic events | ${proposal.targetAddress} | ${proposal.expectedEffect}`);
  const approved = await request(`/api/actions/${proposal.id}/approve`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) });
  assert.equal(approved.status, 200);
  assert.equal(approved.body.status, "active");
  assert.equal(approved.body.approvedBy, "demo@sentrygate.local");
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks WHERE action_id=?").get(proposal.id).count, 1);
  console.log(`APPROVED: by ${approved.body.approvedBy} at ${approved.body.approvedAt} | active local gateway entry | no external traffic`);
  const rolled = await request(`/api/actions/${proposal.id}/rollback`, { method: "POST", headers, body: JSON.stringify({ confirmed: true }) });
  assert.equal(rolled.status, 200);
  assert.equal(rolled.body.status, "rolled_back");
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks WHERE action_id=?").get(proposal.id).count, 0);
  console.log(`ROLLED BACK: ${rolled.body.status} | temporary gateway entry removed | Windows Firewall untouched`);
} finally {
  await new Promise((resolve) => server.close(resolve));
  db.close();
}
