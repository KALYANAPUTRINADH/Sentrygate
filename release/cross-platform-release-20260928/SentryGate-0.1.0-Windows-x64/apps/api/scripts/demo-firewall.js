import crypto from "node:crypto";
import path from "node:path";
import { createServer } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";

const db = openDatabase(":memory:");
const config = loadConfig({ dbPath: ":memory:", apiBaseUrl: "http://127.0.0.1:0", sessionSecret: crypto.randomBytes(32).toString("base64url"), webRoot: path.resolve("apps/web") });
const server = createServer(db, config);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
config.apiBaseUrl = `http://127.0.0.1:${server.address().port}`;
const base = config.apiBaseUrl;
async function request(path, options = {}) {
  const response = await fetch(`${base}${path}`, { headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }, ...options });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? `Request failed (${response.status})`);
  return { body, cookie: response.headers.get("set-cookie")?.split(";")[0] };
}
try {
  const admin = await request("/api/setup", { method: "POST", body: JSON.stringify({ email: "demo@sentrygate.local", password: "demo-only-password-2026" }) });
  const cookie = { Cookie: admin.cookie };
  const device = await request("/api/devices/enroll", { method: "POST", headers: cookie, body: JSON.stringify({ name: "Mock Windows test device", hostname: "SG-DEMO", osVersion: "Windows mock", agentVersion: "0.4.0" }) });
  const rule = await request("/api/firewall/rules", { method: "POST", headers: cookie, body: JSON.stringify({ deviceId: device.body.deviceId, remoteCidr: "198.51.100.24/32", protocol: "TCP", localPort: 65000, reason: "Demonstrate preview and rollback", evidence: "Synthetic local demo only; no network observation", expiresAt: new Date(Date.now() + 60000).toISOString(), idempotencyKey: crypto.randomUUID() }) });
  console.log("PREVIEW (no firewall operation):", JSON.stringify({ status: rule.body.rule.status, remote: rule.body.rule.remoteCidr, protocol: rule.body.rule.protocol, port: rule.body.rule.localPort, expiresAt: rule.body.rule.expiresAt }));
  await request(`/api/firewall/rules/${rule.body.rule.id}/approve`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: true, previewToken: rule.body.previewToken }) });
  const authorization = { Authorization: `Bearer ${device.body.credential}` };
  const desired = await request(`/api/devices/${device.body.deviceId}/config`, { headers: authorization });
  const mockApply = async (entry) => ({ id: entry.id, status: "active", detail: "Mock operation: no Windows API called", actualState: { name: entry.name, group: "SentryGate", action: "Block", direction: "Inbound" } });
  const applied = await mockApply(desired.body.firewallRules[0]);
  await request(`/api/devices/${device.body.deviceId}/firewall/state`, { method: "POST", headers: authorization, body: JSON.stringify({ results: [applied] }) });
  console.log("MOCK APPLY:", applied.detail);
  await request(`/api/firewall/rules/${rule.body.rule.id}/rollback`, { method: "POST", headers: cookie, body: JSON.stringify({ confirmed: true }) });
  const removal = await request(`/api/devices/${device.body.deviceId}/config`, { headers: authorization });
  const mockRemove = { id: rule.body.rule.id, status: "removed", detail: "Mock operation: SentryGate rule removed", actualState: null };
  if (removal.body.firewallRules[0]?.operation !== "remove") throw new Error("Rollback was not delivered as a removal");
  await request(`/api/devices/${device.body.deviceId}/firewall/state`, { method: "POST", headers: authorization, body: JSON.stringify({ results: [mockRemove] }) });
  const final = await request("/api/firewall/rules", { headers: cookie });
  console.log("MOCK ROLLBACK:", final.body[0].status, "(no Windows firewall touched)");
} finally {
  await new Promise((resolve) => server.close(resolve));
  db.close();
}
