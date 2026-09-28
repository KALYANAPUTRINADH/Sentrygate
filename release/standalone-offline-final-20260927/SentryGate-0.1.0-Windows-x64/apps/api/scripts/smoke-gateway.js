import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { createServer as createApiServer } from "../src/app.js";
import { ensureAgentCredential } from "../src/agent-credentials.js";
import { loadConfig } from "../src/config.js";
import { migrate } from "../src/db.js";
import { createGatewayServer } from "../src/gateway.js";
import { fileURLToPath } from "node:url";

const db = new DatabaseSync(":memory:");
const config = loadConfig({ dbPath: ":memory:", sessionSecret: crypto.randomBytes(48).toString("base64url"), host: "127.0.0.1", gatewayHost: "127.0.0.1", port: 0, gatewayPort: 0, webRoot: fileURLToPath(new URL("../../web", import.meta.url)) });
migrate(db);
ensureAgentCredential(db, config.sessionSecret);

const upstream = http.createServer((_req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("sample upstream response");
});
const api = createApiServer(db, config);
let gateway;

async function listen(server) {
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
}
async function close(server) {
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
}

try {
  await listen(upstream);
  api.listen(0, "127.0.0.1");
  await new Promise((resolve) => api.once("listening", resolve));
  config.apiBaseUrl = `http://127.0.0.1:${api.address().port}`;
  gateway = createGatewayServer(db, config);
  await listen(gateway);
  const assetId = Number(db.prepare(`INSERT INTO assets (name,type,owner,status,address,description,upstream_url,created_at)
    VALUES (?,?,?,?,?,?,?,?)`).run("Local smoke site", "website", "local", "healthy", "local.test", "", `http://127.0.0.1:${upstream.address().port}`, new Date().toISOString()).lastInsertRowid);
  db.prepare("INSERT INTO gateway_rules (asset_id,updated_at) VALUES (?,?)").run(assetId, new Date().toISOString());
  const base = `http://127.0.0.1:${gateway.address().port}/site/${assetId}`;

  const normal = await fetch(`${base}/`);
  assert.equal(normal.status, 200);
  assert.equal(await normal.text(), "sample upstream response");
  console.log(`Normal request: HTTP ${normal.status}, response forwarded from local upstream.`);

  db.prepare("UPDATE gateway_rules SET mode = 'block' WHERE asset_id = ?").run(assetId);
  const blocked = await fetch(`${base}/.env`);
  assert.equal(blocked.status, 403);
  console.log(`Sensitive-path probe: HTTP ${blocked.status}, blocked by sensitive_path rule.`);
  console.log(`Ingested events: ${db.prepare("SELECT COUNT(*) AS count FROM events").get().count}; alerts: ${db.prepare("SELECT COUNT(*) AS count FROM alerts").get().count}.`);
} finally {
  await close(gateway);
  await close(api);
  await close(upstream);
  db.close();
}
