import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createServer } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";

test("two standalone installations keep administrators, credentials, events, storage, and listeners independent", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sentrygate-standalone-"));
  const installations = [];
  t.after(async () => {
    for (const item of installations) {
      await new Promise((resolve) => item.server.close(resolve));
      item.db.close();
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  for (const suffix of ["one", "two"]) {
    const dataDir = path.join(root, suffix, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const dbPath = path.join(dataDir, "sentrygate.db");
    const config = loadConfig({ standalone: true, dbPath, dataDir, host: "0.0.0.0", gatewayHost: "0.0.0.0", remoteAccessEnabled: true, apiBaseUrl: "https://203.0.113.8", port: 0, sessionSecret: `${suffix}-distinct-session-secret-value-32` });
    const db = openDatabase(dbPath), server = createServer(db, config);
    await new Promise((resolve) => server.listen(0, config.host, resolve));
    installations.push({ config, db, server, base: `http://127.0.0.1:${server.address().port}` });
    assert.equal(server.address().address, "127.0.0.1");
  }

  const request = async (installation, url, options = {}) => {
    const response = await fetch(`${installation.base}${url}`, { headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }, ...options });
    return { status: response.status, body: await response.json(), cookie: response.headers.get("set-cookie")?.split(";")[0] };
  };
  const devices = [];
  for (let index = 0; index < installations.length; index++) {
    const owner = await request(installations[index], "/api/setup", { method: "POST", body: JSON.stringify({ email: `owner${index}@sentrygate.test`, password: `local-owner-password-${index}-unique` }) });
    assert.equal(owner.status, 201);
    const enrolled = await request(installations[index], "/api/devices/enroll", { method: "POST", headers: { Cookie: owner.cookie }, body: JSON.stringify({ name: `Local computer ${index}`, hostname: `LOCAL-${index}`, osVersion: "Windows test", agentVersion: "0.3.0" }) });
    assert.equal(enrolled.status, 201);
    const remoteEnrollment = await request(installations[index], "/api/devices/enroll", { method: "POST", headers: { Cookie: owner.cookie }, body: JSON.stringify({ name: "Another computer", hostname: "OTHER-PC", osVersion: "Windows test", agentVersion: "0.3.0" }) });
    assert.equal(remoteEnrollment.status, 409);
    devices.push({ owner, enrolled });
    const event = { eventId: randomUUID(), rule: "new_listening_port", title: `Only installation ${index}`, reason: "Synthetic local listener evidence", evidence: { local: true }, timestamp: new Date().toISOString(), severity: "medium", category: "endpoint-detection" };
    const report = { device: { deviceId: enrolled.body.deviceId, hostname: `LOCAL-${index}`, osVersion: "Windows test", agentVersion: "0.3.0" }, timestamp: new Date().toISOString(), healthStatus: "healthy", processes: [], connections: [], events: [event] };
    const delivered = await request(installations[index], `/api/devices/${enrolled.body.deviceId}/report`, { method: "POST", headers: { Authorization: `Bearer ${enrolled.body.credential}` }, body: JSON.stringify(report) });
    assert.equal(delivered.status, 200);
  }

  for (let index = 0; index < installations.length; index++) {
    const own = await request(installations[index], "/api/devices", { headers: { Cookie: devices[index].owner.cookie } });
    const health = await request(installations[index], "/api/health");
    assert.equal(own.body.length, 1);
    assert.equal(own.body[0].deviceId, devices[index].enrolled.body.deviceId);
    assert.equal(health.body.standalone, true);
    assert.equal(health.body.remoteAccessEnabled, false);
    assert.equal(installations[index].config.apiBaseUrl, "http://127.0.0.1:0");
    const eventRows = installations[index].db.prepare("SELECT reason FROM events").all();
    assert.deepEqual(eventRows.map((row) => row.reason), ["Synthetic local listener evidence"]);
  }
  assert.notEqual(devices[0].enrolled.body.deviceId, devices[1].enrolled.body.deviceId);
  assert.notEqual(devices[0].enrolled.body.credential, devices[1].enrolled.body.credential);
  const crossCredential = await request(installations[0], `/api/devices/${devices[1].enrolled.body.deviceId}/config`, { headers: { Authorization: `Bearer ${devices[1].enrolled.body.credential}` } });
  assert.equal(crossCredential.status, 401);
});
