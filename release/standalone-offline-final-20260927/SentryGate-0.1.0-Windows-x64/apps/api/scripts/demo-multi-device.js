import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createServer } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { EventSpool } from "../../agent/src/spool.js";

export async function runMultiDeviceDemo() {
  const db = openDatabase(":memory:");
  const config = loadConfig({ dbPath: ":memory:", sessionSecret: "multi-device-demo-secret-minimum-32-bytes", webRoot: path.resolve("apps/web") });
  const server = createServer(db, config);
  const spoolDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentrygate-multi-agent-"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (pathname, options = {}) => {
    const response = await fetch(`${base}${pathname}`, { headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }, ...options });
    return { status: response.status, body: await response.json(), cookie: response.headers.get("set-cookie")?.split(";")[0] };
  };
  let spool;
  try {
    const setup = await request("/api/setup", { method: "POST", body: JSON.stringify({ email: "demo-owner@sentrygate.test", password: "multi-device-demo-password" }) });
    if (setup.status !== 201) throw new Error(`Isolated demo administrator setup failed (HTTP ${setup.status}: ${setup.body?.error ?? "unknown error"})`);
    const devices = [];
    for (const name of ["Demo Computer A", "Demo Computer B", "Demo Computer C (offline)"]) {
      const enrolled = await request("/api/devices/enroll", { method: "POST", headers: { Cookie: setup.cookie }, body: JSON.stringify({ name, hostname: name.replaceAll(" ", "-"), osVersion: "Simulated Windows 11", agentVersion: "0.3.0" }) });
      if (enrolled.status !== 201) throw new Error(`Could not enroll ${name}`);
      devices.push(enrolled.body);
    }
    const makeEvent = (label) => ({ eventId: randomUUID(), rule: "new_listening_port", title: "Simulated new listening port", reason: `${label}: simulated listener observed in metadata.`, evidence: { endpoint: "127.0.0.1:65000", simulated: true }, timestamp: new Date().toISOString(), severity: "medium", category: "endpoint-detection" });
    const makeReport = (device, events) => ({ device: { deviceId: device.deviceId, hostname: "SIMULATED", osVersion: "Simulated Windows 11", agentVersion: "0.3.0" }, timestamp: new Date().toISOString(), healthStatus: "healthy", collectionErrors: [], backendAddresses: ["127.0.0.1"], processes: [], connections: [], installedApplications: [], services: [], startupEntries: [], securitySettings: { firewallProfiles: [], defenderRealtimeProtection: null }, events });
    const deliver = (device, event) => request(`/api/devices/${device.deviceId}/report`, { method: "POST", headers: { Authorization: `Bearer ${device.credential}` }, body: JSON.stringify(makeReport(device, [event])) });

    const liveA = makeEvent("Computer A"), liveB = makeEvent("Computer B");
    const liveResults = await Promise.all([deliver(devices[0], liveA), deliver(devices[1], liveB)]);
    if (liveResults.some((result) => result.status !== 200)) throw new Error("Live simulated report failed");

    const offlineEvent = makeEvent("Computer C offline buffer");
    const spoolPath = path.join(spoolDir, "events.db");
    spool = new EventSpool(spoolPath, { protect: (value) => `demo:${value}`, unprotect: (value) => value.slice(5) });
    spool.enqueue(offlineEvent);
    const bufferedBeforeReconnect = spool.count();
    spool.close(); spool = new EventSpool(spoolPath, { protect: (value) => `demo:${value}`, unprotect: (value) => value.slice(5) });
    const [restoredEvent] = spool.list(10);
    if (!restoredEvent || restoredEvent.eventId !== offlineEvent.eventId) throw new Error("Offline spool did not restore the queued event");
    const reconnected = await deliver(devices[2], restoredEvent);
    if (reconnected.status !== 200) throw new Error("Buffered simulated report failed after reconnection");
    spool.acknowledge(reconnected.body.acceptedEventIds);
    const duplicate = await deliver(devices[2], offlineEvent);
    if (duplicate.status !== 200) throw new Error("Idempotent retry failed");
    const revoke = await request(`/api/devices/${devices[1].deviceId}/credential/revoke`, { method: "POST", headers: { Cookie: setup.cookie } });
    const revokedReport = await deliver(devices[1], makeEvent("revoked device retry"));
    if (revoke.status !== 200 || revokedReport.status !== 401) throw new Error("Revocation did not deny the old device credential");
    const listing = await request("/api/devices", { headers: { Cookie: setup.cookie } });
    const details = await Promise.all(devices.map((device) => request(`/api/devices/${device.deviceId}`, { headers: { Cookie: setup.cookie } })));
    const eventCounts = devices.map((device) => db.prepare("SELECT COUNT(*) AS count FROM events WHERE device_id=?").get(device.deviceId).count);
    if (details.some((detail) => detail.status !== 200 || detail.body.recentAlerts.length !== 1)) throw new Error("Device detail returned missing or cross-device alerts");
    return {
      enrolledDevices: listing.body.length,
      liveReportsAccepted: liveResults.length,
      offlineEventsBuffered: bufferedBeforeReconnect,
      offlineEventsPendingAfterAck: spool.count(),
      duplicateRetryCreatedNoDuplicate: eventCounts[2] === 1,
      eventCounts,
      revokedDeviceRejected: revokedReport.status === 401,
      health: listing.body.map(({ name, healthStatus, lastHeartbeat, configStatus, policyVersion, openAlertCount }, index) => ({ name, healthStatus, lastHeartbeat, configStatus, policyVersion, openAlertCount, deviceScopedAlerts: details[index].body.recentAlerts.length }))
    };
  } finally {
    spool?.close();
    await new Promise((resolve) => server.close(resolve));
    db.close();
    fs.rmSync(spoolDir, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\//, ""))) {
  runMultiDeviceDemo().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
