import assert from "node:assert/strict";
import test from "node:test";
import { runMultiDeviceDemo } from "../scripts/demo-multi-device.js";

test("three-device simulation isolates reports, persists offline spool, deduplicates reconnect, and revokes credentials", async () => {
  const result = await runMultiDeviceDemo();
  assert.equal(result.enrolledDevices, 3);
  assert.equal(result.liveReportsAccepted, 2);
  assert.equal(result.offlineEventsBuffered, 1);
  assert.equal(result.offlineEventsPendingAfterAck, 0);
  assert.equal(result.duplicateRetryCreatedNoDuplicate, true);
  assert.deepEqual(result.eventCounts, [1, 1, 1]);
  assert.equal(result.revokedDeviceRejected, true);
  assert.ok(result.health[0].lastHeartbeat);
  assert.equal(result.health[1].healthStatus, "revoked");
  assert.equal(result.health[0].policyVersion, 1);
  assert.equal(result.health[0].openAlertCount, 1);
  assert.equal(result.health[1].openAlertCount, 1);
  assert.deepEqual(result.health.map((device) => device.deviceScopedAlerts), [1, 1, 1]);
});
