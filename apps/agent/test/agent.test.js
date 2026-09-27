import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createDetector } from "../src/detection.js";
import { EventSpool } from "../src/spool.js";
import { collectWindowsMetadata } from "../src/windows-collector.js";
import { sampleAndReport } from "../src/agent.js";
import { reconcileFirewall } from "../src/windows-firewall.js";

test("detection emits an evidence-backed event for a newly opened listening port only", () => {
  const detector = createDetector();
  const proc = [{ pid: 44, name: "test.exe" }];
  const initial = [{ pid: 44, state: "Listen", localAddress: "0.0.0.0", localPort: 80 }];
  assert.deepEqual(detector.inspect({ connections: initial, processes: proc }), []);
  const next = [...initial, { pid: 44, state: "Listen", localAddress: "0.0.0.0", localPort: 9443 }];
  const events = detector.inspect({ connections: next, processes: proc });
  assert.equal(events[0].rule, "new_listening_port");
  assert.match(events[0].reason, /0\.0\.0\.0:9443/);
  assert.equal(events[0].evidence.endpoint, "0.0.0.0:9443");
});

test("detection reports process outbound volume and repeated failed reports once per outage", () => {
  const detector = createDetector();
  const connections = Array.from({ length: 5 }, (_, i) => ({ pid: 7, state: "Established", remoteAddress: `203.0.113.${i + 1}`, localAddress: "10.0.0.2", localPort: 1000 + i }));
  const outbound = detector.inspect({ connections, processes: [{ pid: 7, name: "worker.exe" }], threshold: 5 });
  assert.equal(outbound[0].rule, "outbound_connection_volume");
  assert.equal(outbound[0].evidence.observedCount, 5);
  assert.deepEqual(detector.reportSendFailure(), []);
  assert.deepEqual(detector.reportSendFailure(), []);
  assert.equal(detector.reportSendFailure()[0].rule, "repeated_agent_failures");
  assert.deepEqual(detector.reportSendFailure(), []);
  detector.reportSendSuccess();
  assert.equal(detector.reportSendFailure().length, 0);
});

test("encrypted event spool retries pending entries, acknowledges IDs, and suppresses enqueue duplicates", () => {
  const prefix = "protected:";
  const spool = new EventSpool(":memory:", { protect: (text) => prefix + Buffer.from(text).toString("base64"), unprotect: (text) => Buffer.from(text.slice(prefix.length), "base64").toString() });
  const event = { eventId: "stable-1", timestamp: new Date().toISOString(), rule: "new_listening_port" };
  spool.enqueue(event); spool.enqueue(event);
  assert.equal(spool.count(), 1);
  assert.deepEqual(spool.list(), [event]);
  spool.acknowledge([event.eventId]);
  assert.equal(spool.count(), 0);
  spool.close();
});

test("Windows collector normalizes mocked process and TCP APIs without collecting private content", async () => {
  const result = await collectWindowsMetadata({ run: async () => ({
    processes: { Pid: 5, ParentPid: 1, Name: "worker.exe", StartedAt: "2026-09-01T00:00:00Z" },
    connections: [{ OwningProcess: 5, State: "Established", LocalAddress: "10.0.0.2", LocalPort: 4000, RemoteAddress: "203.0.113.4", RemotePort: 443 }]
  }) });
  assert.equal(result.processes[0].pid, 5);
  assert.equal(result.connections[0].protocol, "TCP");
  assert.equal("commandLine" in result.processes[0], false);
});

test("agent buffers while backend is unavailable and resends until acknowledged", async () => {
  const spool = new EventSpool(path.join(os.tmpdir(), `sentrygate-agent-${randomUUID()}.db`));
  const detector = createDetector();
  const config = { deviceId: randomUUID(), apiBaseUrl: "http://offline.test", collectProcesses: true, collectConnections: true };
  const collect = async () => ({ processes: [], connections: [] });
  const down = await sampleAndReport({ config, credential: "not-logged", spool, detector, collect, lookupImpl: async () => [], fetchImpl: async () => { throw new Error("offline"); } });
  assert.equal(down.delivered, false);
  detector.reportSendFailure();
  const outageEvent = detector.reportSendFailure()[0];
  spool.enqueue(outageEvent);
  assert.equal(spool.count(), 1);
  const online = await sampleAndReport({ config, credential: "not-logged", spool, detector, collect, fetchImpl: async (url, options) => {
    if (url.endsWith("/config")) return Response.json({ collectProcesses: true, collectConnections: true, retainedDays: 30 });
    const payload = JSON.parse(options.body);
    return Response.json({ acceptedEventIds: payload.events.map((entry) => entry.eventId), settings: {} });
  }, lookupImpl: async () => [] });
  assert.equal(online.delivered, true);
  assert.equal(spool.count(), 0);
  spool.close();
});

test("agent passes approved policies to the mocked firewall adapter and reports exact observed state", async () => {
  const spool = new EventSpool(":memory:");
  const deviceId = randomUUID(), rule = { id: randomUUID(), name: "SentryGate-test", group: "SentryGate", status: "approved", operation: "ensure", remoteAddress: "198.51.100.8/32", protocol: "TCP", localPort: 65000, expiresAt: new Date(Date.now() + 300000).toISOString() };
  const seen = [], config = { deviceId, apiBaseUrl: "http://sentrygate.test", retainedDays: 30 };
  const result = await sampleAndReport({ config, credential: "secret-token", spool, detector: createDetector(), collect: async () => ({ processes: [], connections: [] }), lookupImpl: async () => [{ address: "203.0.113.40" }], policyStore: { save: (rules) => seen.push(["cache", rules]), load: () => [] }, firewall: async (rules) => { seen.push(["apply", rules]); return { results: [{ id: rule.id, status: "active", detail: "Mock firewall confirms owned rule", actualState: { name: rule.name, group: "SentryGate", action: "Block" } }] }; }, fetchImpl: async (url, options = {}) => {
    if (url.endsWith("/config")) return Response.json({ firewallRules: [rule], collectProcesses: false, collectConnections: false });
    if (url.endsWith("/report")) { seen.push(["device-report", JSON.parse(options.body)]); return Response.json({ acceptedEventIds: [], settings: {} }); }
    if (url.endsWith("/firewall/state")) { seen.push(["report", JSON.parse(options.body)]); return Response.json({ accepted: true }); }
    throw new Error(`Unexpected request ${url}`);
  } });
  assert.equal(result.delivered, true);
  assert.deepEqual(seen.map(([kind]) => kind), ["cache", "apply", "device-report", "report"]);
  assert.equal(seen[1][1][0].id, rule.id);
  assert.equal(seen.find(([kind]) => kind === "report")[1].results[0].actualState.group, "SentryGate");
  assert.deepEqual(seen.find(([kind]) => kind === "device-report")[1].backendAddresses, ["203.0.113.40"]);
  spool.close();
});

test("Windows firewall adapter sends structured policy to PowerShell without shell interpolation", async () => {
  const rules = [{ id: randomUUID(), name: "SentryGate-rule", group: "SentryGate", operation: "ensure", remoteAddress: "198.51.100.4/32", protocol: "TCP", localPort: 65000 }];
  let invocation;
  const result = await reconcileFirewall(rules, { run: async (...args) => { invocation = args; return { stdout: JSON.stringify({ results: [{ id: rules[0].id, status: "active", detail: "mocked" }] }) }; } });
  assert.equal(invocation[0], "powershell.exe");
  assert.ok(invocation[1].includes("-File"));
  assert.deepEqual(JSON.parse(invocation[2].input), { rules });
  assert.equal(result.results[0].status, "active");
});
