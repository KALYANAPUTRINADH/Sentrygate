import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID, createHmac } from "node:crypto";
import test from "node:test";
import { createDetector } from "../src/detection.js";
import { EventSpool } from "../src/spool.js";
import { collectWindowsMetadata } from "../src/windows-collector.js";
import { acceptApplicationPolicyCommand, isPrivateEndpointAddress, parseAgentCliArgs, sampleAndReport } from "../src/agent.js";
import { reconcileFirewall } from "../src/windows-firewall.js";

test("Windows service CLI passes its protected config path into the agent", () => {
  assert.deepEqual(parseAgentCliArgs(["C:\\ProgramData\\SentryGate\\Agent\\config.json"]), { configPath: "C:\\ProgramData\\SentryGate\\Agent\\config.json", once: false });
  assert.deepEqual(parseAgentCliArgs(["C:\\ProgramData\\SentryGate\\Agent\\config.json", "--once"]), { configPath: "C:\\ProgramData\\SentryGate\\Agent\\config.json", once: true });
  assert.deepEqual(parseAgentCliArgs(["--once"]), { once: true });
});

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

test("detects startup additions and disabled protections from observed metadata", () => {
  const detector = createDetector();
  const base = { connections: [], processes: [], startupEntries: [{ name: "Approved", executablePath: "C:\\Safe\\ok.exe", source: "Run" }], securitySettings: { firewallProfiles: [{ name: "Domain", enabled: true }], defenderRealtimeProtection: true } };
  assert.deepEqual(detector.inspect(base), []);
  const changed = detector.inspect({ ...base, startupEntries: [...base.startupEntries, { name: "NewEntry", executablePath: "C:\\Temp\\new.exe", source: "Run" }], securitySettings: { firewallProfiles: [{ name: "Domain", enabled: false }], defenderRealtimeProtection: false } });
  assert.deepEqual(changed.map((event) => event.rule).sort(), ["new_startup_entry", "security_protection_disabled"]);
  assert.match(changed[0].reason + changed[1].reason, /disabled|startup entry/i);
  const serviceDetector = createDetector();
  assert.deepEqual(serviceDetector.inspect({ connections: [], processes: [], services: [{ name: "WinDefend", state: "Running", startMode: "Auto" }] }), []);
  const serviceAlert = serviceDetector.inspect({ connections: [], processes: [], services: [{ name: "WinDefend", state: "Stopped", startMode: "Disabled" }] });
  assert.equal(serviceAlert[0].rule, "security_protection_disabled");
  assert.match(serviceAlert[0].reason, /WinDefend reports Stopped\/Disabled/);
});

test("listener and startup baselines survive an agent restart without repeating unchanged alerts", () => {
  let saved;
  const initial = { connections: [{ pid: 22, state: "Listen", localAddress: "0.0.0.0", localPort: 443 }], processes: [{ pid: 22, name: "web.exe" }], startupEntries: [{ name: "Approved", executablePath: "C:\\Safe\\app.exe", source: "Run" }], securitySettings: { firewallProfiles: [{ name: "Domain", enabled: true }], defenderRealtimeProtection: true } };
  createDetector({ onState: (value) => { saved = value; } }).inspect(initial);
  const restarted = createDetector({ initialState: saved });
  assert.deepEqual(restarted.inspect(initial), []);
  const changed = restarted.inspect({ ...initial, connections: [...initial.connections, { pid: 22, state: "Listen", localAddress: "0.0.0.0", localPort: 8443 }], startupEntries: [...initial.startupEntries, { name: "Unexpected", executablePath: "C:\\Temp\\app.exe", source: "Run" }] });
  assert.deepEqual(changed.map((event) => event.rule).sort(), ["new_listening_port", "new_startup_entry"]);
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

test("agent event spool enforces a bounded queue without losing idempotent retries",()=>{
  const spool=new EventSpool(":memory:",{maxEvents:1,maxBytes:1024*1024});
  const first={eventId:"capacity-1",timestamp:new Date().toISOString()},second={eventId:"capacity-2",timestamp:new Date().toISOString()};
  assert.equal(spool.enqueue(first),true);
  assert.equal(spool.enqueue(first),true);
  assert.equal(spool.enqueue(second),false);
  assert.equal(spool.count(),1);
  spool.acknowledge([first.eventId]);
  assert.equal(spool.enqueue(second),true);
  spool.close();
});

test("Windows collector normalizes mocked process and TCP APIs without collecting private content", async () => {
  const result = await collectWindowsMetadata({ run: async () => ({
    processes: { Pid: 5, ParentPid: 1, Name: "worker.exe", ExecutablePath: "C:\\Program Files\\worker.exe", StartedAt: "2026-09-01T00:00:00Z" },
    connections: [{ OwningProcess: 5, State: "Established", LocalAddress: "10.0.0.2", LocalPort: 4000, RemoteAddress: "203.0.113.4", RemotePort: 443 }],
    installedApplications: [{ Name: "Worker", DisplayVersion: "1.2" }], services: [{ Name: "WorkerService", State: "Running" }],
    startupEntries: [{ Name: "Worker", ExecutablePath: "C:\\Program Files\\worker.exe" }], securitySettings: { defenderRealtimeProtection: true, firewallProfiles: [{ Name: "Domain", Enabled: true }] }
  }) });
  assert.equal(result.processes[0].pid, 5);
  assert.equal(result.connections[0].protocol, "TCP");
  assert.equal(result.processes[0].executablePath, "C:\\Program Files\\worker.exe");
  assert.equal(result.installedApplications[0].name, "Worker");
  assert.equal(result.services[0].state, "Running");
  assert.equal(result.startupEntries[0].name, "Worker");
  assert.equal(result.securitySettings.firewallProfiles[0].enabled, true);
  assert.equal("commandLine" in result.processes[0], false);
});

test("authenticated application commands reject expired and replayed nonces", () => {
  const store = { value: { nonces: [], policies: [] }, load() { return this.value; }, save(value) { this.value = value; } };
  const now = Date.now(), command = { nonce: randomUUID(), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), policies: [{ id: randomUUID(), name: "SentryGate-App-test", group: "SentryGate", kind: "application", operation: "ensure", action: "Block", programPath: "C:\\app.exe", expiresAt: new Date(now + 120_000).toISOString() }] };
  assert.equal(acceptApplicationPolicyCommand(command, store, now).accepted, true);
  assert.equal(acceptApplicationPolicyCommand(command, store, now).accepted, false);
  assert.equal(acceptApplicationPolicyCommand({ ...command, nonce: randomUUID() }, store, now + 120_000).accepted, false);
});

test("firewall helper request is HMAC authenticated and rejects missing credentials", async () => {
  const rules = [{ id: randomUUID(), name: "SentryGate-App-test", group: "SentryGate", kind: "application", operation: "ensure", programPath: "C:\\app.exe", action: "Block", expiresAt: new Date(Date.now() + 60_000).toISOString() }];
  const key = Buffer.from("0123456789abcdef0123456789abcdef");
  let envelope;
  const result = await reconcileFirewall(rules, { helperKey: key, connect: async (message) => {
    envelope = JSON.parse(message); const payload = Buffer.from(envelope.payload, "base64");
    assert.equal(createHmac("sha256", key).update(payload).digest("base64"), envelope.signature);
    return JSON.stringify({ results: [{ id: rules[0].id, status: "active", detail: "mocked" }] });
  } });
  assert.equal(result.results[0].status, "active");
  assert.ok(envelope.payload);
  await assert.rejects(() => reconcileFirewall(rules, { helperKey: "short", connect: async () => "{}" }), /not installed/);
});

test("agent keeps metadata reporting available when the helper is offline and uses unexpired cached policy only", async () => {
  const spool = new EventSpool(":memory:"), policy = { id: randomUUID(), group: "SentryGate", kind: "application", operation: "ensure", action: "Block", programPath: "C:\\app.exe", expiresAt: new Date(Date.now() + 60_000).toISOString() };
  const seen = []; const config = { deviceId: randomUUID(), apiBaseUrl: "https://offline-helper.test", retainedDays: 30 };
  const result = await sampleAndReport({ config, credential: "credential", spool, detector: createDetector(), commandStore: { load: () => ({ policies: [policy] }) }, firewall: async (rules) => { seen.push(rules); return { results: [] }; }, collect: async () => ({ processes: [], connections: [] }), lookupImpl: async () => [{address:"127.0.0.1"}], fetchImpl: async (url, options = {}) => {
    if (url.endsWith("/config")) throw new Error("backend offline");
    if (url.endsWith("/report")) return Response.json({ acceptedEventIds: [], settings: {} });
    throw new Error(`Unexpected ${url}`);
  } });
  assert.equal(result.delivered, true);
  assert.equal(seen[0][0].id, policy.id);
  spool.close();
});

test("agent buffers while backend is unavailable and resends until acknowledged", async () => {
  const spool = new EventSpool(path.join(os.tmpdir(), `sentrygate-agent-${randomUUID()}.db`));
  const detector = createDetector();
  const config = { deviceId: randomUUID(), apiBaseUrl: "https://offline.test", collectProcesses: true, collectConnections: true };
  const collect = async () => ({ processes: [], connections: [] });
  const down = await sampleAndReport({ config, credential: "not-logged", spool, detector, collect, lookupImpl: async () => [{address:"127.0.0.1"}], fetchImpl: async () => { throw new Error("offline"); } });
  assert.equal(down.delivered, false);
  detector.reportSendFailure();
  const outageEvent = detector.reportSendFailure()[0];
  spool.enqueue(outageEvent);
  assert.equal(spool.count(), 1);
  const online = await sampleAndReport({ config, credential: "not-logged", spool, detector, collect, fetchImpl: async (url, options) => {
    if (url.endsWith("/config")) return Response.json({ collectProcesses: true, collectConnections: true, retainedDays: 30 });
    const payload = JSON.parse(options.body);
    return Response.json({ acceptedEventIds: payload.events.map((entry) => entry.eventId), settings: {} });
  }, lookupImpl: async () => [{address:"127.0.0.1"}] });
  assert.equal(online.delivered, true);
  assert.equal(spool.count(), 0);
  spool.close();
});

test("agent refuses remote cleartext APIs and preserves normal TLS certificate failures",async()=>{
  const spool=new EventSpool(":memory:"),base={deviceId:randomUUID(),apiBaseUrl:"http://api.example.invalid",retainedDays:30};
  await assert.rejects(()=>sampleAndReport({config:base,credential:"credential",spool,detector:createDetector(),collect:async()=>({processes:[],connections:[]})}),/require HTTPS/);
  const config={...base,apiBaseUrl:"https://api.example.invalid"};
  const result=await sampleAndReport({config,credential:"credential",spool,detector:createDetector(),collect:async()=>({processes:[],connections:[]}),lookupImpl:async()=>[{address:"127.0.0.1"}],fetchImpl:async()=>{throw new TypeError("self-signed certificate");}});
  assert.equal(result.delivered,false);
  spool.close();
});

test("agent rejects unresolved or public backend destinations before any network request",async()=>{
  assert.equal(isPrivateEndpointAddress("10.12.0.8"),true);
  assert.equal(isPrivateEndpointAddress("fd12::8"),true);
  assert.equal(isPrivateEndpointAddress("8.8.8.8"),false);
  const spool=new EventSpool(":memory:"),calls=[];
  const result=await sampleAndReport({config:{deviceId:randomUUID(),apiBaseUrl:"https://collector.example.test",retainedDays:30},credential:"credential",spool,detector:createDetector(),collect:async()=>({processes:[],connections:[]}),lookupImpl:async()=>[{address:"8.8.8.8"}],fetchImpl:async(...args)=>{calls.push(args);throw new Error("must not send");}});
  assert.equal(result.delivered,false);
  assert.equal(calls.length,0);
  const liveSpool=new EventSpool(":memory:");
  const offline=await sampleAndReport({config:{deviceId:randomUUID(),apiBaseUrl:"https://collector.example.test",retainedDays:30},credential:"credential",spool:liveSpool,detector:createDetector(),collect:async()=>({processes:[],connections:[]}),lookupImpl:async()=>[{address:"8.8.8.8"}]});
  assert.equal(offline.delivered,false);
  liveSpool.close();spool.close();
});

test("agent passes approved policies to the mocked firewall adapter and reports exact observed state", async () => {
  const spool = new EventSpool(":memory:");
  const deviceId = randomUUID(), rule = { id: randomUUID(), name: "SentryGate-test", group: "SentryGate", status: "approved", operation: "ensure", remoteAddress: "198.51.100.8/32", protocol: "TCP", localPort: 65000, expiresAt: new Date(Date.now() + 300000).toISOString() };
  const seen = [], config = { deviceId, apiBaseUrl: "https://sentrygate.test", retainedDays: 30 };
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

test("Windows service installer enables automatic startup and restart recovery without elevating the monitor",()=>{
  const installer=fs.readFileSync("apps/agent/scripts/install-agent.ps1","utf8");
  const host=fs.readFileSync("apps/agent/scripts/service-host.cs","utf8");
  assert.match(installer,/StartupType Automatic/);
  assert.match(installer,/sc\.exe failure SentryGateAgent reset= 86400 actions= restart\/5000\/restart\/15000\/restart\/60000/);
  assert.match(installer,/NT AUTHORITY\\LocalService/);
  assert.match(host,/BackendReady\(api\)/);
  assert.match(host,/api\/health/);
  assert.match(host,/service\.log/);
  assert.match(host,/Environment\.Exit\(code == 0 \? 1 : code\)/);
  assert.match(installer,/apiUri\.Scheme -ne 'http'/);
  assert.match(installer,/Preserving existing DPAPI-protected enrollment/);
  assert.match(installer,/packages\\shared/);
});
