import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import net from "node:net";
import { lookup } from "node:dns/promises";
import { collectHostMetadata } from "./platform-collector.js";
import { createDetector } from "./detection.js";
import { EventSpool } from "./spool.js";
import { readProtected, protectText, unprotectText } from "./secure-store.js";
import { reconcilePlatformFirewall } from "./platform-firewall.js";
import { isLocalAddress } from "../../../packages/shared/network-policy.js";

export const agentVersion = "0.3.0";

export async function runAgent({ configPath = process.env.SENTRYGATE_AGENT_CONFIG ?? path.join(os.homedir(), ".sentrygate-agent", "config.json"), once = false, collect = collectHostMetadata, spoolFactory } = {}) {
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const dataRoot = config.dataRoot ?? path.join(os.homedir(), ".sentrygate-agent");
  fs.mkdirSync(dataRoot, { recursive: true, mode: 0o700 });
  const localKeyPath = config.localKeyPath ?? path.join(dataRoot, "local.key");
  const credentialPath = path.resolve(path.dirname(configPath), config.credentialFile ?? "credential.dpapi");
  const credential = readProtected(credentialPath, config.dpapiScope ?? "CurrentUser", localKeyPath);
  const spool = (spoolFactory ?? ((dbPath,limits) => new EventSpool(dbPath, {
    protect: (value) => protectText(value, config.dpapiScope ?? "CurrentUser", localKeyPath),
    unprotect: (value) => unprotectText(value, config.dpapiScope ?? "CurrentUser", localKeyPath),
    maxBytes: limits.maxBytes
  })))(path.join(dataRoot, "events.db"),{maxBytes:config.spoolMaxBytes??268_435_456});
  const baselinePath = path.join(dataRoot, "host-baseline.dpapi");
  let detectorBaseline = null;
  try { detectorBaseline = JSON.parse(unprotectText(fs.readFileSync(baselinePath, "utf8"), config.dpapiScope ?? "CurrentUser", localKeyPath)); } catch { /* First run or unavailable baseline starts a fresh observation window. */ }
  const detector = createDetector({ initialState: detectorBaseline, onState: (value) => {
    try { fs.writeFileSync(baselinePath, protectText(JSON.stringify(value), config.dpapiScope ?? "CurrentUser", localKeyPath), { encoding: "utf8", mode: 0o600 }); } catch { /* Keep the monitor alive when protected local storage is unavailable. */ }
  } });
  const policyPath = path.join(dataRoot, "firewall-policy.dpapi");
  const policyStore = {
    save(rules) { fs.writeFileSync(policyPath, protectText(JSON.stringify(rules), config.dpapiScope ?? "CurrentUser", localKeyPath), { encoding: "utf8", mode: 0o600 }); },
    load() { try { return JSON.parse(unprotectText(fs.readFileSync(policyPath, "utf8"), config.dpapiScope ?? "CurrentUser", localKeyPath)); } catch { return []; } }
  };
  const commandPath = path.join(dataRoot, "application-policy.dpapi");
  const commandStore = {
    load() { try { return JSON.parse(unprotectText(fs.readFileSync(commandPath, "utf8"), config.dpapiScope ?? "CurrentUser", localKeyPath)); } catch { return { nonces: [], policies: [] }; } },
    save(value) { fs.writeFileSync(commandPath, protectText(JSON.stringify(value), config.dpapiScope ?? "CurrentUser", localKeyPath), { encoding: "utf8", mode: 0o600 }); }
  };
  const helperKeyPath = path.resolve(path.dirname(configPath), config.firewallHelperKeyFile ?? "firewall-helper.key.dpapi");
  let helperKey = "";
  if (fs.existsSync(helperKeyPath) && process.platform === "win32") try { helperKey = Buffer.from(readProtected(helperKeyPath, "LocalMachine", localKeyPath), "base64"); } catch { /* Missing helper key keeps enforcement unavailable. */ }
  let stopping = false;
  const stop = () => { stopping = true; };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    do {
      await sampleAndReport({ config, credential, spool, detector, collect, policyStore, commandStore, helperKey });
      if (!once && !stopping) await new Promise((resolve) => setTimeout(resolve, Math.max(10, config.intervalSeconds ?? 30) * 1000));
    } while (!once && !stopping);
  } finally { spool.close(); }
}

export async function sampleAndReport({ config, credential, spool, detector, collect, now = new Date().toISOString(), fetchImpl = fetch, firewall = reconcilePlatformFirewall, policyStore, commandStore, helperKey = "", lookupImpl = lookup }) {
  const deviceId = config.deviceId;
  const apiUrl=new URL(config.apiBaseUrl),apiHost=apiUrl.hostname.replace(/^\[|\]$/g,"");
  if(apiUrl.protocol!=="https:" && !["127.0.0.1","::1","localhost"].includes(apiHost)) throw new Error("Agent API connections require HTTPS except for loopback development");
  let backendAddresses=[];
  try { backendAddresses=net.isIP(apiHost)?[apiHost]:(await lookupImpl(apiHost,{all:true})).map((entry)=>entry.address).slice(0,64); } catch { /* An unavailable resolver means the backend is offline. */ }
  const backendEligible=backendAddresses.length>0&&backendAddresses.every(isPrivateEndpointAddress);
  if(!backendEligible) config.backendOfflineReason="Configured backend did not resolve exclusively to loopback or private/link-local addresses.";
  let policyOnline = false;
  let applicationPolicies = [];
  let commandAckNonce = null;
  let commandFailure = "";
  try {
    if(!backendEligible) throw new Error(config.backendOfflineReason);
    const policyResponse = await fetchImpl(`${config.apiBaseUrl.replace(/\/$/, "")}/api/devices/${deviceId}/config`, {
      headers: { Authorization: `Bearer ${credential}` }, signal: AbortSignal.timeout(10000)
    });
    if (policyResponse.ok) {
      const receivedConfig = await policyResponse.json();
      Object.assign(config, receivedConfig);
      policyOnline = true;
      policyStore?.save(config.firewallRules ?? []);
      if (receivedConfig.applicationPolicyCommand) {
        const accepted = acceptApplicationPolicyCommand(receivedConfig.applicationPolicyCommand, commandStore, Date.parse(now));
        if (accepted.accepted) { applicationPolicies = accepted.policies; commandAckNonce = accepted.nonce; }
        else commandFailure = accepted.reason;
      }
      if (Number.isInteger(receivedConfig.configVersion)) await fetchImpl(`${config.apiBaseUrl.replace(/\/$/, "")}/api/devices/${deviceId}/config/ack`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${credential}` },
        body: JSON.stringify({ version: receivedConfig.configVersion, status: "applied", detail: "Configuration received and stored by the agent." }), signal: AbortSignal.timeout(10000)
      }).catch(() => {});
    }
  } catch { /* Continue with the last locally known collection policy during outages. */ }
  if (!policyOnline && policyStore) config.firewallRules = policyStore.load();
  if (!policyOnline && commandStore) applicationPolicies = commandStore.load().policies.filter((policy) => policy.operation === "remove" || Date.parse(policy.expiresAt) > Date.now());
  let firewallResults = [];
  const firewallCommands = [...(Array.isArray(config.firewallRules) ? config.firewallRules.map((rule) => ({ ...rule, kind: "inbound" })) : []), ...applicationPolicies];
  if (firewall && firewallCommands.length) {
    try { firewallResults = (await firewall(firewallCommands, { helperKey })).results ?? []; }
    catch (error) { firewallResults = firewallCommands.map((rule) => ({ id: rule.id, status: "failed", detail: String(error.message ?? "Firewall operation failed").slice(0, 1000), actualState: null })); }
  }
  const [identity, telemetry] = await Promise.all([
    Promise.resolve({ hostname: os.hostname(), osVersion: `${os.type()} ${os.release()}`, agentVersion }),
    collect({ collectProcesses: config.collectProcesses !== false, collectConnections: config.collectConnections !== false, collectApplications: config.collectApplications !== false, collectServices: config.collectServices !== false, collectStartup: config.collectStartup !== false, collectSecurity: config.collectSecurity !== false })
  ]);
  const processes = telemetry.processes ?? [];
  const connections = telemetry.connections ?? [];
  const collectionErrors = [...(telemetry.collectionErrors ?? [])];
  if (commandFailure) collectionErrors.push(commandFailure);
  if (collectionErrors.length) console.error(JSON.stringify({ timestamp: now, event: "collector.errors", details: collectionErrors }));
  spool.pruneBefore(new Date(Date.now() - (config.retainedDays ?? 30) * 86_400_000).toISOString());
  if (!collectionErrors.length) for (const event of detector.inspect({ connections, processes, startupEntries: telemetry.startupEntries ?? [], services: telemetry.services ?? [], securitySettings: telemetry.securitySettings ?? {}, threshold: config.outboundConnectionThreshold ?? 40, now })) spool.enqueue(event);
  if(spool.storageBytes?.()>=spool.maxBytes || spool.count()>=spool.maxEvents)collectionErrors.push("Local encrypted event spool reached its configured capacity; new detections may not be queued until delivery or retention frees space.");
  const report = { device: { deviceId, ...identity }, timestamp: now, healthStatus: collectionErrors.length ? "degraded" : "healthy", collectionErrors, backendAddresses, processes, connections,
    installedApplications: telemetry.installedApplications ?? [], services: telemetry.services ?? [], startupEntries: telemetry.startupEntries ?? [], securitySettings: telemetry.securitySettings ?? {},
    ...(commandAckNonce ? { commandAckNonce } : {}), events: spool.list(200) };
  try {
    if(!backendEligible) throw new Error(config.backendOfflineReason);
    const response = await fetchImpl(`${config.apiBaseUrl.replace(/\/$/, "")}/api/devices/${deviceId}/report`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${credential}` }, body: JSON.stringify(report), signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) throw new Error(`Device report rejected (${response.status})`);
    const result = await response.json();
    spool.acknowledge(result.acceptedEventIds ?? []);
    Object.assign(config, result.settings ?? {});
    detector.reportSendSuccess();
    if (firewallResults.length) await fetchImpl(`${config.apiBaseUrl.replace(/\/$/, "")}/api/devices/${deviceId}/firewall/state`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${credential}` }, body: JSON.stringify({ results: firewallResults }), signal: AbortSignal.timeout(10000)
    }).catch(() => {});
    const applicationResults = firewallResults.filter((result) => applicationPolicies.some((policy) => policy.id === result.id));
    if (applicationResults.length) await fetchImpl(`${config.apiBaseUrl.replace(/\/$/, "")}/api/devices/${deviceId}/application-policy-state`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${credential}` }, body: JSON.stringify({ results: applicationResults }), signal: AbortSignal.timeout(10000)
    }).catch(() => {});
    return { delivered: true, pending: spool.count() };
  } catch {
    for (const event of detector.reportSendFailure(now)) spool.enqueue(event);
    return { delivered: false, pending: spool.count() };
  }
}

export function isPrivateEndpointAddress(address) {
  return isLocalAddress(address);
}

export function acceptApplicationPolicyCommand(command, store, now = Date.now()) {
  if (!command || typeof command.nonce !== "string" || !/^[a-f0-9-]{36}$/i.test(command.nonce) || !Array.isArray(command.policies) || command.policies.length > 100) return { accepted: false, policies: [], reason: "Application policy command failed validation." };
  const issued = Date.parse(command.issuedAt), expires = Date.parse(command.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + 15_000 || issued < now - 120_000 || expires <= now || expires > issued + 120_000) return { accepted: false, policies: [], reason: "Expired application policy command was rejected." };
  const state = store?.load?.() ?? { nonces: [], policies: [] };
  if ((state.nonces ?? []).includes(command.nonce)) return { accepted: false, policies: [], reason: "Replayed application policy command was rejected." };
  const policies = command.policies.filter((policy) => policy && typeof policy.id === "string" && policy.group === "SentryGate" && policy.kind === "application" && ["ensure", "remove"].includes(policy.operation) && ["Allow", "Block"].includes(policy.action) && typeof policy.programPath === "string" && Number.isFinite(Date.parse(policy.expiresAt)));
  if (policies.length !== command.policies.length) return { accepted: false, policies: [], reason: "Application policy command contained invalid rule data." };
  store?.save?.({ nonces: [...(state.nonces ?? []), command.nonce].slice(-128), policies });
  return { accepted: true, nonce: command.nonce, policies };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runAgent({ once: process.argv.includes("--once") }).catch(() => { console.error("SentryGate agent stopped due to configuration or collection error."); process.exitCode = 1; });
}
