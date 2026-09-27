import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import net from "node:net";
import { lookup } from "node:dns/promises";
import { collectWindowsMetadata } from "./windows-collector.js";
import { createDetector } from "./detection.js";
import { EventSpool } from "./spool.js";
import { readProtected, protectText, unprotectText } from "./secure-store.js";
import { reconcileFirewall } from "./windows-firewall.js";

export const agentVersion = "0.3.0";

export async function runAgent({ configPath = process.env.SENTRYGATE_AGENT_CONFIG ?? path.join(os.homedir(), ".sentrygate-agent", "config.json"), once = false, collect = collectWindowsMetadata, spoolFactory } = {}) {
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const credentialPath = path.resolve(path.dirname(configPath), config.credentialFile ?? "credential.dpapi");
  const credential = readProtected(credentialPath, config.dpapiScope ?? "CurrentUser");
  const dataRoot = config.dataRoot ?? path.join(os.homedir(), ".sentrygate-agent");
  const spool = (spoolFactory ?? ((dbPath,limits) => new EventSpool(dbPath, {
    protect: (value) => protectText(value, config.dpapiScope ?? "CurrentUser"),
    unprotect: (value) => unprotectText(value, config.dpapiScope ?? "CurrentUser"),
    maxBytes: limits.maxBytes
  })))(path.join(dataRoot, "events.db"),{maxBytes:config.spoolMaxBytes??268_435_456});
  const detector = createDetector();
  const policyPath = path.join(dataRoot, "firewall-policy.dpapi");
  const policyStore = {
    save(rules) { fs.writeFileSync(policyPath, protectText(JSON.stringify(rules), config.dpapiScope ?? "CurrentUser"), { encoding: "utf8", mode: 0o600 }); },
    load() { try { return JSON.parse(unprotectText(fs.readFileSync(policyPath, "utf8"), config.dpapiScope ?? "CurrentUser")); } catch { return []; } }
  };
  let stopping = false;
  const stop = () => { stopping = true; };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    do {
      await sampleAndReport({ config, credential, spool, detector, collect, policyStore });
      if (!once && !stopping) await new Promise((resolve) => setTimeout(resolve, Math.max(10, config.intervalSeconds ?? 30) * 1000));
    } while (!once && !stopping);
  } finally { spool.close(); }
}

export async function sampleAndReport({ config, credential, spool, detector, collect, now = new Date().toISOString(), fetchImpl = fetch, firewall = reconcileFirewall, policyStore, lookupImpl = lookup }) {
  const deviceId = config.deviceId;
  const apiUrl=new URL(config.apiBaseUrl),apiHost=apiUrl.hostname.replace(/^\[|\]$/g,"");
  if(apiUrl.protocol!=="https:" && !["127.0.0.1","::1","localhost"].includes(apiHost)) throw new Error("Agent API connections require HTTPS except for loopback development");
  let policyOnline = false;
  try {
    const policyResponse = await fetchImpl(`${config.apiBaseUrl.replace(/\/$/, "")}/api/devices/${deviceId}/config`, {
      headers: { Authorization: `Bearer ${credential}` }, signal: AbortSignal.timeout(10000)
    });
    if (policyResponse.ok) {
      const receivedConfig = await policyResponse.json();
      Object.assign(config, receivedConfig);
      policyOnline = true;
      policyStore?.save(config.firewallRules ?? []);
      if (Number.isInteger(receivedConfig.configVersion)) await fetchImpl(`${config.apiBaseUrl.replace(/\/$/, "")}/api/devices/${deviceId}/config/ack`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${credential}` },
        body: JSON.stringify({ version: receivedConfig.configVersion, status: "applied", detail: "Configuration received and stored by the agent." }), signal: AbortSignal.timeout(10000)
      }).catch(() => {});
    }
  } catch { /* Continue with the last locally known collection policy during outages. */ }
  if (!policyOnline && policyStore) config.firewallRules = policyStore.load();
  let firewallResults = [];
  if (firewall && Array.isArray(config.firewallRules)) {
    try { firewallResults = (await firewall(config.firewallRules)).results ?? []; }
    catch (error) { firewallResults = config.firewallRules.map((rule) => ({ id: rule.id, status: "failed", detail: String(error.message ?? "Firewall operation failed").slice(0, 1000), actualState: null })); }
  }
  const [identity, telemetry] = await Promise.all([
    Promise.resolve({ hostname: os.hostname(), osVersion: `${os.type()} ${os.release()}`, agentVersion }),
    collect({ collectProcesses: config.collectProcesses !== false, collectConnections: config.collectConnections !== false })
  ]);
  const processes = telemetry.processes ?? [];
  const connections = telemetry.connections ?? [];
  const collectionErrors = [...(telemetry.collectionErrors ?? [])];
  let backendAddresses = [];
  try {
    const host = new URL(config.apiBaseUrl).hostname.replace(/^\[|\]$/g, "");
    backendAddresses = net.isIP(host) ? [host] : (await lookupImpl(host, { all: true })).map((entry) => entry.address).slice(0, 64);
  } catch { /* Backend address telemetry is best effort; API-side DNS validation also applies. */ }
  spool.pruneBefore(new Date(Date.now() - (config.retainedDays ?? 30) * 86_400_000).toISOString());
  if (!collectionErrors.length) for (const event of detector.inspect({ connections, processes, threshold: config.outboundConnectionThreshold ?? 40, now })) spool.enqueue(event);
  if(spool.storageBytes?.()>=spool.maxBytes || spool.count()>=spool.maxEvents)collectionErrors.push("Local encrypted event spool reached its configured capacity; new detections may not be queued until delivery or retention frees space.");
  const report = { device: { deviceId, ...identity }, timestamp: now, healthStatus: collectionErrors.length ? "degraded" : "healthy", collectionErrors, backendAddresses, processes, connections, events: spool.list(200) };
  try {
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
    return { delivered: true, pending: spool.count() };
  } catch {
    for (const event of detector.reportSendFailure(now)) spool.enqueue(event);
    return { delivered: false, pending: spool.count() };
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runAgent({ once: process.argv.includes("--once") }).catch(() => { console.error("SentryGate agent stopped due to configuration or collection error."); process.exitCode = 1; });
}
