import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { collectWindowsMetadata } from "./windows-collector.js";

const execFileAsync = promisify(execFile);

export async function collectHostMetadata(options = {}) {
  if (process.platform === "win32") return collectWindowsMetadata(options);
  if (process.platform === "darwin") return collectMacMetadata(options);
  if (process.platform === "linux") return collectLinuxMetadata(options);
  throw new Error(`SentryGate collection is unsupported on ${process.platform}`);
}

export async function collectMacMetadata({ run = runCommand, collectProcesses = true, collectConnections = true, collectServices = true, collectSecurity = true } = {}) {
  const errors = [];
  const processes = collectProcesses ? await readProcesses(run, "mac", errors) : [];
  let connections = [];
  if (collectConnections) {
    try { connections = parseLsof(await run("/usr/sbin/lsof", ["-nP", "-iTCP", "-iUDP", "-FpcnT"])); }
    catch (error) { errors.push(`Connection metadata unavailable: ${safeError(error)}`); }
  }
  const services = collectServices ? await readMacServices(run, errors) : [];
  const securitySettings = collectSecurity ? await readMacSecurity(run, errors) : { firewallProfiles: [], defenderRealtimeProtection: null };
  return { processes, connections, installedApplications: [], services, startupEntries: [], securitySettings: { ...securitySettings, platformName: "macOS" },
    collectionErrors: errors, collectionNotes: ["macOS installed-application inventory and login-item inventory are not collected in this release."] };
}

export async function collectLinuxMetadata({ run = runCommand, collectProcesses = true, collectConnections = true, collectServices = true, collectSecurity = true } = {}) {
  const errors = [];
  const processes = collectProcesses ? await readProcesses(run, "linux", errors) : [];
  let connections = [];
  if (collectConnections) {
    try { connections = parseSs(await run("ss", ["-H", "-tunap"])); }
    catch (error) { errors.push(`Connection metadata unavailable: ${safeError(error)}`); }
  }
  const services = collectServices ? await readLinuxServices(run, errors) : [];
  const securitySettings = collectSecurity ? await readLinuxSecurity(run, errors) : { firewallProfiles: [], defenderRealtimeProtection: null };
  return { processes, connections, installedApplications: [], services, startupEntries: [], securitySettings: { ...securitySettings, platformName: "Linux" },
    collectionErrors: errors, collectionNotes: ["Installed-application and startup-entry inventories are not collected in this release."] };
}

export function parsePs(text) {
  return String(text).split(/\r?\n/).filter(Boolean).map((line) => {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+(.{24})\s+(.+)$/);
    if (!match) return null;
    return { pid: Number(match[1]), parentPid: Number(match[2]), startedAt: match[3].trim(), name: match[4].trim().split(/[\\/]/).pop().slice(0, 260), executablePath: "" };
  }).filter(Boolean).slice(0, 10000);
}

export function parseSs(text, timestamp = new Date().toISOString()) {
  const output = [];
  for (const line of String(text).split(/\r?\n/).filter(Boolean)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 6) continue;
    const protocol = fields[0].toUpperCase();
    if (!["TCP", "UDP", "TCP6", "UDP6"].includes(protocol)) continue;
    const processMatch = fields.slice(6).join(" ").match(/pid=(\d+)/);
    const local = parseEndpoint(fields[4]), remote = fields[5].includes("*") ? null : parseEndpoint(fields[5]);
    if (!local) continue;
    const rawState = fields[1].toUpperCase();
    const state = rawState === "LISTEN" || protocol.startsWith("UDP") && rawState === "UNCONN" ? "Listen" : ["ESTAB", "ESTABLISHED"].includes(rawState) ? "Established" : rawState;
    output.push({ pid: processMatch ? Number(processMatch[1]) : 0, protocol: protocol.startsWith("UDP") ? "UDP" : "TCP", state, localAddress: local.address, localPort: local.port,
      remoteAddress: remote?.address ?? "", remotePort: remote?.port ?? 0, timestamp });
  }
  return output.slice(0, 20000);
}

export function parseLsof(text, timestamp = new Date().toISOString()) {
  const output = [];
  let record = {};
  const flush = () => {
    const value = record;
    if (!value.name) return;
    const [localText, remoteText] = value.name.split("->");
    const local = parseEndpoint(localText), remote = remoteText ? parseEndpoint(remoteText) : null;
    if (!local) return;
    const udp = /UDP/i.test(value.type ?? "");
    const rawState = value.state ?? (remote ? "ESTABLISHED" : "LISTEN");
    const state = rawState === "LISTEN" ? "Listen" : ["ESTAB", "ESTABLISHED"].includes(rawState) ? "Established" : rawState;
    output.push({ pid: Number(value.pid ?? 0), protocol: udp ? "UDP" : "TCP", state, localAddress: local.address, localPort: local.port,
      remoteAddress: remote?.address ?? "", remotePort: remote?.port ?? 0, timestamp });
  };
  for (const line of String(text).split(/\r?\n/)) {
    if (line.startsWith("p")) { flush(); record = { pid: line.slice(1) }; }
    else if (line.startsWith("c")) record.command = line.slice(1);
    else if (line.startsWith("n")) record.name = line.slice(1);
    else if (line.startsWith("TST=")) record.state = line.slice(4).toUpperCase();
    else if (line.startsWith("t")) record.type = line.slice(1);
  }
  flush();
  return output.slice(0, 20000);
}

async function readProcesses(run, platform, errors) {
  try {
    const command = platform === "mac" ? "/bin/ps" : "ps";
    const args = platform === "mac" ? ["-axo", "pid=,ppid=,lstart=,comm="] : ["-eo", "pid=,ppid=,lstart=,comm="];
    return parsePs(await run(command, args));
  } catch (error) { errors.push(`Process metadata unavailable: ${safeError(error)}`); return []; }
}
async function readMacServices(run, errors) {
  try { return parseLaunchctl(await run("/bin/launchctl", ["list"])); }
  catch (error) { errors.push(`Service metadata unavailable: ${safeError(error)}`); return []; }
}
async function readLinuxServices(run, errors) {
  try { return parseSystemd(await run("systemctl", ["list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"])); }
  catch (error) { errors.push(`Service metadata unavailable: ${safeError(error)}`); return []; }
}
async function readMacSecurity(run, errors) {
  try { const result = await run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]); return { firewallProfiles: [{ name: "macOS Application Firewall", enabled: /enabled/i.test(result) }], defenderRealtimeProtection: null }; }
  catch (error) { errors.push(`Firewall status unavailable: ${safeError(error)}`); return { firewallProfiles: [], defenderRealtimeProtection: null }; }
}
async function readLinuxSecurity(run, errors) {
  const profiles = [];
  for (const [name, command, args] of [["nftables", "systemctl", ["is-active", "nftables"]], ["ufw", "ufw", ["status"]], ["firewalld", "systemctl", ["is-active", "firewalld"]]]) {
    try { const result = await run(command, args); profiles.push({ name, enabled: name === "ufw" ? /^Status:\s*active/im.test(result) : /^active\s*$/im.test(result) }); }
    catch (error) { if (error.code !== "ENOENT" && error.code !== 1) errors.push(`${name} status unavailable: ${safeError(error)}`); }
  }
  return { firewallProfiles: profiles, defenderRealtimeProtection: null };
}
function parseLaunchctl(text) { return String(text).split(/\r?\n/).slice(1).filter(Boolean).slice(0, 5000).map((line) => { const parts = line.trim().split(/\s+/, 3); return { name: parts[2] ?? "unknown", displayName: parts[2] ?? "unknown", state: parts[0] === "-" ? "unknown" : "running", startMode: "launchd", processId: Number(parts[0]) || 0 }; }); }
function parseSystemd(text) { return String(text).split(/\r?\n/).filter(Boolean).slice(0, 5000).map((line) => { const parts = line.trim().split(/\s+/); return { name: parts[0], displayName: parts.slice(4).join(" ").slice(0, 260), state: "running", startMode: "systemd", processId: 0 }; }); }
function parseEndpoint(value) {
  const match = String(value ?? "").match(/^(.+):(\d+|\*)$/);
  if (!match) return null;
  let address = match[1].replace(/^\[|\]$/g, "");
  if (address === "*" || address === "*") address = "0.0.0.0";
  return { address, port: match[2] === "*" ? 0 : Number(match[2]) };
}
async function runCommand(command, args) {
  const { stdout } = await execFileAsync(command, args, { encoding: "utf8", timeout: 15000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
  return stdout;
}
function safeError(error) { return String(error?.code ?? error?.message ?? "command failed").slice(0, 120); }

export function hostIdentity() { return { hostname: os.hostname(), osVersion: `${os.type()} ${os.release()}` }; }
