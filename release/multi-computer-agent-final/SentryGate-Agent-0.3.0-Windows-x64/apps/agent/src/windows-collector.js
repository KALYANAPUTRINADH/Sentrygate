import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

export async function collectWindowsMetadata({ run = runPowerShell, collectProcesses = true, collectConnections = true, collectApplications = true, collectServices = true, collectStartup = true, collectSecurity = true } = {}) {
  if (process.platform !== "win32" && run === runPowerShell) throw new Error("Windows CIM collection is available only on Windows");
  const result = await run({ collectProcesses, collectConnections, collectApplications, collectServices, collectStartup, collectSecurity });
  const data = typeof result === "string" ? JSON.parse(result) : result;
  return {
    processes: collectProcesses ? normalizeList(data.processes, normalizeProcess).slice(0, 10000) : [],
    connections: collectConnections ? normalizeList(data.connections, normalizeConnection).slice(0, 20000) : [],
    installedApplications: collectApplications ? normalizeList(data.installedApplications, normalizeApplication).slice(0, 5000) : [],
    services: collectServices ? normalizeList(data.services, normalizeService).slice(0, 5000) : [],
    startupEntries: collectStartup ? normalizeList(data.startupEntries, normalizeStartup).slice(0, 2000) : [],
    securitySettings: collectSecurity ? normalizeSecurity(data.securitySettings) : { firewallProfiles: [], defenderRealtimeProtection: null, collectionNotes: [] },
    collectionErrors: Array.isArray(data.collectionErrors) ? data.collectionErrors.slice(0, 10).map((error) => String(error).slice(0, 300)) : []
  };
}

async function runPowerShell({ collectProcesses, collectConnections, collectApplications, collectServices, collectStartup, collectSecurity }) {
  const script = fileURLToPath(new URL("../scripts/collect.ps1", import.meta.url));
  const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
    "-CollectProcesses", String(collectProcesses), "-CollectConnections", String(collectConnections), "-CollectApplications", String(collectApplications), "-CollectServices", String(collectServices), "-CollectStartup", String(collectStartup), "-CollectSecurity", String(collectSecurity)], { windowsHide: true, maxBuffer: 12 * 1024 * 1024, timeout: 30000 });
  return stdout;
}

function normalizeList(value, normalize) { return (Array.isArray(value) ? value : value ? [value] : []).map(normalize); }
function normalizeProcess(item) { return { pid: Number(item.pid ?? item.Pid), parentPid: Number(item.parentPid ?? item.ParentPid ?? 0), name: String(item.name ?? item.Name ?? "unknown").slice(0, 260), executablePath: String(item.executablePath ?? item.ExecutablePath ?? "").slice(0, 2048), startedAt: item.startedAt ?? item.StartedAt ?? null }; }
function normalizeConnection(item) { return { pid: Number(item.pid ?? item.Pid ?? item.OwningProcess), protocol: "TCP", state: String(item.state ?? item.State ?? "Unknown").slice(0, 30), localAddress: String(item.localAddress ?? item.LocalAddress ?? ""), localPort: Number(item.localPort ?? item.LocalPort ?? 0), remoteAddress: String(item.remoteAddress ?? item.RemoteAddress ?? ""), remotePort: Number(item.remotePort ?? item.RemotePort ?? 0), timestamp: item.timestamp ?? new Date().toISOString() }; }
function normalizeApplication(item) { return { name: String(item.name ?? item.Name ?? "").slice(0, 260), version: String(item.version ?? item.Version ?? "").slice(0, 100), publisher: String(item.publisher ?? item.Publisher ?? "").slice(0, 260), installLocation: String(item.installLocation ?? item.InstallLocation ?? "").slice(0, 2048), installDate: String(item.installDate ?? item.InstallDate ?? "").slice(0, 20) }; }
function normalizeService(item) { return { name: String(item.name ?? item.Name ?? "").slice(0, 260), displayName: String(item.displayName ?? item.DisplayName ?? "").slice(0, 260), state: String(item.state ?? item.State ?? "Unknown").slice(0, 30), startMode: String(item.startMode ?? item.StartMode ?? "Unknown").slice(0, 30), processId: Number(item.processId ?? item.ProcessId ?? 0) }; }
function normalizeStartup(item) { return { name: String(item.name ?? item.Name ?? "").slice(0, 260), executablePath: String(item.executablePath ?? item.ExecutablePath ?? "").slice(0, 2048), source: String(item.source ?? item.Source ?? "").slice(0, 500) }; }
function normalizeSecurity(value = {}) {
  return { firewallProfiles: normalizeList(value.firewallProfiles, (profile) => ({ name: String(profile.name ?? profile.Name ?? "").slice(0, 30), enabled: profile.enabled === true || profile.Enabled === true } )).slice(0, 10),
    defenderRealtimeProtection: typeof value.defenderRealtimeProtection === "boolean" ? value.defenderRealtimeProtection : null,
    collectionNotes: Array.isArray(value.collectionNotes) ? value.collectionNotes.slice(0, 10).map((note) => String(note).slice(0, 300)) : [] };
}
