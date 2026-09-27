import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

export async function collectWindowsMetadata({ run = runPowerShell, collectProcesses = true, collectConnections = true } = {}) {
  if (process.platform !== "win32" && run === runPowerShell) throw new Error("Windows CIM collection is available only on Windows");
  const result = await run({ collectProcesses, collectConnections });
  const data = typeof result === "string" ? JSON.parse(result) : result;
  return {
    processes: collectProcesses ? normalizeList(data.processes, normalizeProcess).slice(0, 10000) : [],
    connections: collectConnections ? normalizeList(data.connections, normalizeConnection).slice(0, 20000) : [],
    collectionErrors: Array.isArray(data.collectionErrors) ? data.collectionErrors.slice(0, 10).map((error) => String(error).slice(0, 300)) : []
  };
}

async function runPowerShell({ collectProcesses, collectConnections }) {
  const script = fileURLToPath(new URL("../scripts/collect.ps1", import.meta.url));
  const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
    "-CollectProcesses", String(collectProcesses), "-CollectConnections", String(collectConnections)], { windowsHide: true, maxBuffer: 12 * 1024 * 1024, timeout: 30000 });
  return stdout;
}

function normalizeList(value, normalize) { return (Array.isArray(value) ? value : value ? [value] : []).map(normalize); }
function normalizeProcess(item) { return { pid: Number(item.pid ?? item.Pid), parentPid: Number(item.parentPid ?? item.ParentPid ?? 0), name: String(item.name ?? item.Name ?? "unknown").slice(0, 260), startedAt: item.startedAt ?? item.StartedAt ?? null }; }
function normalizeConnection(item) { return { pid: Number(item.pid ?? item.Pid ?? item.OwningProcess), protocol: "TCP", state: String(item.state ?? item.State ?? "Unknown").slice(0, 30), localAddress: String(item.localAddress ?? item.LocalAddress ?? ""), localPort: Number(item.localPort ?? item.LocalPort ?? 0), remoteAddress: String(item.remoteAddress ?? item.RemoteAddress ?? ""), remotePort: Number(item.remotePort ?? item.RemotePort ?? 0), timestamp: item.timestamp ?? new Date().toISOString() }; }
