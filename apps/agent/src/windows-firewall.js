import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/firewall.ps1", import.meta.url));

export async function reconcileFirewall(rules, { run = runPowerShell } = {}) {
  if (process.platform !== "win32" && run === runPowerShell) throw new Error("Firewall management is available only on Windows");
  const { stdout } = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script], {
    input: JSON.stringify({ rules }), encoding: "utf8", windowsHide: true, maxBuffer: 2_000_000
  });
  return JSON.parse(stdout.trim() || "{}");
}

function runPowerShell(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(stderr.slice(-2000) || `PowerShell exited with code ${code}`)));
    child.stdin.end(options.input);
  });
}
