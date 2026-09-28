import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import test from "node:test";

const execFileAsync = promisify(execFile);

test("live Windows collector returns useful non-elevated process, socket, service, and firewall data", { skip: process.platform !== "win32" }, async () => {
  const script = fileURLToPath(new URL("../scripts/collect.ps1", import.meta.url));
  const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script], {
    encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 12 * 1024 * 1024
  });
  const result = JSON.parse(stdout);
  assert.ok(result.processes.length > 0, "process metadata should fall back to Get-Process when CIM is denied");
  assert.ok(result.connections.some((item) => item.state === "Listen"), "socket metadata should fall back to netstat");
  assert.ok(result.services.length > 0, "service metadata should fall back to Get-Service when CIM is denied");
  assert.ok(result.securitySettings.firewallProfiles.length > 0, "firewall status should fall back to read-only netsh");
  assert.deepEqual(result.collectionErrors, []);
  assert.equal(typeof result.securitySettings.defenderRealtimeProtection === "boolean" || result.securitySettings.defenderRealtimeProtection === null, true);
});
