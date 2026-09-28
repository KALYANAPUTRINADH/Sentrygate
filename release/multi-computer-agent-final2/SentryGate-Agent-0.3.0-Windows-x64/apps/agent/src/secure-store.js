import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/dpapi.ps1", import.meta.url));
export function protectText(value, scope = "CurrentUser") {
  assertWindows();
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", "Protect", "-Scope", scope], { input: value, encoding: "utf8", windowsHide: true }).trim();
}
export function unprotectText(value, scope = "CurrentUser") {
  assertWindows();
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", "Unprotect", "-Scope", scope], { input: value, encoding: "utf8", windowsHide: true }).trim();
}
export function writeProtected(path, value, scope) { writeFileSync(path, protectText(value, scope), { encoding: "utf8", mode: 0o600 }); }
export function readProtected(path, scope) { return unprotectText(readFileSync(path, "utf8"), scope); }
function assertWindows() { if (process.platform !== "win32") throw new Error("DPAPI secure storage requires Windows"); }
