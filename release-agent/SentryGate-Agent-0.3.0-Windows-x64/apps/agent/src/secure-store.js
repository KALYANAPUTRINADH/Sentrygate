import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/dpapi.ps1", import.meta.url));
export function protectText(value, scope = "CurrentUser", keyPath) {
  if (process.platform !== "win32") return protectTextWithLocalKey(value, keyPath);
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", "Protect", "-Scope", scope], { input: value, encoding: "utf8", windowsHide: true }).trim();
}
export function unprotectText(value, scope = "CurrentUser", keyPath) {
  if (process.platform !== "win32") return unprotectTextWithLocalKey(value, keyPath);
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", "Unprotect", "-Scope", scope], { input: value, encoding: "utf8", windowsHide: true }).trim();
}
export function writeProtected(filePath, value, scope, keyPath) { writeFileSync(filePath, protectText(value, scope, keyPath), { encoding: "utf8", mode: 0o600 }); }
export function readProtected(filePath, scope, keyPath) { return unprotectText(readFileSync(filePath, "utf8"), scope, keyPath); }

export function protectTextWithLocalKey(value, keyPath) {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", loadLocalKey(keyPath), iv);
  const ciphertext = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return `sg1:${Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64")}`;
}
export function unprotectTextWithLocalKey(value, keyPath) {
  const [version, encoded] = String(value).split(":");
  if (version !== "sg1" || !encoded) throw new Error("Protected local secret has an unsupported format");
  const packed = Buffer.from(encoded, "base64");
  if (packed.length < 29) throw new Error("Protected local secret is truncated");
  const decipher = crypto.createDecipheriv("aes-256-gcm", loadLocalKey(keyPath), packed.subarray(0, 12));
  decipher.setAuthTag(packed.subarray(12, 28));
  return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString("utf8");
}
function loadLocalKey(keyPath) {
  const filePath = path.resolve(keyPath ?? process.env.SENTRYGATE_AGENT_KEY_PATH ?? path.join(os.homedir(), ".sentrygate-agent", "local.key"));
  mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  if (!existsSync(filePath)) {
    const key = crypto.randomBytes(32);
    try { writeFileSync(filePath, key, { flag: "wx", mode: 0o600 }); }
    catch (error) { if (error.code !== "EEXIST") throw error; }
  }
  if (process.platform !== "win32") chmodSync(filePath, 0o600);
  const key = readFileSync(filePath);
  if (key.length !== 32) throw new Error("Protected local key has an invalid length");
  return key;
}
