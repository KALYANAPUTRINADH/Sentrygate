import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import readline from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { writeProtected } from "../src/secure-store.js";

const dataRoot = path.resolve(process.env.SENTRYGATE_AGENT_DATA ?? path.join(os.homedir(), ".local", "share", "SentryGate", "Agent"));
const deviceId = process.argv[2];
const apiBaseUrl = process.argv[3] ?? "http://127.0.0.1:4300";
if (!/^[a-f0-9-]{36}$/i.test(deviceId ?? "")) throw new Error("Usage: node configure-agent-unix.mjs <local-device-guid> [http://127.0.0.1:4300]");
const endpoint = new URL(apiBaseUrl);
if (endpoint.protocol !== "http:" || !["127.0.0.1", "::1", "localhost"].includes(endpoint.hostname.replace(/^\[|\]$/g, ""))) throw new Error("Standalone agent configuration accepts only loopback HTTP");
fs.mkdirSync(dataRoot, { recursive: true, mode: 0o700 });
const deviceRl = readline.createInterface({ input: stdin, output: stdout });
let credential;
try { credential = await deviceRl.question(`Confirm local device ID suffix '${deviceId.slice(-6)}': `); }
finally { deviceRl.close(); }
if (credential !== deviceId.slice(-6)) throw new Error("Device ID confirmation did not match");
credential = await readHiddenSecret("Paste this computer's one-time local enrollment credential: ");
if (credential.length < 32 || credential.length > 512 || /\s/.test(credential)) throw new Error("Credential format is invalid");
writeProtected(path.join(dataRoot, "credential.local"), credential, "CurrentUser", path.join(dataRoot, "local.key"));
credential = "";
const config = { deviceId, apiBaseUrl: endpoint.origin, credentialFile: "credential.local", localKeyPath: path.join(dataRoot, "local.key"), dataRoot, spoolMaxBytes: 268435456, intervalSeconds: 30, collectProcesses: true, collectConnections: true };
fs.writeFileSync(path.join(dataRoot, "config.json"), `${JSON.stringify(config, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
process.stdout.write(`Local agent configuration saved under ${dataRoot}. The token is encrypted and was not logged.\n`);

async function readHiddenSecret(prompt) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") throw new Error("Run this command in an interactive terminal so the credential can be entered without echo");
  stdout.write(prompt);
  stdin.setRawMode(true);
  stdin.resume();
  return new Promise((resolve, reject) => {
    let value = "";
    const finish = (error) => {
      stdin.removeListener("data", onData);
      stdin.setRawMode(false);
      stdout.write("\n");
      if (error) reject(error); else resolve(value);
    };
    const onData = (chunk) => {
      for (const char of chunk.toString("utf8")) {
        if (char === "\u0003") return finish(new Error("Credential entry cancelled"));
        if (char === "\r" || char === "\n") return finish();
        if (char === "\u007f" || char === "\b") value = value.slice(0, -1);
        else if (char >= " " && char <= "~") value += char;
        if (value.length > 512) return finish(new Error("Credential is too long"));
      }
    };
    stdin.on("data", onData);
  });
}
