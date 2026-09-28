import net from "node:net";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/firewall.ps1", import.meta.url));

export async function reconcileFirewall(rules, { run, helperKey, now = Date.now(), connect = connectPipe } = {}) {
  if (!Array.isArray(rules) || rules.length > 100) throw new Error("Firewall operation batch must contain at most 100 rules");
  if (!rules.length) return { results: [] };
  if (run) {
    const { stdout } = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script], {
      input: JSON.stringify({ rules }), encoding: "utf8", windowsHide: true, maxBuffer: 2_000_000
    });
    return JSON.parse(stdout.trim() || "{}");
  }
  const key = Buffer.isBuffer(helperKey) ? helperKey : typeof helperKey === "string" ? Buffer.from(helperKey, "utf8") : Buffer.alloc(0);
  if (key.length < 32) throw new Error("SentryGate Firewall Helper is not installed or its protected key is unavailable");
  if (process.platform !== "win32") throw new Error("The privileged firewall helper is available only on Windows");
  const payload = Buffer.from(JSON.stringify({ rules, nonce: crypto.randomUUID(), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 90_000).toISOString() }));
  const signature = crypto.createHmac("sha256", key).update(payload).digest("base64");
  const response = await connect(JSON.stringify({ payload: payload.toString("base64"), signature }));
  const result = JSON.parse(response);
  if (result.error) throw new Error(result.error);
  return result;
}

function connectPipe(message) {
  return new Promise((resolve, reject) => {
    const pipe = net.connect("\\\\.\\pipe\\SentryGate.Firewall");
    let response = "";
    pipe.setEncoding("utf8");
    pipe.setTimeout(35_000, () => { pipe.destroy(new Error("SentryGate Firewall Helper timed out")); });
    pipe.once("connect", () => pipe.end(`${message}\n`));
    pipe.on("data", (chunk) => { response += chunk; if (response.length > 2_000_000) pipe.destroy(new Error("Firewall helper response exceeded limit")); });
    pipe.once("error", reject);
    pipe.once("end", () => resolve(response.trim()));
  });
}
