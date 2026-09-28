import { execFile } from "node:child_process";
import { promisify } from "node:util";
import net from "node:net";

const execFileAsync = promisify(execFile);
const TABLE = ["inet", "sentrygate"];
const CHAIN = [...TABLE, "input"];

export async function reconcileLinuxNftables(rules, { run = runNft, now = Date.now(), isElevated = () => typeof process.getuid !== "function" || process.getuid() === 0 } = {}) {
  if (!Array.isArray(rules) || rules.length > 100) throw new Error("Firewall operation batch must contain at most 100 rules");
  if (!rules.length) return { results: [] };
  if (!isElevated()) throw new Error("Linux firewall changes require an administrator-installed privileged SentryGate agent");
  const results = [];
  for (const rule of rules) {
    try {
      validateRule(rule, now);
      await ensureOwnedChain(run);
      if (rule.operation === "remove" || rule.expiresAt && Date.parse(rule.expiresAt) <= now) {
        await removeOwnedRule(rule.id, run);
        results.push({ id: rule.id, status: "removed", detail: "SentryGate-owned nftables rule removed or already absent.", actualState: { table: "inet sentrygate", owned: true, active: false } });
      } else {
        let existing = await listChain(run);
        const marker = `SentryGate:${rule.id}`;
        let owned = existing.filter((line) => line.includes(marker));
        const cidr = rule.remoteCidr ?? rule.remoteAddress;
        const family = net.isIP(cidr.split("/")[0]) === 6 ? "ip6" : "ip";
        if (owned.some((line) => !line.includes(`${family} saddr ${cidr}`) || !line.includes(`${String(rule.protocol).toLowerCase()} dport ${rule.localPort}`) || !line.includes("drop"))) throw new Error("Existing SentryGate nftables rule differs from the approved specification");
        if (!owned.length) {
          await run(["add", "rule", ...CHAIN, family, "saddr", cidr, String(rule.protocol).toLowerCase(), "dport", String(rule.localPort), "counter", "drop", "comment", marker]);
          existing = await listChain(run);
          owned = existing.filter((line) => line.includes(marker));
          if (owned.length !== 1 || !owned[0].includes(`${family} saddr ${cidr}`) || !owned[0].includes(`${String(rule.protocol).toLowerCase()} dport ${rule.localPort}`) || !owned[0].includes("drop")) throw new Error("Could not verify the exact SentryGate nftables rule after applying it");
        }
        results.push({ id: rule.id, status: "active", detail: "SentryGate-owned nftables input rule is present.", actualState: { table: "inet sentrygate", chain: "input", remoteCidr: rule.remoteCidr ?? rule.remoteAddress, protocol: rule.protocol, localPort: rule.localPort, owned: true, active: true } });
      }
    } catch (error) { results.push({ id: rule?.id ?? "unknown", status: "failed", detail: String(error.message ?? "nftables operation failed").slice(0, 500), actualState: null }); }
  }
  return { results };
}

export function validateRule(rule, now = Date.now()) {
  if (!rule || typeof rule.id !== "string" || !/^[a-f0-9-]{36}$/i.test(rule.id)) throw new Error("Firewall rule ID is invalid");
  if (rule.group !== "SentryGate" || rule.kind !== "inbound" || !["ensure", "remove"].includes(rule.operation ?? "ensure")) throw new Error("Only SentryGate-owned inbound rules can be changed");
  if (!rule.expiresAt || !Number.isFinite(Date.parse(rule.expiresAt)) || Date.parse(rule.expiresAt) <= now) {
    if (rule.operation !== "remove") throw new Error("An unexpired rule expiry is required");
  }
  if (rule.operation !== "remove" && Date.parse(rule.expiresAt) > now + 366 * 86_400_000) throw new Error("Firewall rule expiry exceeds one year");
  const cidr = rule.remoteCidr ?? rule.remoteAddress;
  if (!net.isIP(cidr?.split("/")[0]) || !/^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$|^[0-9a-f:]+(?:\/\d{1,3})?$/i.test(cidr)) throw new Error("A valid IPv4 or IPv6 address/CIDR is required");
  const address = cidr.split("/")[0], version = net.isIP(address);
  if (cidr.includes("/")) {
    const prefix = Number(cidr.split("/")[1]), max = version === 4 ? 32 : 128;
    if (prefix < (version === 4 ? 24 : 64) || prefix > max) throw new Error("CIDR must be a host or a narrowly scoped /24 IPv4 or /64 IPv6 network");
  }
  if (version === 4 && (/^(0|127|224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239)\./.test(address) || address === "255.255.255.255")) throw new Error("Unspecified, loopback, multicast, and broadcast addresses are protected");
  if (version === 6 && (/^::$/.test(address) || /^::1$/i.test(address) || /^ff/i.test(address))) throw new Error("Unspecified, loopback, and multicast addresses are protected");
  if (!Number.isInteger(rule.localPort) || rule.localPort < 1 || rule.localPort > 65535 || !["tcp", "udp"].includes(String(rule.protocol).toLowerCase())) throw new Error("Protocol or local port is invalid");
}

async function ensureOwnedChain(run) {
  let table;
  try { table = await run(["list", "table", ...TABLE]); }
  catch {
    await run(["add", "table", ...TABLE, "{", "comment", "SentryGate:owned", ";", "}"]);
    table = await run(["list", "table", ...TABLE]);
  }
  if (!table.includes('comment "SentryGate:owned"') && !table.includes("comment SentryGate:owned")) throw new Error("An unowned nftables table already uses the SentryGate name; refusing to modify it");
  try { await run(["list", "chain", ...CHAIN]); return; } catch { /* Create only our input chain in the verified owned table. */ }
  await run(["add", "chain", ...CHAIN, "{", "type", "filter", "hook", "input", "priority", "-10", ";", "policy", "accept", ";", "}"]);
}
async function listChain(run) {
  try { return (await run(["-a", "list", "chain", ...CHAIN])).split(/\r?\n/); }
  catch (error) { if (error.code === "ENOENT") throw new Error("nft command is unavailable"); return []; }
}
async function removeOwnedRule(id, run) {
  const marker = `SentryGate:${id}`, lines = await listChain(run), owned = lines.filter((line) => line.includes(marker));
  for (const line of owned) {
    const match = line.match(/# handle (\d+)\s*$/);
    if (!match) throw new Error("Could not verify the owned nftables rule handle");
    await run(["delete", "rule", ...CHAIN, "handle", match[1]]);
  }
  if ((await listChain(run)).some((line) => line.includes(marker))) throw new Error("SentryGate-owned nftables rule remains after rollback");
}
async function runNft(args) {
  const { stdout } = await execFileAsync("nft", args, { encoding: "utf8", timeout: 10000, maxBuffer: 1_000_000, windowsHide: true });
  return stdout;
}
