import net from "node:net";
import { recordAudit } from "./audit.js";

export function parseNetwork(value) {
  if (typeof value !== "string") return null;
  const [address, prefixText, extra] = value.split("/");
  const version = net.isIP(address);
  if (!version || extra !== undefined) return null;
  const bits = version === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? bits : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const number = ipNumber(address);
  const shift = BigInt(bits - prefix);
  const start = (number >> shift) << shift;
  return { version, bits, prefix, addressNumber: number, start, end: start + (1n << shift) - 1n };
}

export function overlaps(left, right) {
  const a = parseNetwork(left), b = parseNetwork(right);
  return Boolean(a && b && a.version === b.version && a.start <= b.end && b.start <= a.end);
}

export function validateFirewallRule(body, db, now = Date.now(), configuredBackendAddresses = []) {
  if (!body || typeof body !== "object") return "Rule details are required";
  const network = parseNetwork(body.remoteCidr);
  if (!network) return "A valid IP address or CIDR is required";
  if (network.addressNumber !== network.start) return "CIDR address must use the network prefix address";
  if (!['TCP', 'UDP'].includes(body.protocol)) return "Protocol must be TCP or UDP";
  if (!Number.isInteger(body.localPort) || body.localPort < 1 || body.localPort > 65535) return "Port must be from 1 to 65535";
  if (typeof body.deviceId !== "string" || !db.prepare("SELECT 1 FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(body.deviceId)) return "An enrolled, active Windows device is required";
  if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 500) return "A reason is required (maximum 500 characters)";
  if (typeof body.evidence !== "string" || !body.evidence.trim() || body.evidence.length > 2000) return "Evidence is required (maximum 2000 characters)";
  if (typeof body.expiresAt !== "string" || !Number.isFinite(Date.parse(body.expiresAt)) || Date.parse(body.expiresAt) <= now || Date.parse(body.expiresAt) > now + 366 * 86400000) return "Expiry must be in the future and within one year";
  const device = db.prepare("SELECT backend_addresses FROM device_agents WHERE device_id=?").get(body.deviceId);
  const protectedNetworks = network.version === 4 ? ["127.0.0.0/8"] : ["::1/128", "::ffff:7f00:0/104"];
  protectedNetworks.push(...JSON.parse(db.prepare("SELECT management_addresses FROM firewall_settings WHERE id=1").get()?.management_addresses ?? "[]"));
  protectedNetworks.push(...JSON.parse(device?.backend_addresses ?? "[]"), ...configuredBackendAddresses);
  for (const address of protectedNetworks) if (overlaps(body.remoteCidr, address)) return `Rule overlaps protected address ${address}`;
  return null;
}

export function expireFirewallRules(db, now = new Date().toISOString()) {
  const expired = db.prepare("SELECT * FROM firewall_rules WHERE status IN ('approved','active','failed') AND expires_at<=?").all(now);
  for (const rule of expired) {
    db.prepare("UPDATE firewall_rules SET status='expired',updated_at=? WHERE id=?").run(now, rule.id);
    if (rule.action_id) db.prepare("UPDATE proposed_actions SET status='expired',updated_at=? WHERE id=? AND status IN ('approved','active')").run(now, rule.action_id);
    recordHistory(db, rule, "system", "expired", "Rule expiry reached; agent will remove it on next authenticated sync.", "expiry removal pending or complete", now);
    recordAudit(db, "system", "firewall.rule_expired", `firewall:${rule.id}`, "Expiry reached; removal queued for the enrolled agent.");
  }
}

export function recordHistory(db, rule, actor, action, result, exactRule = rule, createdAt = new Date().toISOString()) {
  const specification = JSON.stringify({ id: rule.id, deviceId: rule.device_id, name: `SentryGate-${rule.id}`, group: "SentryGate", remoteCidr: rule.remote_cidr, protocol: rule.protocol, localPort: rule.local_port, direction: "Inbound", action: "Block", expiresAt: rule.expires_at });
  db.prepare("INSERT INTO firewall_history (rule_id,actor,action,evidence,exact_rule,result,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?)")
    .run(rule.id, actor, action, rule.evidence, typeof exactRule === "string" ? exactRule : specification, result, rule.expires_at, createdAt);
}

function ipNumber(address) {
  if (net.isIP(address) === 4) return address.split(".").reduce((n, part) => (n << 8n) | BigInt(part), 0n);
  let value = address.toLowerCase();
  const ipv4 = value.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4) {
    const octets = ipv4[1].split(".").map(Number);
    value = value.slice(0, -ipv4[1].length) + ((octets[0] << 8 | octets[1]).toString(16)) + ":" + ((octets[2] << 8 | octets[3]).toString(16));
  }
  const halves = value.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  return groups.reduce((n, part) => (n << 16n) | BigInt(`0x${part || "0"}`), 0n);
}
