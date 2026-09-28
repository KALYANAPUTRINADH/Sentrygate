import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { collectLinuxMetadata, collectMacMetadata, parseLsof, parsePs, parseSs } from "../src/platform-collector.js";
import { reconcileLinuxNftables, validateRule } from "../src/linux-firewall.js";
import { protectTextWithLocalKey, unprotectTextWithLocalKey } from "../src/secure-store.js";

test("platform parsers preserve process and connection metadata without command arguments", () => {
  const processRows = parsePs("  41     1 Mon Sep 27 12:34:56 2026 /usr/libexec/sshd\n  42    41 Tue Sep 28 12:34:56 2026 worker");
  assert.equal(processRows[0].pid, 41);
  assert.equal(processRows[0].name, "sshd");
  assert.equal(processRows[0].executablePath, "");

  const linux = parseSs('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=41,fd=3))\ntcp ESTAB 0 0 10.0.0.2:4321 203.0.113.8:443 users:(("worker",pid=42,fd=8))');
  assert.deepEqual(linux.map(({ state, localPort, remoteAddress, pid }) => ({ state, localPort, remoteAddress, pid })), [
    { state: "Listen", localPort: 22, remoteAddress: "", pid: 41 },
    { state: "Established", localPort: 4321, remoteAddress: "203.0.113.8", pid: 42 }
  ]);

  const mac = parseLsof("p41\ncsshd\nf3\ntIPv4\nn*:22\nTST=LISTEN\np42\ncworker\nf8\ntIPv4\nn10.0.0.2:4321->203.0.113.8:443\nTST=ESTABLISHED");
  assert.deepEqual(mac.map(({ state, localPort, remoteAddress, pid }) => ({ state, localPort, remoteAddress, pid })), [
    { state: "Listen", localPort: 22, remoteAddress: "", pid: 41 },
    { state: "Established", localPort: 4321, remoteAddress: "203.0.113.8", pid: 42 }
  ]);
  assert.equal(parseSs("udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*")[0].state, "Listen");
});

test("local AES-GCM secret wrapping authenticates data and uses a per-installation 0600 key", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sentrygate-local-key-"));
  try {
    const keyFile = path.join(root, "private", "local.key");
    const encrypted = protectTextWithLocalKey("unique device secret", keyFile);
    assert.notEqual(encrypted, "unique device secret");
    assert.equal(unprotectTextWithLocalKey(encrypted, keyFile), "unique device secret");
    if (process.platform !== "win32") assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
    assert.throws(() => unprotectTextWithLocalKey(`${encrypted.slice(0, -2)}aa`, keyFile));
    const otherKey = path.join(root, "other.key");
    assert.throws(() => unprotectTextWithLocalKey(encrypted, otherKey));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("macOS and Linux collectors invoke fixed metadata commands and emit API-shaped security metadata", async () => {
  const calls = [];
  const run = async (command, args) => {
    calls.push([command, args]);
    if (command.endsWith("ps")) return "  41     1 Mon Sep 27 12:34:56 2026 /usr/bin/example";
    if (command === "ss") return 'tcp LISTEN 0 128 127.0.0.1:4300 0.0.0.0:* users:(("node",pid=41,fd=9))';
    if (command.endsWith("lsof")) return "p41\ncnode\nf9\ntIPv4\nn127.0.0.1:4300\nTST=LISTEN";
    if (command.endsWith("socketfilterfw")) return "Firewall is enabled. (State = 1)";
    if (command === "ufw") return "Status: inactive";
    if (args.includes("--state=running")) return "example.service loaded active running Example service";
    if (args.includes("list")) return "PID Status Label\n41 0 com.example.worker";
    return "active";
  };
  const linux = await collectLinuxMetadata({ run });
  const mac = await collectMacMetadata({ run });
  assert.equal(linux.processes[0].pid, 41);
  assert.equal(linux.connections[0].localPort, 4300);
  assert.equal(linux.securitySettings.platformName, "Linux");
  assert.equal(linux.securitySettings.defenderRealtimeProtection, null);
  assert.equal(mac.processes[0].pid, 41);
  assert.equal(mac.connections[0].localPort, 4300);
  assert.equal(mac.securitySettings.firewallProfiles[0].enabled, true);
  assert.equal(mac.securitySettings.platformName, "macOS");
  assert.ok(calls.every(([command]) => ["/bin/ps", "ps", "ss", "/usr/sbin/lsof", "/bin/launchctl", "systemctl", "ufw", "/usr/libexec/ApplicationFirewall/socketfilterfw"].includes(command)));
});

test("Linux firewall adapter owns an isolated nftables table, retries idempotently, and removes by owned handle", async () => {
  const id = "e3b5d247-1b42-4f55-9cc4-72681c8399f4", now = Date.now();
  const rule = { id, group: "SentryGate", kind: "inbound", operation: "ensure", remoteAddress: "203.0.113.9/32", protocol: "TCP", localPort: 8443, expiresAt: new Date(now + 60_000).toISOString() };
  const state = { table: false, chain: false, ruleLine: "" }, calls = [];
  const run = async (args) => {
    calls.push(args);
    const joined = args.join(" ");
    if (joined.startsWith("list chain") || joined.startsWith("-a list chain")) { if (!state.chain) { const error = new Error("not found"); error.code = "ENOENT"; throw error; } return state.ruleLine; }
    if (joined.startsWith("list table")) { if (!state.table) { const error = new Error("not found"); error.code = "ENOENT"; throw error; } return 'table inet sentrygate { comment "SentryGate:owned"; }'; }
    if (joined.startsWith("add table")) { state.table = true; return ""; }
    if (joined.startsWith("add chain")) { state.chain = true; return ""; }
    if (joined.startsWith("add rule")) { state.ruleLine = `ip saddr 203.0.113.9/32 tcp dport 8443 drop comment "SentryGate:${id}" # handle 17`; return ""; }
    if (joined.startsWith("delete rule")) { assert.equal(args.at(-1), "17"); state.ruleLine = ""; return ""; }
    throw new Error(`Unexpected nft command: ${joined}`);
  };
  assert.deepEqual((await reconcileLinuxNftables([rule], { run, now, isElevated: () => true })).results[0].status, "active");
  assert.deepEqual((await reconcileLinuxNftables([rule], { run, now, isElevated: () => true })).results[0].status, "active");
  assert.equal(calls.filter((call) => call[0] === "add" && call[1] === "rule").length, 1);
  assert.deepEqual((await reconcileLinuxNftables([{ ...rule, operation: "remove" }], { run, now, isElevated: () => true })).results[0].status, "removed");
  assert.throws(() => validateRule({ ...rule, remoteAddress: "0.0.0.0/0" }, now), /narrowly scoped|protected/);
  assert.ok(calls.every((call) => call.includes("sentrygate") || call[0] === "add" && call[1] === "table"));
});

test("Linux firewall adapter refuses unprivileged enforcement before invoking nft", async () => {
  const calls = [];
  const rule = { id: "e3b5d247-1b42-4f55-9cc4-72681c8399f4", group: "SentryGate", kind: "inbound", operation: "ensure", remoteAddress: "203.0.113.9", protocol: "TCP", localPort: 8443, expiresAt: new Date(Date.now() + 60_000).toISOString() };
  await assert.rejects(reconcileLinuxNftables([rule], { isElevated: () => false, run: async (args) => calls.push(args) }), /administrator-installed privileged/);
  assert.deepEqual(calls, []);
});

test("Unix installers define boot services and separate the local backend from the privileged agent", () => {
  const install = fs.readFileSync(new URL("../../../scripts/install-sentrygate-unix.sh", import.meta.url), "utf8");
  const agentInstall = fs.readFileSync(new URL("../../../scripts/install-agent-service-unix.sh", import.meta.url), "utf8");
  const linux = fs.readFileSync(new URL("../../../scripts/install-sentrygate-linux.sh", import.meta.url), "utf8");
  const macos = fs.readFileSync(new URL("../../../scripts/install-sentrygate-macos.sh", import.meta.url), "utf8");
  assert.match(linux, /uname -s.*Linux/);
  assert.match(macos, /uname -s.*Darwin/);
  assert.match(install, /systemctl --user enable --now sentrygate\.service/);
  assert.match(install, /loginctl enable-linger/);
  assert.match(install, /LaunchDaemons\/local\.sentrygate\.dashboard\.plist/);
  assert.match(agentInstall, /systemctl enable --now sentrygate-agent\.service/);
  assert.match(agentInstall, /LaunchDaemons\/local\.sentrygate\.agent\.plist/);
  assert.match(install, /SENTRYGATE_STANDALONE=true/);
});
