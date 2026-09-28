import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { protectText, unprotectText } from "../apps/agent/src/secure-store.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = path.resolve(process.env.SENTRYGATE_DATA_DIR ?? path.join(os.homedir(), ".local", "share", "SentryGate"));
const runtimeDir = path.resolve(process.env.SENTRYGATE_RUNTIME_DIR ?? path.join(dataDir, "runtime"));
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
fs.mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
process.env.SENTRYGATE_STANDALONE = "true";
process.env.SENTRYGATE_HOST = "127.0.0.1";
process.env.SENTRYGATE_GATEWAY_HOST = "127.0.0.1";
process.env.SENTRYGATE_REMOTE_ACCESS_ENABLED = "false";
process.env.SENTRYGATE_DATA_DIR = dataDir;
process.env.SENTRYGATE_DB_PATH = path.join(dataDir, "sentrygate.db");
process.env.SENTRYGATE_RUNTIME_DIR = runtimeDir;
process.env.SENTRYGATE_PORT ??= "4300";
process.env.SENTRYGATE_GATEWAY_PORT ??= "4310";
const keyPath = path.join(runtimeDir, "local.key");
const secretPath = path.join(runtimeDir, "session-secret.protected");
process.env.SENTRYGATE_SESSION_SECRET = fs.existsSync(secretPath)
  ? unprotectText(fs.readFileSync(secretPath, "utf8"), "CurrentUser", keyPath)
  : crypto.randomBytes(48).toString("base64url");
if (!fs.existsSync(secretPath)) fs.writeFileSync(secretPath, protectText(process.env.SENTRYGATE_SESSION_SECRET, "CurrentUser", keyPath), { mode: 0o600, flag: "wx" });

const child = spawn(process.execPath, [path.join(root, "apps", "api", "src", "server.js")], { cwd: root, env: process.env, stdio: "inherit" });
const finish = (signal) => { if (!child.killed) child.kill(signal); };
process.once("SIGINT", () => finish("SIGINT"));
process.once("SIGTERM", () => finish("SIGTERM"));
child.once("error", (error) => { process.stderr.write(`SentryGate local backend failed to start (${error.code ?? "error"}).\n`); process.exitCode = 1; });
child.once("exit", (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); });
