import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";

function loadEnvFile() {
  const envPath = path.resolve(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || Object.hasOwn(process.env, match[1])) continue;
    process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, "$2");
  }
}

export function loadConfig(overrides = {}) {
  loadEnvFile();
  const configuredSessionSecret = overrides.sessionSecret ?? process.env.SENTRYGATE_SESSION_SECRET;
  if (configuredSessionSecret && configuredSessionSecret.length < 32) {
    throw new Error("SENTRYGATE_SESSION_SECRET must contain at least 32 characters");
  }
  return {
    dbPath:
      overrides.dbPath ??
      process.env.SENTRYGATE_DB_PATH ??
      path.resolve(process.cwd(), "apps/api/data/sentrygate.db"),
    port: Number(overrides.port ?? process.env.SENTRYGATE_PORT ?? 4300),
    host: overrides.host ?? process.env.SENTRYGATE_HOST ?? "127.0.0.1",
    gatewayPort: Number(overrides.gatewayPort ?? process.env.SENTRYGATE_GATEWAY_PORT ?? 4310),
    gatewayHost: overrides.gatewayHost ?? process.env.SENTRYGATE_GATEWAY_HOST ?? "127.0.0.1",
    sessionSecret: configuredSessionSecret || crypto.randomBytes(32).toString("base64url"),
    cookieSecure: overrides.cookieSecure ?? process.env.NODE_ENV === "production",
    apiBaseUrl: overrides.apiBaseUrl ?? process.env.SENTRYGATE_API_BASE_URL ?? `http://127.0.0.1:${Number(overrides.port ?? process.env.SENTRYGATE_PORT ?? 4300)}`,
    webRoot: overrides.webRoot ?? path.resolve(process.cwd(), "apps/web")
  };
}
