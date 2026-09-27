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
  const tlsCertPath=overrides.tlsCertPath ?? process.env.SENTRYGATE_TLS_CERT ?? "";
  const tlsKeyPath=overrides.tlsKeyPath ?? process.env.SENTRYGATE_TLS_KEY ?? "";
  if(Boolean(tlsCertPath)!==Boolean(tlsKeyPath)) throw new Error("SENTRYGATE_TLS_CERT and SENTRYGATE_TLS_KEY must be configured together");
  if(process.env.NODE_ENV === "production" && (!configuredSessionSecret || !tlsCertPath)) throw new Error("Production mode requires SENTRYGATE_SESSION_SECRET and API/gateway TLS certificates");
  const host=overrides.host ?? process.env.SENTRYGATE_HOST ?? "127.0.0.1";
  const gatewayHost=overrides.gatewayHost ?? process.env.SENTRYGATE_GATEWAY_HOST ?? "127.0.0.1";
  const isLoopback=(value)=>["127.0.0.1","::1","localhost"].includes(value);
  if((!isLoopback(host)||!isLoopback(gatewayHost)) && !tlsCertPath) throw new Error("Non-loopback listeners require TLS certificates");
  const apiBaseUrl=overrides.apiBaseUrl || process.env.SENTRYGATE_API_BASE_URL || `${tlsCertPath?"https":"http"}://127.0.0.1:${Number(overrides.port ?? process.env.SENTRYGATE_PORT ?? 4300)}`;
  if(process.env.NODE_ENV === "production" && new URL(apiBaseUrl).protocol !== "https:") throw new Error("Production SENTRYGATE_API_BASE_URL must use HTTPS");
  if(!["http:","https:"].includes(new URL(apiBaseUrl).protocol)) throw new Error("SENTRYGATE_API_BASE_URL must use HTTP or HTTPS");
  const apiUrl=new URL(apiBaseUrl),apiHostname=apiUrl.hostname.replace(/^\[|\]$/g,"");
  if(apiUrl.protocol!=="https:" && !isLoopback(apiHostname)) throw new Error("SENTRYGATE_API_BASE_URL must use HTTPS except for loopback development");
  if(apiUrl.username||apiUrl.password||apiUrl.search||apiUrl.hash)throw new Error("SENTRYGATE_API_BASE_URL must not embed credentials, query parameters, or fragments");
  const maxDbBytes=Number(overrides.maxDbBytes ?? process.env.SENTRYGATE_MAX_DB_BYTES ?? 2_147_483_648);
  if(!Number.isSafeInteger(maxDbBytes)||maxDbBytes<1_048_576||maxDbBytes>1_099_511_627_776)throw new Error("SENTRYGATE_MAX_DB_BYTES must be between 1 MiB and 1 TiB");
  const eventIngestTimeoutMs=Number(overrides.eventIngestTimeoutMs ?? process.env.SENTRYGATE_EVENT_INGEST_TIMEOUT_MS ?? 1000);
  if(!Number.isInteger(eventIngestTimeoutMs)||eventIngestTimeoutMs<100||eventIngestTimeoutMs>10000)throw new Error("SENTRYGATE_EVENT_INGEST_TIMEOUT_MS must be 100 to 10000 milliseconds");
  return {
    dbPath:
      overrides.dbPath ??
      process.env.SENTRYGATE_DB_PATH ??
      path.resolve(process.cwd(), "apps/api/data/sentrygate.db"),
    port: Number(overrides.port ?? process.env.SENTRYGATE_PORT ?? 4300),
    host,
    gatewayPort: Number(overrides.gatewayPort ?? process.env.SENTRYGATE_GATEWAY_PORT ?? 4310),
    gatewayHost,
    sessionSecret: configuredSessionSecret || crypto.randomBytes(32).toString("base64url"),
    cookieSecure: overrides.cookieSecure ?? (process.env.NODE_ENV === "production" || Boolean(tlsCertPath)),
    tlsCertPath: tlsCertPath ? path.resolve(tlsCertPath) : "",
    tlsKeyPath: tlsKeyPath ? path.resolve(tlsKeyPath) : "",
    apiBaseUrl,
    maxDbBytes,
    eventIngestTimeoutMs,
    webRoot: overrides.webRoot ?? path.resolve(process.cwd(), "apps/web")
  };
}
