import http from "node:http";
import https from "node:https";
import net from "node:net";
import { randomUUID } from "node:crypto";
import { URL } from "node:url";
import { ensureAgentCredential } from "./agent-credentials.js";
import { expireGatewayActions } from "./actions.js";

const hopHeaders = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "forwarded"]);

export function createGatewayServer(db, config) {
  const requestsByClient = new Map();
  const server = http.createServer((req, res) => {
    handleRequest(req, res, db, config, requestsByClient).catch((error) => {
      if (!res.headersSent) sendText(res, 500, "Gateway error");
      else res.destroy(error);
    });
  });
  server.on("upgrade", (req, socket) => {
    recordUnsupportedUpgrade(req, socket, db, config).catch(() => {
      socket.end("HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    });
  });
  return server;
}

async function recordUnsupportedUpgrade(req, socket, db, config) {
  const url = new URL(req.url ?? "/", "http://sentrygate.local");
  const match = url.pathname.match(/^\/site\/(\d+)(\/.*)?$/);
  const assetId = match ? Number(match[1]) : 0;
  const asset = assetId ? db.prepare("SELECT id,type FROM assets WHERE id = ?").get(assetId) : null;
  if (asset?.type === "website") {
    const sourceIp = observedClientIp(req, trustedProxyList(db));
    const timestamp = new Date().toISOString();
    const reason = "WebSocket Upgrade is not supported by this gateway; the connection was not proxied.";
    await postEvent(db, config, buildEvent(req, url.pathname, sourceIp, assetId, 501, "websocket_unsupported", "unsupported", reason, timestamp));
  }
  socket.end("HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
}

async function handleRequest(req, res, db, config, requestsByClient) {
  const requestTimestamp = new Date().toISOString();
  const parsed = new URL(req.url ?? "/", "http://sentrygate.local");
  const route = parsed.pathname.match(/^\/site\/(\d+)(\/.*)?$/);
  if (!route) return sendText(res, 404, "Protected site route not found");

  const assetId = Number(route[1]);
  const sitePath = route[2] || "/";
  const asset = db.prepare("SELECT id, name, type, upstream_url AS upstreamUrl FROM assets WHERE id = ?").get(assetId);
  if (!asset || asset.type !== "website") return sendText(res, 404, "Protected website not found");
  const rule = db.prepare(`SELECT enabled, mode, rate_limit_count AS rateLimitCount, window_seconds AS windowSeconds,
    sensitive_paths_enabled AS sensitivePathsEnabled FROM gateway_rules WHERE asset_id = ?`).get(assetId)
    ?? { enabled: 1, mode: "observe", rateLimitCount: 120, windowSeconds: 60, sensitivePathsEnabled: 1 };
  const sourceIp = observedClientIp(req, trustedProxyList(db));
  const allowlisted = Boolean(db.prepare("SELECT 1 FROM gateway_allowlist WHERE asset_id = ? AND ip = ?").get(assetId, sourceIp));
  expireGatewayActions(db);
  const approvedBlock = !allowlisted && Boolean(db.prepare("SELECT 1 FROM gateway_ip_blocks WHERE asset_id=? AND ip=? AND expires_at>? LIMIT 1").get(assetId, sourceIp, requestTimestamp));
  const isSensitive = Number(rule.enabled) === 1 && Number(rule.sensitivePathsEnabled) === 1 && sensitivePath(sitePath);
  const isRateLimited = Number(rule.enabled) === 1 && !allowlisted && rateExceeded(requestsByClient, assetId, sourceIp, Number(rule.rateLimitCount), Number(rule.windowSeconds));
  const detectionRule = allowlisted ? "allowlist" : approvedBlock ? "approved_block" : isSensitive ? "sensitive_path" : isRateLimited ? "rate_limit" : "none";
  const isDetection = detectionRule !== "none" && detectionRule !== "allowlist";
  const blocked = approvedBlock || (isDetection && rule.mode === "block");
  const action = allowlisted ? "allowlisted" : blocked ? "blocked" : isDetection ? (rule.mode === "challenge-ready" ? "challenge-ready" : "observed") : "forwarded";
  const reason = allowlisted
    ? "Source IP matches this website's allowlist."
    : detectionRule === "approved_block" ? "An administrator-approved temporary SentryGate website block matched this observed source IP."
    : detectionRule === "sensitive_path" ? "Request path matches an enabled sensitive-path rule."
      : detectionRule === "rate_limit" ? `Request exceeded ${rule.rateLimitCount} requests in ${rule.windowSeconds} seconds for this observed source IP.`
        : "No enabled gateway rule matched this request.";

  if (blocked) {
    const status = detectionRule === "rate_limit" ? 429 : 403;
    await postEvent(db, config, buildEvent(req, parsed.pathname, sourceIp, assetId, status, detectionRule, action, reason, requestTimestamp));
    return sendText(res, status, detectionRule === "rate_limit" ? "Rate limit exceeded" : "Request blocked by SentryGate");
  }

  if (!asset.upstreamUrl) {
    const reasonText = "No upstream URL is configured for this protected website.";
    await postEvent(db, config, buildEvent(req, parsed.pathname, sourceIp, assetId, 503, "upstream_unavailable", "upstream-error", reasonText, requestTimestamp));
    return sendText(res, 503, reasonText);
  }

  let upstream;
  try { upstream = new URL(asset.upstreamUrl); }
  catch { return sendText(res, 502, "Invalid upstream configuration"); }

  const basePath = upstream.pathname.replace(/\/$/, "");
  const upstreamPath = `${basePath}${sitePath.startsWith("/") ? sitePath : `/${sitePath}`}${parsed.search}`;
  const headers = filteredHeaders(req.headers);
  for (const name of Object.keys(headers)) {
    if (name.startsWith("x-forwarded-") || name === "x-real-ip") delete headers[name];
  }
  headers.host = upstream.host;
  headers["x-forwarded-for"] = sourceIp;
  headers["x-forwarded-proto"] = req.socket.encrypted ? "https" : "http";
  headers["x-forwarded-host"] = req.headers.host ?? "";

  await new Promise((resolve) => {
    const transport = upstream.protocol === "https:" ? https : http;
    const proxyRequest = transport.request({
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port || undefined,
      method: req.method,
      path: upstreamPath,
      headers
    }, (upstreamResponse) => {
      const status = upstreamResponse.statusCode ?? 502;
      const event = buildEvent(req, parsed.pathname, sourceIp, assetId, status, detectionRule, action, reason, requestTimestamp);
      (async () => {
        await postEvent(db, config, event).catch((error) => console.error("Gateway event delivery failed:", error.message));
        res.writeHead(status, filteredHeaders(upstreamResponse.headers));
        upstreamResponse.pipe(res);
      })().catch((error) => { if (!res.headersSent) sendText(res, 502, "Upstream response failed"); else res.destroy(error); resolve(); });
      upstreamResponse.on("end", resolve);
      upstreamResponse.on("close", resolve);
      upstreamResponse.on("error", () => resolve());
      res.on("close", () => { if (!res.writableEnded) upstreamResponse.destroy(); });
    });

    proxyRequest.setTimeout(config.upstreamTimeoutMs ?? 30000, () => proxyRequest.destroy(new Error("Upstream timeout")));
    proxyRequest.on("error", async () => {
      const reasonText = "The configured upstream could not be reached or timed out.";
      await postEvent(db, config, buildEvent(req, parsed.pathname, sourceIp, assetId, 502, "upstream_unavailable", "upstream-error", reasonText, requestTimestamp)).catch(() => {});
      if (!res.headersSent) sendText(res, 502, "Upstream unavailable");
      resolve();
    });
    req.pipe(proxyRequest);
  });
}

function observedClientIp(req, trustedProxies) {
  const peer = normalizeIp(req.socket.remoteAddress ?? "");
  if (!trustedProxies.includes(peer)) return peer;
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded !== "string") return peer;
  const chain = forwarded.split(",").map((part) => normalizeIp(part.trim()));
  const nearest = chain.at(-1);
  return nearest && net.isIP(nearest) ? nearest : peer;
}

function trustedProxyList(db) {
  try { return JSON.parse(db.prepare("SELECT trusted_proxies FROM gateway_settings WHERE id = 1").get()?.trusted_proxies ?? "[]"); }
  catch { return []; }
}

function normalizeIp(ip) {
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

function sensitivePath(pathname) {
  let decoded = pathname;
  try { decoded = decodeURIComponent(pathname); } catch {}
  return /(?:^|\/)\.env(?:$|\/)|(?:^|\/)\.git(?:$|\/)/i.test(decoded);
}

function rateExceeded(requestsByClient, assetId, ip, maxRequests, windowSeconds) {
  const now = Date.now();
  const key = `${assetId}:${ip}`;
  const cutoff = now - windowSeconds * 1000;
  const recent = (requestsByClient.get(key) ?? []).filter((timestamp) => timestamp > cutoff);
  const exceeded = recent.length >= maxRequests;
  if (!exceeded) recent.push(now);
  requestsByClient.set(key, recent);
  if (requestsByClient.size > 10000) {
    for (const [knownKey, timestamps] of requestsByClient) {
      if (!timestamps.length || timestamps.at(-1) < now - 3_600_000) requestsByClient.delete(knownKey);
    }
  }
  return exceeded;
}

function buildEvent(req, pathname, sourceIp, assetId, responseStatus, detectionRule, action, reason, timestamp) {
  const detection = detectionRule !== "none" && detectionRule !== "allowlist";
  return {
    eventId: randomUUID(),
    assetId,
    timestamp,
    sourceIp,
    method: req.method ?? "GET",
    path: pathname,
    userAgent: String(req.headers["user-agent"] ?? "").slice(0, 1000),
    responseStatus,
    detectionRule,
    action,
    reason,
    severity: detectionRule === "rate_limit" ? "high" : detection ? "medium" : "info",
    requestDetails: `${req.method ?? "GET"} ${pathname}`
  };
}

async function postEvent(db, config, event) {
  const token = ensureAgentCredential(db, config.sessionSecret);
  const response = await fetch(`${config.apiBaseUrl}/api/agent/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(event),
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) throw new Error(`Event ingestion failed: ${response.status}`);
}

function filteredHeaders(source) {
  const headers = { ...source };
  const connectionTokens = String(headers.connection ?? "").split(",").map((token) => token.trim().toLowerCase());
  for (const header of hopHeaders) delete headers[header];
  for (const header of connectionTokens) delete headers[header];
  return headers;
}

function sendText(res, status, text) {
  const body = Buffer.from(text);
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": body.length, "Cache-Control": "no-store" });
  res.end(body);
}
