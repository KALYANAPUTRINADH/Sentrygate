import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import net from "node:net";
import { randomUUID } from "node:crypto";
import { URL } from "node:url";
import { ensureAssetCredential } from "./agent-credentials.js";
import { expireGatewayActions } from "./actions.js";
import { logOperational } from "./logger.js";
import { performance } from "node:perf_hooks";
import { resolveLocalEndpoint } from "../../../packages/shared/network-policy.js";

const hopHeaders = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "forwarded"]);
const gatewayVersion = "0.7.0";

export function createGatewayServer(db, config) {
  const requestsByClient = new Map();
  const handler=(req, res) => {
    const started=performance.now();
    res.once("finish",()=>{
      const route=String(req.url??"").match(/^\/site\/(\d+)(?:\/|\?|$)/);
      if(!route)return;
      try{
        const event=req.sentryEventId?db.prepare("SELECT id FROM events WHERE source_event_id=?").get(req.sentryEventId):null;
        db.prepare("INSERT INTO gateway_request_metrics(asset_id,event_id,observed_at,duration_ms,upstream_error) VALUES(?,?,?,?,?)")
          .run(Number(route[1]),event?.id??null,new Date().toISOString(),Math.max(0,performance.now()-started),res.statusCode>=500?1:0);
      }catch(error){logOperational("error","gateway.metrics_write_failed",{code:error.code??error.name??"Error"});}
    });
    handleRequest(req, res, db, config, requestsByClient).catch((error) => {
      logOperational("error","gateway.request_failed",{code:error.code??error.name??"Error"});
      if (!res.headersSent) sendText(res, 502, "Gateway temporarily unavailable");
      else res.destroy(error);
    });
  };
  const server=config.tlsCertPath
    ? https.createServer({cert:fs.readFileSync(config.tlsCertPath),key:fs.readFileSync(config.tlsKeyPath),minVersion:"TLSv1.2"},handler)
    : http.createServer(handler);
  server.on("upgrade", (req, socket) => {
    recordUnsupportedUpgrade(req, socket, db, config).catch(() => {
      socket.end("HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    });
  });
  const heartbeat = () => {
    try {
      const now = new Date().toISOString();
      db.prepare(`INSERT INTO website_gateway_status(asset_id,gateway_version,last_heartbeat,health_status)
        SELECT id,?,?, 'healthy' FROM assets WHERE type='website' AND removed_at IS NULL
        ON CONFLICT(asset_id) DO UPDATE SET gateway_version=excluded.gateway_version,last_heartbeat=excluded.last_heartbeat,health_status='healthy'`)
        .run(gatewayVersion,now);
    } catch(error) { logOperational("error","gateway.heartbeat_failed",{code:error.code??error.name??"Error"}); }
  };
  server.on("listening", heartbeat);
  const heartbeatTimer=setInterval(heartbeat,30_000);
  heartbeatTimer.unref();
  const outboxTimer=setInterval(()=>flushGatewayOutbox(db,config).catch(error=>logOperational("error","gateway.outbox_retry_failed",{code:error.code??error.name??"Error"})),config.gatewayOutboxRetryMs??5000);
  outboxTimer.unref();
  server.on("close",()=>{clearInterval(heartbeatTimer);clearInterval(outboxTimer);});
  return server;
}

async function recordUnsupportedUpgrade(req, socket, db, config) {
  const url = new URL(req.url ?? "/", "http://sentrygate.local");
  const match = url.pathname.match(/^\/site\/(\d+)(\/.*)?$/);
  const assetId = match ? Number(match[1]) : 0;
  const asset = assetId ? db.prepare("SELECT id,type FROM assets WHERE id = ? AND removed_at IS NULL").get(assetId) : null;
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
  const asset = db.prepare("SELECT id, name, type, upstream_url AS upstreamUrl FROM assets WHERE id = ? AND removed_at IS NULL").get(assetId);
  if (!asset || asset.type !== "website") return sendText(res, 404, "Protected website not found");
  const rule = db.prepare(`SELECT enabled, mode, failure_mode AS failureMode, rate_limit_count AS rateLimitCount, window_seconds AS windowSeconds,
    sensitive_paths_enabled AS sensitivePathsEnabled FROM gateway_rules WHERE asset_id = ?`).get(assetId)
    ?? { enabled: 1, mode: "observe", failureMode: "open", rateLimitCount: 120, windowSeconds: 60, sensitivePathsEnabled: 1 };
  const sourceIp = observedClientIp(req, trustedProxyList(db));
  const allowlisted = Boolean(db.prepare("SELECT 1 FROM gateway_allowlist WHERE asset_id = ? AND ip = ?").get(assetId, sourceIp));
  expireGatewayActions(db);
  const approvedBlock = !allowlisted && Boolean(db.prepare("SELECT 1 FROM gateway_ip_blocks WHERE asset_id=? AND ip=? AND expires_at>? LIMIT 1").get(assetId, sourceIp, requestTimestamp));
  const isSensitive = Number(rule.enabled) === 1 && Number(rule.sensitivePathsEnabled) === 1 && sensitivePath(sitePath);
  const isRateLimited = Number(rule.enabled) === 1 && !allowlisted && rateExceeded(requestsByClient, assetId, sourceIp, Number(rule.rateLimitCount), Number(rule.windowSeconds));
  const detectionRule = allowlisted ? "allowlist" : approvedBlock ? "approved_block" : isSensitive ? "sensitive_path" : isRateLimited ? "rate_limit" : "none";
  const isDetection = detectionRule !== "none" && detectionRule !== "allowlist";
  let blocked = approvedBlock || (isDetection && rule.mode === "block");
  let action = allowlisted ? "allowlisted" : blocked ? "blocked" : isDetection ? (rule.mode === "challenge-ready" ? "challenge-ready" : "observed") : "forwarded";
  const reason = allowlisted
    ? "Source IP matches this website's allowlist."
    : detectionRule === "approved_block" ? "An administrator-approved temporary SentryGate website block matched this observed source IP."
    : detectionRule === "sensitive_path" ? "Request path matches an enabled sensitive-path rule."
      : detectionRule === "rate_limit" ? `Request exceeded ${rule.rateLimitCount} requests in ${rule.windowSeconds} seconds for this observed source IP.`
        : "No enabled gateway rule matched this request.";

  let eventDeliveryFailed=false;
  if (blocked) {
    const status = detectionRule === "rate_limit" ? 429 : 403;
    try { await postEvent(db, config, buildEvent(req, parsed.pathname, sourceIp, assetId, status, detectionRule, action, reason, requestTimestamp)); }
    catch (error) {
      eventDeliveryFailed=true;
      logOperational("error","gateway.event_delivery_failed",{assetId,mode:rule.failureMode,code:error.code??error.name??"Error"});
      if(rule.failureMode === "closed") return sendText(res,503,"Security event service unavailable; request not forwarded");
      blocked=false; action="forwarded";
    }
    if(blocked) return sendText(res, status, detectionRule === "rate_limit" ? "Rate limit exceeded" : "Request blocked by SentryGate");
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
        if(!eventDeliveryFailed) await postEvent(db, config, event).catch((error) => logOperational("error","gateway.event_delivery_failed",{assetId,code:error.code??error.name??"Error"}));
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
      await postEvent(db, config, buildEvent(req, parsed.pathname, sourceIp, assetId, 502, "upstream_unavailable", "upstream-error", reasonText, requestTimestamp)).catch(error => logOperational("error","gateway.event_delivery_failed",{assetId,code:error.code??error.name??"Error"}));
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
  req.sentryEventId=randomUUID();
  return {
    eventId: req.sentryEventId,
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
  const payload=JSON.stringify(event);
  const existing=db.prepare("SELECT 1 FROM gateway_event_outbox WHERE event_id=?").get(event.eventId);
  if(!existing){
    const capacity=db.prepare("SELECT COUNT(*) AS count,COALESCE(SUM(length(event_json)),0) AS bytes FROM gateway_event_outbox").get();
    if(capacity.count>=(config.gatewayOutboxMaxEvents??100_000)||capacity.bytes+Buffer.byteLength(payload)>(config.gatewayOutboxMaxBytes??268_435_456))throw new Error("Gateway local event outbox reached its configured capacity");
    db.prepare("INSERT INTO gateway_event_outbox(event_id,asset_id,event_json,created_at) VALUES(?,?,?,?)").run(event.eventId,event.assetId,payload,event.timestamp);
  }
  await flushGatewayOutbox(db,config,{limit:25}).catch(()=>{});
}

export async function flushGatewayOutbox(db,config,{limit=25,fetchImpl=fetch,lookupImpl}={}) {
  const rows=db.prepare("SELECT event_id AS eventId,asset_id AS assetId,event_json AS eventJson FROM gateway_event_outbox ORDER BY created_at,event_id LIMIT ?").all(limit);
  if(!rows.length)return {sent:0,pending:0};
  let sent=0;
  for(const row of rows){
    try {
      await resolveLocalEndpoint(new URL(config.apiBaseUrl).hostname,lookupImpl);
      const token=ensureAssetCredential(db,config.sessionSecret,row.assetId);
      const response=await fetchImpl(`${config.apiBaseUrl}/api/agent/events`,{method:"POST",headers:{"Content-Type":"application/json","X-SentryGate-Asset-Credential":token},body:row.eventJson,signal:AbortSignal.timeout(config.eventIngestTimeoutMs??5000)});
      if(!response.ok)throw new Error(`Event ingestion failed: ${response.status}`);
      db.prepare("DELETE FROM gateway_event_outbox WHERE event_id=?").run(row.eventId);sent++;
    }catch(error){
      db.prepare("UPDATE gateway_event_outbox SET attempts=attempts+1,last_error=? WHERE event_id=?").run(String(error.code??error.name??"delivery_failed").slice(0,100),row.eventId);
      break;
    }
  }
  return {sent,pending:db.prepare("SELECT COUNT(*) AS count FROM gateway_event_outbox").get().count};
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
