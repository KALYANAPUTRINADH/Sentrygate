import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { lookup } from "node:dns/promises";
import { recordAudit } from "./audit.js";
import { rotateAgentCredential, rotateAssetCredential, verifyAgentCredential, verifyAssetCredential } from "./agent-credentials.js";
import { hashPassword, signSession, verifyPassword, verifySession } from "./security.js";
import { expireFirewallRules, overlaps, recordHistory, validateFirewallRule } from "./firewall.js";
import { correlateEvent, incidentDetail, makeIncidentPdf } from "./incidents.js";
import { actionForDashboard, evaluateIncidentPolicies, expireGatewayActions, validateActionTarget } from "./actions.js";
import { logOperational } from "./logger.js";
import { databaseBytes } from "./operations.js";
import { generatePilotReport, pilotMetrics } from "./pilot.js";
import { applyAnalysisFeedback, findingForDashboard, readAnalysisSettings } from "./offline-analysis.js";

function cookieName(config) {
  const port = Number(config.port);
  return Number.isInteger(port) && port > 0 && port <= 65535
    ? `sentrygate_session_${port}`
    : "sentrygate_session";
}

export function createServer(db, config) {
  const loginAttempts=new Map();
  const listener=async (req, res) => {
    res.setHeader("X-Content-Type-Options","nosniff");
    res.setHeader("Referrer-Policy","no-referrer");
    res.setHeader("X-Frame-Options","DENY");
    res.setHeader("Content-Security-Policy","default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    if(config.tlsCertPath) res.setHeader("Strict-Transport-Security","max-age=31536000");
    try {
      await route(req, res, db, config, loginAttempts);
    } catch (error) {
      logOperational("error","request.failed",{method:req.method,path:new URL(req.url??"/","http://local").pathname,code:error.code??error.name??"Error"});
      json(res, error.statusCode ?? 500, { error: error.statusCode ? error.message : "Internal server error" });
    }
  };
  if(config.tlsCertPath) return https.createServer({cert:fs.readFileSync(config.tlsCertPath),key:fs.readFileSync(config.tlsKeyPath),minVersion:"TLSv1.2"},listener);
  return http.createServer(listener);
}

async function route(req, res, db, config, loginAttempts) {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if(req.method === "POST" && ["/api/setup","/api/login"].includes(url.pathname) && req.headers.origin){
    try{if(!sameRequestOrigin(req.headers.origin,req))return json(res,403,{error:"Cross-origin authentication request rejected"});}
    catch{return json(res,403,{error:"Invalid request origin"});}
  }

  const deviceReport = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})\/report$/i);
  const deviceConfig = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})\/config$/i);
  if (deviceConfig && req.method === "GET") {
    const device = db.prepare("SELECT * FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(deviceConfig[1]);
    const token = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    if (!device || !safeTokenMatches(token, device.credential_hash)) return json(res, 401, { error: "Valid device credential required" });
    expireFirewallRules(db);
    const rules = db.prepare("SELECT * FROM firewall_rules WHERE device_id=? AND status IN ('approved','active','failed','removing','expired')").all(deviceConfig[1]).map(firewallRuleForAgent);
    const enforcementEnabled = Boolean(db.prepare("SELECT enforcement_enabled FROM firewall_settings WHERE id=1").get().enforcement_enabled);
    let applicationPolicyCommand = null;
    {
      expireApplicationPolicies(db);
      const policies = db.prepare(`SELECT * FROM application_network_policies WHERE device_id=? AND mode IN ('allow','block') AND status IN (${enforcementEnabled ? "'approved','active','removing','expired','failed'" : "'removing','expired'"})`).all(device.device_id).map(applicationPolicyForAgent);
      if (policies.length) {
        const issuedAt = new Date().toISOString(), nonce = crypto.randomUUID(), expiresAt = new Date(Date.now() + 90_000).toISOString();
        db.prepare("DELETE FROM device_command_nonces WHERE expires_at<?").run(issuedAt);
        db.prepare("INSERT INTO device_command_nonces(device_id,nonce,expires_at) VALUES(?,?,?)").run(device.device_id, nonce, expiresAt);
        applicationPolicyCommand = { nonce, issuedAt, expiresAt, policies };
      }
    }
    const update = db.prepare("SELECT version,config_json FROM device_config_updates WHERE device_id=? AND status IN ('pending','failed') ORDER BY version DESC LIMIT 1").get(device.device_id);
    if (update) db.prepare("UPDATE device_config_updates SET status='pending',attempts=attempts+1,last_attempt_at=?,detail='' WHERE device_id=? AND version=?").run(new Date().toISOString(), device.device_id, update.version);
    return json(res, 200, { ...deviceSettingsFor(device), ...(update ? JSON.parse(update.config_json) : {}), configVersion: update?.version ?? device.config_version, firewallRules: rules, applicationPolicyCommand });
  }
  const configAck = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})\/config\/ack$/i);
  if (configAck && req.method === "POST") {
    const deviceId = configAck[1], token = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const device = db.prepare("SELECT * FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(deviceId);
    if (!device || !safeTokenMatches(token, device.credential_hash)) return json(res, 401, { error: "Valid device credential required" });
    const body = await readJson(req);
    if (!Number.isInteger(body.version) || !["applied", "failed"].includes(body.status) || typeof body.detail !== "string" || body.detail.length > 1000) return json(res, 400, { error: "Invalid configuration acknowledgement" });
    const result = db.prepare("UPDATE device_config_updates SET status=?,detail=?,applied_at=CASE WHEN ?='applied' THEN ? ELSE applied_at END WHERE device_id=? AND version=? AND status IN ('pending','failed')")
      .run(body.status, body.detail, body.status, new Date().toISOString(), deviceId, body.version);
    if (result.changes) recordAudit(db, `device:${deviceId}`, `device.config_${body.status}`, `device:${deviceId}`, `Configuration version ${body.version}: ${body.detail || body.status}.`);
    return json(res, 200, { accepted: true, updated: Boolean(result.changes) });
  }
  const firewallState = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})\/firewall\/state$/i);
  if (firewallState && req.method === "POST") {
    const deviceId = firewallState[1], token = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const device = db.prepare("SELECT * FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(deviceId);
    if (!device || !safeTokenMatches(token, device.credential_hash)) return json(res, 401, { error: "Valid device credential required" });
    const body = await readJson(req);
    if (!Array.isArray(body.results) || body.results.length > 500) return json(res, 400, { error: "Firewall results must be an array of at most 500 entries" });
    const stateReceivedAt = new Date().toISOString();
    for (const result of body.results) {
      if (typeof result.id !== "string" || !["active", "removed", "failed", "expired"].includes(result.status) || typeof result.detail !== "string" || result.detail.length > 1000) return json(res, 400, { error: "Invalid firewall state result" });
      const rule = db.prepare("SELECT * FROM firewall_rules WHERE id=? AND device_id=?").get(result.id, deviceId);
      if (!rule) continue;
      const state = JSON.stringify(result.actualState ?? null);
      const status = rule.status === "expired" || rule.status === "removing" ? (result.status === "removed" ? "removed" : result.status === "failed" ? "failed" : rule.status) : result.status;
      db.prepare("UPDATE firewall_rules SET status=?,actual_state=?,failure=?,applied_at=CASE WHEN ?='active' THEN COALESCE(applied_at,?) ELSE applied_at END,rollback_at=CASE WHEN ?='removed' THEN COALESCE(rollback_at,?) ELSE rollback_at END,updated_at=? WHERE id=?")
        .run(status, state, result.status === "failed" ? result.detail : "", result.status, new Date().toISOString(), result.status, new Date().toISOString(), new Date().toISOString(), rule.id);
      if (status !== rule.status || state !== rule.actual_state) {
        const updated = { ...rule, actual_state: state };
        recordHistory(db, updated, `device:${deviceId}`, `agent.${status}`, result.detail || `Agent reports ${status}.`, result.actualState ?? null);
        recordAudit(db, `device:${deviceId}`, `firewall.agent_${status}`, `firewall:${rule.id}`, `${result.detail || `Agent reports ${status}.`} Actual state: ${state.slice(0, 1200)}`);
        const eventResult = db.prepare(`INSERT INTO events (asset_id,source,category,action,reason,evidence,request_details,process_details,severity,detection_rule,device_id,source_event_id,created_at)
          VALUES (?,'windows-firewall','firewall-state',?,?,?,?,?,?,?,?,?,?)`).run(device.asset_id, status, `SentryGate-owned firewall rule ${status}.`,
          `${result.detail || `Agent reports ${status}.`} Rule ${rule.id}: ${rule.protocol} inbound ${rule.remote_cidr} to local port ${rule.local_port}; configured expiry ${rule.expires_at}.`,
          `${rule.protocol} ${rule.remote_cidr}:${rule.local_port}`, state, status === "failed" ? "high" : "info", `firewall_rule_${status}`, deviceId, `firewall:${rule.id}:${status}:${stateReceivedAt}`, stateReceivedAt);
        if (eventResult.changes && rule.incident_id) {
          db.prepare("INSERT OR IGNORE INTO incident_events (incident_id,event_id,linked_at) VALUES (?,?,?)").run(rule.incident_id, Number(eventResult.lastInsertRowid), stateReceivedAt);
          db.prepare("UPDATE incidents SET event_count=(SELECT COUNT(*) FROM incident_events WHERE incident_id=?),last_seen=MAX(last_seen,?),updated_at=? WHERE id=?")
            .run(rule.incident_id, stateReceivedAt, stateReceivedAt, rule.incident_id);
        } else if (eventResult.changes) correlateEvent(db, Number(eventResult.lastInsertRowid));
        if (status === "failed") {
          const prior = db.prepare("SELECT id FROM alerts WHERE device_id=? AND title='SentryGate-owned firewall rule drift' AND status='open' AND evidence LIKE ? LIMIT 1").get(deviceId, `%${rule.id}%`);
          if (!prior) db.prepare(`INSERT INTO alerts(asset_id,title,severity,status,evidence,observed_facts,estimate,event_id,device_id,created_at)
            VALUES(?,?,'high','open',?,?,?,?,?,?)`).run(device.asset_id, "SentryGate-owned firewall rule drift",
            `Agent helper reported that owned rule ${rule.id} failed or differs from the approved state: ${result.detail}`,
            `Observed state: ${state}. Expected SentryGate rule ${rule.protocol} inbound ${rule.remote_cidr} port ${rule.local_port}.`,
            "Only a SentryGate-owned rule was inspected. This report does not imply unrelated firewall rules were changed.", Number(eventResult.lastInsertRowid), deviceId, stateReceivedAt);
        }
        if (rule.action_id) {
          const actionStatus = status === "removed" ? (rule.expires_at <= stateReceivedAt ? "expired" : "rolled_back") : status === "failed" ? "failed" : status === "active" ? "active" : null;
          if (actionStatus) db.prepare("UPDATE proposed_actions SET status=?,failure=?,updated_at=? WHERE id=?").run(actionStatus, status === "failed" ? result.detail : "", stateReceivedAt, rule.action_id);
          if (status === "failed" && (rule.status === "expired" || rule.status === "removing" || rule.expires_at <= stateReceivedAt)) {
            const priorAlert = db.prepare("SELECT 1 FROM alerts WHERE title='Temporary firewall rule removal failed' AND evidence LIKE ? AND status='open' LIMIT 1").get(`%${rule.id}%`);
            if (!priorAlert) db.prepare(`INSERT INTO alerts (asset_id,title,severity,status,evidence,observed_facts,estimate,event_id,device_id,created_at)
              VALUES (?,?,?,?,?,?,?,?,?,?)`).run(device.asset_id, "Temporary firewall rule removal failed", "high", "open",
              `Agent-reported removal failure for SentryGate rule ${rule.id}: ${result.detail}`, "The enrolled agent reported that the SentryGate-owned rule was not successfully removed after expiry or rollback.", "Actual operating-system rule state requires administrator review; no unrelated rules were modified.", Number(eventResult.lastInsertRowid), deviceId, stateReceivedAt);
            recordAudit(db, "system", "action.removal_failed", `action:${rule.action_id}`, `Agent reported failed SentryGate rule removal for firewall rule ${rule.id}: ${result.detail}`);
          }
        }
      }
    }
    return json(res, 200, { accepted: true });
  }
  if (deviceReport && req.method === "POST") {
    const deviceId = deviceReport[1];
    const token = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const device = db.prepare("SELECT * FROM device_agents WHERE device_id = ? AND revoked_at IS NULL AND is_demo = 0").get(deviceId);
    if (!device || !safeTokenMatches(token, device.credential_hash)) return json(res, 401, { error: "Valid device credential required" });
    if(databaseCapacityReached(config))return json(res,507,{error:"Local database storage limit reached; device reporting paused until retention or capacity is addressed"});
    const body = await readJson(req, 10_000_000);
    const invalid = validateDeviceReport(body, deviceId);
    if (invalid) return json(res, 400, { error: invalid });
    const receivedAt = new Date().toISOString();
    const acceptedEventIds = [];
    db.exec("BEGIN");
    try {
      db.prepare(`UPDATE device_agents SET hostname=?,os_version=?,agent_version=?,last_heartbeat=?,health_status=?,health_detail=?,backend_addresses=? WHERE device_id=?`)
        .run(body.device.hostname, body.device.osVersion, body.device.agentVersion, receivedAt, body.healthStatus, (body.collectionErrors ?? []).join("; ").slice(0, 1000), JSON.stringify(body.backendAddresses ?? []), deviceId);
      db.prepare(`INSERT INTO device_snapshots (device_id,captured_at,processes_json,connections_json,applications_json,services_json,startup_entries_json,security_settings_json) VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(device_id) DO UPDATE SET captured_at=excluded.captured_at,processes_json=excluded.processes_json,connections_json=excluded.connections_json,
        applications_json=excluded.applications_json,services_json=excluded.services_json,startup_entries_json=excluded.startup_entries_json,security_settings_json=excluded.security_settings_json`)
        .run(deviceId, body.timestamp, JSON.stringify(body.processes), JSON.stringify(body.connections), JSON.stringify(body.installedApplications ?? []), JSON.stringify(body.services ?? []), JSON.stringify(body.startupEntries ?? []), JSON.stringify(body.securitySettings ?? {}));
      for (const item of body.events) {
        const inserted = db.prepare(`INSERT OR IGNORE INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,
          request_details,process_details,severity,detection_rule,device_id,source_event_id,created_at)
          VALUES (?,'windows-agent',?,?,?,?,?,?,?,?,?,?,?,?)`).run(device.asset_id, item.category, "observed", item.reason,
          JSON.stringify(item.evidence), item.remoteAddress ?? "", item.connectionDetails ?? "", item.processDetails ?? "",
          item.severity, item.rule, deviceId, item.eventId, item.timestamp);
        acceptedEventIds.push(item.eventId);
        if (!inserted.changes) continue;
        db.prepare(`INSERT INTO alerts (title,severity,status,evidence,observed_facts,estimate,event_id,device_id,created_at)
          VALUES (?,?, 'open', ?, ?, ?, ?, ?, ?)`)
          .run(item.title, item.severity, item.reason, JSON.stringify(item.evidence), "Detection rule matched observed process or TCP metadata; no process was terminated and no traffic was blocked.", Number(inserted.lastInsertRowid), deviceId, item.timestamp);
        correlateEvent(db, Number(inserted.lastInsertRowid));
      }
      const cutoff = new Date(Date.now() - device.retained_days * 86_400_000).toISOString();
      db.prepare("DELETE FROM events WHERE device_id=? AND created_at < ?").run(deviceId, cutoff);
      db.prepare("DELETE FROM alerts WHERE device_id=? AND created_at < ?").run(deviceId, cutoff);
      if (body.commandAckNonce) {
        const nonce = db.prepare("SELECT expires_at,consumed_at FROM device_command_nonces WHERE device_id=? AND nonce=?").get(deviceId, body.commandAckNonce);
        if (!nonce || nonce.expires_at < receivedAt) throw Object.assign(new Error("Device command is expired or unknown"), { statusCode: 400 });
        if (!nonce.consumed_at) {
          db.prepare("UPDATE device_command_nonces SET consumed_at=? WHERE device_id=? AND nonce=? AND consumed_at IS NULL").run(receivedAt, deviceId, body.commandAckNonce);
          recordAudit(db, `device:${deviceId}`, "device.command_acknowledged", `device:${deviceId}`, `Authenticated one-time application policy command acknowledgement ${body.commandAckNonce}.`);
        }
      }
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    return json(res, 200, { acceptedEventIds, settings: deviceSettingsFor(device) });
  }

  if (url.pathname === "/api/health" && req.method === "GET") {
    if(!["127.0.0.1","::1","::ffff:127.0.0.1"].includes(req.socket.remoteAddress)&&!currentAdmin(req,db,config))return json(res,401,{error:"Authentication required"});
    db.prepare("SELECT 1 AS ready").get();
    const bytes=databaseBytes(config.dbPath);
    const storage=storageStatus(config,bytes);
    const gatewayOutbox=db.prepare("SELECT COUNT(*) AS pending,COALESCE(SUM(length(event_json)),0) AS queuedBytes FROM gateway_event_outbox").get();
    return json(res, bytes<config.maxDbBytes?200:503, { ok: bytes<config.maxDbBytes, service: "sentrygate-api", database: "ready", gatewayOutbox, ...storage, transport: config.tlsCertPath?"https":"loopback-http-development", remoteAccessEnabled:config.remoteAccessEnabled, standalone:Boolean(config.standalone) });
  }

  if (url.pathname === "/api/session" && req.method === "GET") {
    const admin = currentAdmin(req, db, config);
    return json(res, 200, {
      authenticated: Boolean(admin),
      setupRequired: setupRequired(db),
      admin: admin ? { email: admin.email, role: admin.role } : null
    });
  }

  if (url.pathname === "/api/setup" && req.method === "POST") {
    if (!setupRequired(db)) {
      return json(res, 409, { error: "Administrator already configured" });
    }
    const body = await readJson(req);
    const validation = validateCredentials(body, true);
    if (validation) {
      return json(res, 400, { error: validation });
    }
    const email = body.email.toLowerCase();
    const { salt, hash } = hashPassword(body.password);
    const result = db
      .prepare("INSERT INTO admins (email, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, 'owner', ?)")
      .run(email, hash, salt, new Date().toISOString());
    recordAudit(db, email, "admin.setup", "administrator", "Initial administrator created.");
    setCookie(res, signSession({ id: Number(result.lastInsertRowid), email }, config.sessionSecret), config);
    return json(res, 201, { email });
  }

  if (url.pathname === "/api/login" && req.method === "POST") {
    const body = await readJson(req);
    const validation = validateCredentials(body, false);
    if (validation) {
      return json(res, 400, { error: validation });
    }
    const peer=String(req.socket.remoteAddress??"unknown").replace(/^::ffff:/,""),now=Date.now();
    const throttle=loginAttempts.get(peer);
    if(throttle && throttle.resetAt<=now)loginAttempts.delete(peer);
    const active=loginAttempts.get(peer);
    if(active?.count>=10){res.setHeader("Retry-After",String(Math.max(1,Math.ceil((active.resetAt-now)/1000))));return json(res,429,{error:"Too many failed sign-in attempts; retry after the indicated delay"});}
    const email = body.email.toLowerCase();
    const admin = db.prepare("SELECT id, email, role, password_hash, password_salt FROM admins WHERE email = ?").get(email);
    if (!admin || !verifyPassword(body.password, admin.password_salt, admin.password_hash)) {
      const prior=loginAttempts.get(peer);
      loginAttempts.set(peer,{count:(prior?.count??0)+1,resetAt:prior?.resetAt>now?prior.resetAt:now+15*60_000});
      if(loginAttempts.size>10000)for(const [key,value] of loginAttempts)if(value.resetAt<=now)loginAttempts.delete(key);
      recordAudit(db, email, "admin.login_failed", "administrator", "Failed administrator login.");
      return json(res, 401, { error: "Invalid credentials" });
    }
    loginAttempts.delete(peer);
    recordAudit(db, admin.email, "admin.login", "administrator", "Administrator logged in.");
    setCookie(res, signSession(admin, config.sessionSecret), config);
    return json(res, 200, { email: admin.email, role: admin.role });
  }

  if (url.pathname === "/api/agent/events" && req.method === "POST") {
    if (databaseCapacityReached(config)) return json(res,507,{error:"Local database storage limit reached; ingestion paused until retention or capacity is addressed"});
    const body = await readJson(req);
    const siteToken = req.headers["x-sentrygate-asset-credential"];
    const token = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1];
    if (siteToken !== undefined ? !verifyAssetCredential(db, body?.assetId, siteToken) : !verifyAgentCredential(db, token)) return json(res, 401, { error: "Valid credential for this asset required" });
    const invalidEvent = validateGatewayEvent(body);
    if (invalidEvent) return json(res, 400, { error: invalidEvent });
    if (!db.prepare("SELECT 1 FROM assets WHERE id = ?").get(body.assetId)) return json(res, 400, { error: "Event asset does not exist" });
    const evidence = `${body.sourceIp} observed ${body.method} ${body.path}; upstream response ${body.responseStatus}; rule ${body.detectionRule}; action ${body.action}.`;
    let duplicate = false;
    db.exec("BEGIN");
    try {
      const sourceEventId = body.eventId ?? crypto.randomUUID();
      const inserted = db.prepare(`INSERT OR IGNORE INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,
        request_details,severity,method,request_path,user_agent,response_status,detection_rule,source_event_id,created_at)
        VALUES (?, 'website-gateway', 'http-request', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(body.assetId, body.action, body.reason, evidence, body.sourceIp, `${body.method} ${body.path}`,
          body.severity, body.method, body.path, body.userAgent, body.responseStatus, body.detectionRule, sourceEventId, body.timestamp);
      duplicate = !inserted.changes;
      if (inserted.changes && body.detectionRule !== "none" && body.detectionRule !== "allowlist") {
        db.prepare(`INSERT INTO alerts (asset_id,event_id,title,severity,status,evidence,observed_facts,estimate,created_at)
          VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)`)
          .run(body.assetId, Number(inserted.lastInsertRowid), alertTitle(body.detectionRule), body.severity, evidence,
            `Matched rule ${body.detectionRule}: ${body.reason}`, "Rule match indicates a request pattern, not who sent it.", body.timestamp);
      }
      if (inserted.changes) correlateEvent(db, Number(inserted.lastInsertRowid));
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    return json(res, duplicate ? 200 : 201, { accepted: true, duplicate });
  }

  if (url.pathname === "/api/application/events" && req.method === "POST") {
    if (databaseCapacityReached(config)) return json(res,507,{error:"Local database storage limit reached; ingestion paused until retention or capacity is addressed"});
    const token = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    if (!verifyAgentCredential(db, token)) return json(res, 401, { error: "Valid event-ingestion credential required" });
    const body = await readJson(req);
    const asset = Number.isInteger(body?.assetId) ? db.prepare("SELECT id FROM assets WHERE id=?").get(body.assetId) : null;
    if (!asset || typeof body.eventId !== "string" || body.eventId.length < 8 || body.eventId.length > 120 || !validDate(body.timestamp) || typeof body.sourceIp !== "string" || !net.isIP(body.sourceIp) || typeof body.rule !== "string" || !/^[a-zA-Z0-9_.:-]{1,100}$/.test(body.rule) || !["low", "medium", "high", "critical"].includes(body.severity) || !["observed", "recorded", "blocked", "allowed"].includes(body.action) || typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 2000 || typeof body.evidence !== "string" || !body.evidence.trim() || body.evidence.length > 5000 || (body.requestDetails !== undefined && (typeof body.requestDetails !== "string" || body.requestDetails.length > 2048))) return json(res, 400, { error: "Invalid application event; asset, source IP, rule, severity, action, evidence and stable event ID are required" });
    const inserted = db.prepare(`INSERT OR IGNORE INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,request_details,severity,detection_rule,source_event_id,created_at)
      VALUES (?,'application',?,?,?,?,?,?,?,?,?,?)`).run(body.assetId, typeof body.category === "string" ? body.category.slice(0, 100) : "application-event", body.action, body.reason, body.evidence, body.sourceIp, body.requestDetails ?? "", body.severity, body.rule, body.eventId, body.timestamp);
    if (inserted.changes) correlateEvent(db, Number(inserted.lastInsertRowid));
    return json(res, inserted.changes ? 201 : 200, { accepted: true, duplicate: !inserted.changes });
  }

  const applicationPolicyState = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})\/application-policy-state$/i);
  if (applicationPolicyState && req.method === "POST") {
    const deviceId = applicationPolicyState[1], token = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const device = db.prepare("SELECT * FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(deviceId);
    if (!device || !safeTokenMatches(token, device.credential_hash)) return json(res, 401, { error: "Valid device credential required" });
    const body = await readJson(req);
    if (!Array.isArray(body.results) || body.results.length > 100 || body.results.some((r) => typeof r.id !== "string" || !["active", "removed", "failed"].includes(r.status) || typeof r.detail !== "string" || r.detail.length > 1000)) return json(res, 400, { error: "Invalid application policy state report" });
    for (const result of body.results) {
      const policy = db.prepare("SELECT * FROM application_network_policies WHERE id=? AND device_id=?").get(result.id, deviceId);
      if (!policy) continue;
      const status = result.status === "active" && policy.status === "removing" ? "removing" : result.status;
      const actualState = JSON.stringify(result.actualState ?? null);
      const stateChanged = policy.status !== status || (policy.actual_state ?? "null") !== actualState || (policy.failure ?? "") !== (status === "failed" ? result.detail : "");
      if (!stateChanged) continue;
      db.prepare("UPDATE application_network_policies SET status=?,actual_state=?,failure=?,updated_at=? WHERE id=?").run(status, actualState, status === "failed" ? result.detail : "", new Date().toISOString(), policy.id);
      if (["failed", "active", "removed"].includes(status)) recordAudit(db, `device:${deviceId}`, `firewall.application_policy_${status}`, `application-policy:${policy.id}`, `${result.detail || status}; observed state ${JSON.stringify(result.actualState ?? null).slice(0, 800)}.`);
      if (status === "failed") {
        const eventId = crypto.randomUUID(), createdAt = new Date().toISOString();
        db.prepare(`INSERT INTO events(asset_id,source,category,action,reason,evidence,process_details,severity,detection_rule,device_id,source_event_id,created_at)
          VALUES(?,'windows-firewall','application-policy','observed',?,?,?,?,?,?,?,?)`).run(device.asset_id, result.detail, actualState, policy.program_path, "high", "sentrygate_application_rule_changed", deviceId, `app-policy-state:${policy.id}:${createdAt}`, createdAt);
        const prior = db.prepare("SELECT 1 FROM alerts WHERE device_id=? AND title='SentryGate application firewall rule changed' AND status='open' AND evidence LIKE ? LIMIT 1").get(deviceId, `%${policy.id}%`);
        if (!prior) db.prepare(`INSERT INTO alerts(asset_id,title,severity,status,evidence,observed_facts,estimate,device_id,created_at)
          VALUES(?,'SentryGate application firewall rule changed','high','open',?,?,?,?,?)`).run(device.asset_id, `${result.detail} Policy ${policy.id}.`, "The SentryGate firewall helper reported a drift or failed operation for a SentryGate-owned rule.", "Actual firewall state requires administrator review; unrelated firewall rules were not changed.", deviceId, createdAt);
      }
    }
    return json(res, 200, { accepted: true });
  }

  const admin = url.pathname.startsWith("/api/") ? currentAdmin(req, db, config) : null;
  if (url.pathname.startsWith("/api/") && !admin) {
    return json(res, 401, { error: "Authentication required" });
  }
  if (url.pathname.startsWith("/api/") && admin && !["GET","HEAD"].includes(req.method)) {
    const origin=req.headers.origin;
    if(origin){try{if(!sameRequestOrigin(origin,req))return json(res,403,{error:"Cross-origin administrator request rejected"});}catch{return json(res,403,{error:"Invalid request origin"});}}
  }
  if (url.pathname.startsWith("/api/") && admin.role !== "owner") {
    const analystWrite = admin.role === "security_analyst" && ((req.method === "POST" && /^\/api\/incidents\/[a-f0-9-]+\/notes$/.test(url.pathname)) || (req.method === "PATCH" && /^\/api\/incidents\/[a-f0-9-]+\/status$/.test(url.pathname)) || (req.method === "POST" && url.pathname === "/api/action-policies") || (req.method === "POST" && ["/api/firewall/rules", "/api/application-policies/preview"].includes(url.pathname)) || (req.method === "POST" && /^\/api\/events\/\d+\/false-positive$/.test(url.pathname)) || (req.method === "POST" && /^\/api\/alerts\/\d+\/respond$/.test(url.pathname)) || (req.method === "POST" && /^\/api\/analysis\/findings\/[a-f0-9-]+\/feedback$/i.test(url.pathname)));
    if (!(["GET", "HEAD"].includes(req.method)) && !analystWrite) return json(res, 403, { error: "This administrator role cannot perform that action" });
  }

  if (url.pathname === "/api/storage" && req.method === "GET") {
    const bytes=databaseBytes(config.dbPath);
    return json(res,200,{...storageStatus(config,bytes),remoteAccessEnabled:config.remoteAccessEnabled});
  }

  if (url.pathname === "/api/firewall/enforcement" && req.method === "GET") {
    const setting = db.prepare("SELECT enforcement_enabled AS enabled,updated_at AS updatedAt FROM firewall_settings WHERE id=1").get();
    return json(res, 200, { ...setting, enabled: Boolean(setting.enabled), automaticBlockingEnabled: false });
  }
  if (url.pathname === "/api/firewall/enforcement" && req.method === "PUT") {
    const body = await readJson(req);
    if (typeof body.enabled !== "boolean" || body.enabled && body.confirmed !== true) return json(res, 400, { error: "An explicit confirmed boolean is required to change application policy enforcement" });
    const now = new Date().toISOString();
    db.prepare("UPDATE firewall_settings SET enforcement_enabled=?,updated_at=? WHERE id=1").run(Number(body.enabled), now);
    if (!body.enabled) db.prepare("UPDATE application_network_policies SET status='removing',rollback_at=?,updated_at=? WHERE status IN ('approved','active','failed') AND mode IN ('allow','block')").run(now, now);
    recordAudit(db, admin.email, body.enabled ? "firewall.application_enforcement_enabled" : "firewall.application_enforcement_disabled", "firewall:application-enforcement", body.enabled ? "Enabled explicitly approved per-application policies; automatic blocking remains disabled." : "Disabled application policy enforcement and queued removal of all active SentryGate application rules.");
    return json(res, 200, { enabled: body.enabled, updatedAt: now });
  }
  if (url.pathname === "/api/application-policies" && req.method === "GET") {
    expireApplicationPolicies(db);
    return json(res, 200, db.prepare(`SELECT p.*,d.name AS device_name FROM application_network_policies p JOIN device_agents d USING(device_id)
      ORDER BY CASE p.status WHEN 'proposed' THEN 0 WHEN 'failed' THEN 1 ELSE 2 END,p.created_at DESC LIMIT 500`).all().map(applicationPolicyForDashboard));
  }
  if (url.pathname === "/api/application-policies/preview" && req.method === "POST") {
    const body = await readJson(req), invalid = validateApplicationPolicy(body, db);
    if (invalid) return json(res, 400, { error: invalid });
    const existing = db.prepare("SELECT * FROM application_network_policies WHERE idempotency_key=?").get(body.idempotencyKey);
    if (existing) {
      if (existing.device_id !== body.deviceId || existing.program_path.toLowerCase() !== body.programPath.toLowerCase() || existing.mode !== body.mode || existing.expires_at !== body.expiresAt || existing.reason !== body.reason.trim() || existing.evidence !== body.evidence.trim()) return json(res, 409, { error: "Idempotency key was already used for a different application policy" });
      return json(res, 200, { policy: applicationPolicyForDashboard(existing), preview: JSON.parse(existing.preview_json) });
    }
    const device = db.prepare("SELECT device_id,is_demo,os_version FROM device_agents WHERE device_id=? AND revoked_at IS NULL").get(body.deviceId);
    if (!device || device.is_demo) return json(res, 404, { error: "A non-demo enrolled device is required" });
    if (!/windows/i.test(device.os_version)) return json(res, 400, { error: "Per-application firewall rules are currently supported only for enrolled Windows devices" });
    const snapshot = db.prepare("SELECT processes_json FROM device_snapshots WHERE device_id=?").get(body.deviceId);
    const observed = snapshot ? JSON.parse(snapshot.processes_json).find((process) => typeof process.executablePath === "string" && process.executablePath.toLowerCase() === body.programPath.toLowerCase()) : null;
    if (!observed) return json(res, 400, { error: "Select an executable path observed in this device's latest process inventory" });
    const preview = { deviceId: body.deviceId, applicationName: body.applicationName.trim(), programPath: observed.executablePath, mode: body.mode,
      expectedEffect: body.mode === "review" ? "Record a reviewed policy without changing Windows Firewall." : `${body.mode === "block" ? "Block" : "Allow"} inbound network access for this executable only.`,
      expiresAt: body.expiresAt, reason: body.reason.trim(), evidence: body.evidence.trim(), firewallChange: body.mode !== "review", requiresEnforcementEnabled: body.mode !== "review" };
    const id = crypto.randomUUID(), now = new Date().toISOString();
    db.prepare(`INSERT INTO application_network_policies(id,device_id,application_name,program_path,mode,reason,evidence,expires_at,status,idempotency_key,preview_json,created_by,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?, 'proposed',?,?,?,?,?)`).run(id, body.deviceId, body.applicationName.trim(), observed.executablePath, body.mode, body.reason.trim(), body.evidence.trim(), body.expiresAt, body.idempotencyKey, JSON.stringify(preview), admin.email, now, now);
    recordAudit(db, admin.email, "firewall.application_policy_previewed", `application-policy:${id}`, `Previewed ${body.mode} policy for ${body.applicationName.trim()} on device ${body.deviceId}; no firewall changes were made.`);
    return json(res, 201, { policy: applicationPolicyForDashboard(db.prepare("SELECT * FROM application_network_policies WHERE id=?").get(id)), preview });
  }
  const appPolicyAction = url.pathname.match(/^\/api\/application-policies\/([a-f0-9-]{36})\/(approve|rollback)$/i);
  if (appPolicyAction && req.method === "POST") {
    const [, id, action] = appPolicyAction, body = await readJson(req);
    const policy = db.prepare("SELECT * FROM application_network_policies WHERE id=?").get(id);
    if (!policy) return json(res, 404, { error: "Application policy not found" });
    if (body.confirmed !== true) return json(res, 400, { error: "Explicit administrator confirmation is required" });
    const now = new Date().toISOString();
    if (action === "approve") {
      if (policy.status === "approved" || policy.status === "active") return json(res, 200, applicationPolicyForDashboard(policy));
      if (policy.status !== "proposed" || policy.expires_at <= now) return json(res, 409, { error: "Only an unexpired proposed policy can be approved" });
      if (policy.mode !== "review" && !db.prepare("SELECT enforcement_enabled FROM firewall_settings WHERE id=1").get().enforcement_enabled) return json(res, 409, { error: "Application policy enforcement is preview-only. An owner must explicitly enable it first." });
      const status = policy.mode === "review" ? "review" : "approved";
      db.prepare("UPDATE application_network_policies SET status=?,approved_by=?,approved_at=?,updated_at=? WHERE id=?").run(status, admin.email, now, now, id);
      recordAudit(db, admin.email, "firewall.application_policy_approved", `application-policy:${id}`, `Approved ${policy.mode} policy for ${policy.application_name} on ${policy.device_id}; ${policy.mode === "review" ? "no firewall operation" : "authenticated device helper sync pending"}.`);
    } else {
      if (["removed", "review", "proposed"].includes(policy.status)) return json(res, 200, applicationPolicyForDashboard(policy));
      db.prepare("UPDATE application_network_policies SET status='removing',rollback_at=?,updated_at=? WHERE id=?").run(now, now, id);
      recordAudit(db, admin.email, "firewall.application_policy_rollback_requested", `application-policy:${id}`, `Queued removal of SentryGate-owned policy ${id}; removal confirmation depends on the enrolled agent helper.`);
    }
    return json(res, 200, applicationPolicyForDashboard(db.prepare("SELECT * FROM application_network_policies WHERE id=?").get(id)));
  }
  if (url.pathname === "/api/analysis/settings" && req.method === "GET") {
    const settings = readAnalysisSettings(db);
    const state = db.prepare("SELECT cursor_event_id AS cursorEventId,last_run_at AS lastRunAt,last_error AS lastError,processed_total AS processedTotal FROM local_analysis_state WHERE id=1").get();
    const findings = db.prepare("SELECT COUNT(*) AS count FROM local_analysis_findings").get().count;
    return json(res, 200, { settings, state, findings });
  }
  if (url.pathname === "/api/analysis/settings" && req.method === "PUT") {
    const body = await readJson(req);
    if (typeof body.enabled !== "boolean" || !Number.isInteger(body.batchSize) || body.batchSize < 1 || body.batchSize > 500 || !Number.isInteger(body.pollIntervalMs) || body.pollIntervalMs < 250 || body.pollIntervalMs > 60000 || !Number.isInteger(body.findingRetainedDays) || body.findingRetainedDays < 1 || body.findingRetainedDays > 3650 || !Number.isInteger(body.sensitiveThreshold) || body.sensitiveThreshold < 2 || body.sensitiveThreshold > 100 || !Number.isInteger(body.sensitiveWindowMinutes) || body.sensitiveWindowMinutes < 1 || body.sensitiveWindowMinutes > 1440 || !Number.isInteger(body.requestRateThreshold) || body.requestRateThreshold < 5 || body.requestRateThreshold > 100000 || !Number.isInteger(body.requestWindowSeconds) || body.requestWindowSeconds < 10 || body.requestWindowSeconds > 3600 || !Number.isInteger(body.baselineDays) || body.baselineDays < 1 || body.baselineDays > 90 || !Number.isFinite(body.rateSigma) || body.rateSigma < 1 || body.rateSigma > 10 || !Number.isInteger(body.connectionThreshold) || body.connectionThreshold < 5 || body.connectionThreshold > 100000) return json(res, 400, { error: "Invalid analysis settings; values must be within the displayed bounds" });
    const now = new Date().toISOString();
    db.prepare(`UPDATE local_analysis_settings SET enabled=?,batch_size=?,poll_interval_ms=?,finding_retained_days=?,sensitive_threshold=?,sensitive_window_minutes=?,request_rate_threshold=?,request_window_seconds=?,baseline_days=?,rate_sigma=?,connection_threshold=?,updated_at=? WHERE id=1`)
      .run(Number(body.enabled), body.batchSize, body.pollIntervalMs, body.findingRetainedDays, body.sensitiveThreshold, body.sensitiveWindowMinutes, body.requestRateThreshold, body.requestWindowSeconds, body.baselineDays, body.rateSigma, body.connectionThreshold, now);
    recordAudit(db, admin.email, "analysis.settings_updated", "offline-analysis", `Analysis ${body.enabled ? "enabled" : "disabled"}; batch ${body.batchSize}; retention ${body.findingRetainedDays} days; thresholds sensitive=${body.sensitiveThreshold}, request=${body.requestRateThreshold}, connections=${body.connectionThreshold}.`);
    return json(res, 200, { saved: true });
  }
  if (url.pathname === "/api/analysis/findings" && req.method === "GET") {
    const category = url.searchParams.get("category"), feedback = url.searchParams.get("feedback"), severity = url.searchParams.get("severity");
    const clauses = [], values = [];
    if (category && ["sensitive_path", "request_rate", "connection_pattern"].includes(category)) { clauses.push("category=?"); values.push(category); }
    if (feedback && ["useful", "false_positive", "unreviewed"].includes(feedback)) { clauses.push(feedback === "unreviewed" ? "feedback IS NULL" : "feedback=?"); if (feedback !== "unreviewed") values.push(feedback); }
    if (severity && ["low", "medium", "high"].includes(severity)) { clauses.push("severity=?"); values.push(severity); }
    if (url.searchParams.has("assetId") && /^\d+$/.test(url.searchParams.get("assetId"))) { clauses.push("asset_id=?"); values.push(Number(url.searchParams.get("assetId"))); }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = db.prepare(`SELECT * FROM local_analysis_findings ${where} ORDER BY created_at DESC LIMIT 200`).all(...values);
    return json(res, 200, rows.map(findingForDashboard));
  }
  const findingFeedback = url.pathname.match(/^\/api\/analysis\/findings\/([a-f0-9-]{36})\/feedback$/i);
  if (findingFeedback && req.method === "POST") {
    const body = await readJson(req);
    if (!["useful", "false_positive"].includes(body.feedback)) return json(res, 400, { error: "feedback must be useful or false_positive" });
    const finding = db.prepare("SELECT id,category FROM local_analysis_findings WHERE id=?").get(findingFeedback[1]);
    if (!finding) return json(res, 404, { error: "Analysis finding not found" });
    const now = new Date().toISOString();
    db.prepare("UPDATE local_analysis_findings SET feedback=?,reviewed_by=?,reviewed_at=? WHERE id=?").run(body.feedback, admin.email, now, finding.id);
    const tuning = applyAnalysisFeedback(db, finding.category, now);
    recordAudit(db, admin.email, "analysis.feedback_recorded", `analysis-finding:${finding.id}`, `Marked ${finding.category} finding ${body.feedback}; effective threshold multiplier ${tuning.multiplier} from ${tuning.useful} useful and ${tuning.falsePositive} false-positive reviews.`);
    return json(res, 200, { findingId: finding.id, feedback: body.feedback, tuning });
  }

  if (url.pathname === "/api/actions/settings" && req.method === "GET") {
    const setting = db.prepare("SELECT emergency_paused AS emergencyPaused,enforce_enabled AS enforcementEnabled,max_active_blocks AS maxActiveBlocks,updated_at AS updatedAt FROM action_settings WHERE id=1").get();
    return json(res, 200, { ...setting, automaticBlockingEnabled: Boolean(setting.enforcementEnabled) });
  }
  if (url.pathname === "/api/actions/settings" && req.method === "PUT") {
    const body = await readJson(req);
    if (body.emergencyPaused !== undefined && typeof body.emergencyPaused !== "boolean") return json(res, 400, { error: "emergencyPaused must be a boolean" });
    if (body.enforcementEnabled !== undefined && (typeof body.enforcementEnabled !== "boolean" || body.confirmed !== true)) return json(res, 400, { error: "Changing Enforce requires a boolean value and explicit confirmation" });
    if (body.maxActiveBlocks !== undefined && (!Number.isInteger(body.maxActiveBlocks) || body.maxActiveBlocks < 1 || body.maxActiveBlocks > 50)) return json(res, 400, { error: "maxActiveBlocks must be from 1 to 50" });
    const now = new Date().toISOString();
    const old = db.prepare("SELECT emergency_paused,enforce_enabled,max_active_blocks FROM action_settings WHERE id=1").get();
    const emergencyPaused = body.emergencyPaused ?? Boolean(old.emergency_paused), enforcementEnabled = body.enforcementEnabled ?? Boolean(old.enforce_enabled), maxActiveBlocks = body.maxActiveBlocks ?? old.max_active_blocks;
    db.prepare("UPDATE action_settings SET emergency_paused=?,enforce_enabled=?,max_active_blocks=?,updated_at=? WHERE id=1").run(Number(emergencyPaused), Number(enforcementEnabled), maxActiveBlocks, now);
    if (body.emergencyPaused !== undefined) recordAudit(db, admin.email, body.emergencyPaused ? "action.emergency_paused" : "action.emergency_resumed", "actions:settings", body.emergencyPaused ? "Paused future proposals and automatic policy actions; existing temporary rules were not changed." : "Resumed policy evaluation.");
    if (body.enforcementEnabled !== undefined && enforcementEnabled !== Boolean(old.enforce_enabled)) recordAudit(db, admin.email, enforcementEnabled ? "action.enforce_enabled" : "action.enforce_disabled", "actions:settings", `${enforcementEnabled ? "Enabled" : "Disabled"} automatic actions only for individually enabled Enforce policies. Existing temporary rules were not changed.`);
    if (body.maxActiveBlocks !== undefined && maxActiveBlocks !== old.max_active_blocks) recordAudit(db, admin.email, "action.block_limit_updated", "actions:settings", `Changed global active temporary block limit from ${old.max_active_blocks} to ${maxActiveBlocks}.`);
    if (!emergencyPaused) {
      for (const incident of db.prepare("SELECT id FROM incidents WHERE status IN ('open','investigating')").all()) evaluateIncidentPolicies(db, incident.id);
    }
    return json(res, 200, { emergencyPaused, enforcementEnabled, maxActiveBlocks, automaticBlockingEnabled: enforcementEnabled, updatedAt: now });
  }
  if (url.pathname === "/api/action-policies" && req.method === "GET") {
    return json(res, 200, db.prepare("SELECT p.*,a.name AS asset_name FROM action_policies p JOIN assets a ON a.id=p.asset_id ORDER BY p.created_at DESC").all().map(actionPolicyForDashboard));
  }
  if (url.pathname === "/api/action-policies" && req.method === "POST") {
    const body = await readJson(req), invalid = validateActionPolicy(body, db);
    if (invalid) return json(res, 400, { error: invalid });
    const id = crypto.randomUUID(), now = new Date().toISOString();
    const mode = body.mode ?? "observe";
    if (mode === "enforce" && admin.role !== "owner") return json(res, 403, { error: "Only an owner can create an Enforce policy" });
    db.prepare(`INSERT INTO action_policies (id,name,enabled,mode,asset_id,detection_rule,minimum_severity,minimum_event_count,window_minutes,target_type,target_id,protocol,local_port,duration_minutes,created_by,created_at,updated_at)
      VALUES (?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, body.name.trim(), mode, body.assetId, body.detectionRule || "*", body.minimumSeverity, body.minimumEventCount, body.windowMinutes, body.targetType, String(body.targetId), body.targetType === "device" ? body.protocol : "TCP", body.targetType === "device" ? body.localPort : 443, body.durationMinutes, admin.email, now, now);
    recordAudit(db, admin.email, "action.policy_created", `policy:${id}`, `Created ${mode} policy ${body.name.trim()} for asset ${body.assetId}; global Enforce remains independently controlled.`);
    const incidents = db.prepare("SELECT id FROM incidents WHERE asset_id=? AND status IN ('open','investigating')").all(body.assetId);
    for (const incident of incidents) evaluateIncidentPolicies(db, incident.id);
    return json(res, 201, actionPolicyForDashboard(db.prepare("SELECT p.*,a.name AS asset_name FROM action_policies p JOIN assets a ON a.id=p.asset_id WHERE p.id=?").get(id)));
  }
  const policyMatch = url.pathname.match(/^\/api\/action-policies\/([0-9a-f-]{36})$/i);
  if (policyMatch && req.method === "PATCH") {
    const body = await readJson(req), policy = db.prepare("SELECT * FROM action_policies WHERE id=?").get(policyMatch[1]);
    if (!policy) return json(res, 404, { error: "Action policy not found" });
    if (body.enabled !== undefined && typeof body.enabled !== "boolean") return json(res, 400, { error: "enabled must be a boolean" });
    if (body.mode !== undefined && !["observe", "recommend", "enforce"].includes(body.mode)) return json(res, 400, { error: "mode must be observe, recommend, or enforce" });
    if (body.mode === "enforce" && admin.role !== "owner") return json(res, 403, { error: "Only an owner can configure an Enforce policy" });
    if (body.enabled === undefined && body.mode === undefined) return json(res, 400, { error: "Provide enabled or mode" });
    const now = new Date().toISOString();
    const enabled = body.enabled ?? Boolean(policy.enabled), mode = body.mode ?? policy.mode;
    db.prepare("INSERT INTO action_policy_history(policy_id,actor,previous_json,changed_at) VALUES(?,?,?,?)")
      .run(policy.id, admin.email, JSON.stringify({ enabled: Boolean(policy.enabled), mode: policy.mode }), now);
    db.prepare("UPDATE action_policies SET enabled=?,mode=?,updated_at=? WHERE id=?").run(Number(enabled), mode, now, policy.id);
    recordAudit(db, admin.email, "action.policy_updated", `policy:${policy.id}`, `Updated ${policy.name}: ${policy.mode} → ${mode}; enabled ${enabled}. Previous policy state remains in audit history.`);
    if (enabled && mode !== "observe") for (const incident of db.prepare("SELECT id FROM incidents WHERE asset_id=? AND status IN ('open','investigating')").all(policy.asset_id)) evaluateIncidentPolicies(db, incident.id);
    return json(res, 200, actionPolicyForDashboard(db.prepare("SELECT p.*,a.name AS asset_name FROM action_policies p JOIN assets a ON a.id=p.asset_id WHERE p.id=?").get(policy.id)));
  }
  const restorePolicy = url.pathname.match(/^\/api\/action-policies\/([0-9a-f-]{36})\/restore$/i);
  if (restorePolicy && req.method === "POST") {
    if (admin.role !== "owner") return json(res, 403, { error: "Only an owner can restore policy settings" });
    const policy = db.prepare("SELECT * FROM action_policies WHERE id=?").get(restorePolicy[1]);
    if (!policy) return json(res, 404, { error: "Action policy not found" });
    const previous = db.prepare("SELECT id,previous_json FROM action_policy_history WHERE policy_id=? ORDER BY id DESC LIMIT 1").get(policy.id);
    if (!previous) return json(res, 409, { error: "No prior policy version is available to restore" });
    const prior = JSON.parse(previous.previous_json), now = new Date().toISOString();
    db.prepare("INSERT INTO action_policy_history(policy_id,actor,previous_json,changed_at) VALUES(?,?,?,?)")
      .run(policy.id, admin.email, JSON.stringify({ enabled: Boolean(policy.enabled), mode: policy.mode }), now);
    db.prepare("UPDATE action_policies SET enabled=?,mode=?,updated_at=? WHERE id=?").run(Number(prior.enabled), prior.mode, now, policy.id);
    db.prepare("DELETE FROM action_policy_history WHERE id=?").run(previous.id);
    recordAudit(db, admin.email, "action.policy_restored", `policy:${policy.id}`, `Restored previous ${prior.mode} policy state (enabled=${prior.enabled}) for ${policy.name}.`);
    if (prior.enabled && prior.mode !== "observe") for (const incident of db.prepare("SELECT id FROM incidents WHERE asset_id=? AND status IN ('open','investigating')").all(policy.asset_id)) evaluateIncidentPolicies(db, incident.id);
    return json(res, 200, actionPolicyForDashboard(db.prepare("SELECT p.*,a.name AS asset_name FROM action_policies p JOIN assets a ON a.id=p.asset_id WHERE p.id=?").get(policy.id)));
  }
  if (url.pathname === "/api/actions" && req.method === "GET") {
    expireFirewallRules(db);
    expireGatewayActions(db);
    const stateFilter = url.searchParams.get("status");
    const validStatuses = ["proposed", "approved", "active", "expired", "rollback-pending", "rolled_back", "failed"];
    const rows = db.prepare(`SELECT * FROM proposed_actions ${validStatuses.includes(stateFilter) ? "WHERE status=?" : ""} ORDER BY created_at DESC LIMIT 500`).all(...(validStatuses.includes(stateFilter) ? [stateFilter] : []));
    return json(res, 200, rows.map((row) => actionForDashboard(db, row)));
  }
  const actionMatch = url.pathname.match(/^\/api\/actions\/([0-9a-f-]{36})\/(approve|rollback)$/i);
  if (actionMatch && req.method === "POST") {
    const [, actionId, operation] = actionMatch, body = await readJson(req);
    if (body.confirmed !== true) return json(res, 400, { error: "Explicit administrator confirmation is required" });
    const action = db.prepare("SELECT * FROM proposed_actions WHERE id=?").get(actionId);
    if (!action) return json(res, 404, { error: "Proposed action not found" });
    if (operation === "approve") {
      if (action.status !== "proposed") return ["approved", "active"].includes(action.status) ? json(res, 200, actionForDashboard(db, action)) : json(res, 409, { error: `Action is ${action.status} and cannot be approved` });
      const paused = db.prepare("SELECT emergency_paused FROM action_settings WHERE id=1").get().emergency_paused;
      if (paused) return json(res, 409, { error: "Emergency pause is active; action approval is disabled" });
      if (Date.parse(action.expires_at) <= Date.now()) return json(res, 409, { error: "Proposed action has expired; create a fresh proposal" });
      const device = action.target_type === "device" ? db.prepare("SELECT * FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(action.target_id) : null;
      const incidentAsset = db.prepare("SELECT asset_id FROM incidents WHERE id=?").get(action.incident_id)?.asset_id;
      if (action.target_type === "device" && (!device || Number(device.asset_id) !== Number(incidentAsset))) return json(res, 409, { error: "Action destination device no longer matches the incident asset" });
      if (action.target_type === "website" && Number(action.target_id) !== Number(incidentAsset)) return json(res, 409, { error: "Action destination website does not match the incident asset" });
      const unsafe = validateActionTarget(db, action, device ? JSON.parse(device.backend_addresses ?? "[]") : []);
      if (unsafe) return json(res, 400, { error: unsafe });
      const now = new Date().toISOString();
      if (action.target_type === "website") {
        const asset = db.prepare("SELECT id FROM assets WHERE id=? AND type='website' AND removed_at IS NULL").get(Number(action.target_id));
        if (!asset || db.prepare("SELECT 1 FROM gateway_allowlist WHERE asset_id=? AND ip=?").get(asset.id, action.target_address)) return json(res, 400, { error: "Website target is unavailable or the source is now allowlisted" });
        const existingBlock = db.prepare("SELECT action_id FROM gateway_ip_blocks WHERE asset_id=? AND ip=? AND expires_at>? LIMIT 1").get(asset.id, action.target_address, now);
        if (existingBlock) return json(res, 409, { error: `This website already has an active SentryGate block from action ${existingBlock.action_id}` });
        db.prepare("INSERT INTO gateway_ip_blocks (action_id,asset_id,ip,expires_at,created_at) VALUES (?,?,?,?,?)").run(action.id, asset.id, action.target_address, action.expires_at, now);
        db.prepare("UPDATE proposed_actions SET status='active',approved_by=?,approved_at=?,updated_at=? WHERE id=? AND status='proposed'").run(admin.email, now, now, action.id);
        recordAudit(db, admin.email, "action.approved", `action:${action.id}`, `Approved and activated temporary gateway block ${action.target_address} for website ${asset.id} until ${action.expires_at}.`);
      } else {
        if (!device) return json(res, 400, { error: "Destination device is unavailable" });
        let backendAddresses = [];
        try { const host = new URL(config.apiBaseUrl).hostname.replace(/^\[|\]$/g, ""); backendAddresses = net.isIP(host) ? [host] : (await lookup(host, { all: true })).map((entry) => entry.address); }
        catch { return json(res, 400, { error: "Could not resolve the API backend address; refusing the rule" }); }
        const latestAction = db.prepare("SELECT * FROM proposed_actions WHERE id=?").get(action.id);
        if (db.prepare("SELECT emergency_paused FROM action_settings WHERE id=1").get().emergency_paused) return json(res, 409, { error: "Emergency pause became active before approval completed" });
        if (latestAction.status !== "proposed") return ["approved", "active"].includes(latestAction.status) ? json(res, 200, actionForDashboard(db, latestAction)) : json(res, 409, { error: `Action is ${latestAction.status} and cannot be approved` });
        const latestDevice = db.prepare("SELECT * FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(action.target_id);
        const latestUnsafe = validateActionTarget(db, action, latestDevice ? JSON.parse(latestDevice.backend_addresses ?? "[]") : []);
        if (!latestDevice || latestUnsafe) return json(res, 400, { error: latestUnsafe ?? "Destination device is unavailable" });
        const remoteCidr = action.target_address.includes(":") ? `${action.target_address}/128` : `${action.target_address}/32`;
        const firewallBody = { remoteCidr, protocol: action.target_protocol, localPort: action.target_port, deviceId: action.target_id,
          reason: `Approved response to SentryGate incident ${action.incident_id}`,
          evidence: `Policy evidence: ${JSON.parse(action.evidence_json).qualifyingEventCount} matching events under ${JSON.parse(action.evidence_json).detectionRule}. Incident ${action.incident_id}.`, expiresAt: action.expires_at };
        const invalid = validateFirewallRule(firewallBody, db, Date.now(), backendAddresses);
        if (invalid) return json(res, 400, { error: invalid });
        if (backendAddresses.some((address) => overlaps(remoteCidr, address))) return json(res, 400, { error: "Action overlaps a resolved SentryGate backend address" });
        const ruleId = crypto.randomUUID(), idempotencyKey = `action:${action.id}`, token = crypto.randomBytes(32).toString("base64url");
        db.prepare(`INSERT INTO firewall_rules (id,device_id,remote_cidr,protocol,local_port,reason,evidence,expires_at,status,idempotency_key,preview_hash,created_by,created_at,approved_by,approved_at,updated_at,incident_id,action_id)
          VALUES (?,?,?,?,?,?,?,?,'approved',?,?,?,?,?,?,?,?,?)`).run(ruleId, action.target_id, remoteCidr, action.target_protocol, action.target_port, firewallBody.reason, firewallBody.evidence, action.expires_at, idempotencyKey, tokenHash(token), admin.email, now, admin.email, now, now, action.incident_id, action.id);
        const rule = db.prepare("SELECT * FROM firewall_rules WHERE id=?").get(ruleId);
        recordHistory(db, rule, admin.email, "previewed", `Policy action review: ${action.expected_effect}; no firewall change until approval.`);
        recordHistory(db, rule, admin.email, "approved", "Administrator explicitly approved this action; agent application pending.");
        db.prepare("UPDATE proposed_actions SET status='approved',approved_by=?,approved_at=?,firewall_rule_id=?,updated_at=? WHERE id=? AND status='proposed'").run(admin.email, now, ruleId, now, action.id);
        recordAudit(db, admin.email, "action.approved", `action:${action.id}`, `Approved Windows firewall action ${ruleId}; agent application pending.`);
      }
      return json(res, 200, actionForDashboard(db, db.prepare("SELECT * FROM proposed_actions WHERE id=?").get(action.id)));
    }
    if (action.status === "rolled_back" || action.status === "rollback-pending") return json(res, 200, actionForDashboard(db, action));
    const now = new Date().toISOString();
    if (action.target_type === "website") {
      db.prepare("DELETE FROM gateway_ip_blocks WHERE action_id=?").run(action.id);
      db.prepare("UPDATE proposed_actions SET status='rolled_back',updated_at=? WHERE id=?").run(now, action.id);
      recordAudit(db, admin.email, "action.rolled_back", `action:${action.id}`, "Administrator removed the active SentryGate gateway block.");
    } else {
      if (!action.firewall_rule_id) return json(res, 409, { error: "No SentryGate-owned firewall rule is associated with this action" });
      const rule = db.prepare("SELECT * FROM firewall_rules WHERE id=?").get(action.firewall_rule_id);
      if (!rule || ["removed", "proposed"].includes(rule.status)) return json(res, 409, { error: "Firewall rule is not active" });
      db.prepare("UPDATE firewall_rules SET status='removing',rollback_at=?,updated_at=? WHERE id=?").run(now, now, rule.id);
      db.prepare("UPDATE proposed_actions SET status='rollback-pending',updated_at=? WHERE id=?").run(now, action.id);
      recordHistory(db, rule, admin.email, "rollback_requested", "Administrator requested action rollback; removal awaits authenticated agent sync.");
      recordAudit(db, admin.email, "action.rollback_requested", `action:${action.id}`, "One-click rollback queued for the enrolled Windows agent.");
    }
    return json(res, 200, actionForDashboard(db, db.prepare("SELECT * FROM proposed_actions WHERE id=?").get(action.id)));
  }

  if (url.pathname === "/api/incidents/settings" && req.method === "GET") {
    const settings = db.prepare("SELECT correlation_threshold AS correlationThreshold,correlation_window_minutes AS correlationWindowMinutes,raw_event_days AS rawEventDays,report_days AS reportDays,updated_at AS updatedAt FROM incident_settings WHERE id=1").get();
    return json(res, 200, settings);
  }
  if (url.pathname === "/api/incidents/settings" && req.method === "PUT") {
    const body = await readJson(req);
    if (!Number.isInteger(body.correlationThreshold) || body.correlationThreshold < 2 || body.correlationThreshold > 100 || !Number.isInteger(body.correlationWindowMinutes) || body.correlationWindowMinutes < 1 || body.correlationWindowMinutes > 1440 || !Number.isInteger(body.rawEventDays) || body.rawEventDays < 1 || body.rawEventDays > 3650 || !Number.isInteger(body.reportDays) || body.reportDays < 1 || body.reportDays > 3650) return json(res, 400, { error: "Threshold must be 2-100; window 1-1440 minutes; retention values 1-3650 days" });
    db.prepare("UPDATE incident_settings SET correlation_threshold=?,correlation_window_minutes=?,raw_event_days=?,report_days=?,updated_at=? WHERE id=1")
      .run(body.correlationThreshold, body.correlationWindowMinutes, body.rawEventDays, body.reportDays, new Date().toISOString());
    recordAudit(db, admin.email, "incident.settings_updated", "incident-settings", `Correlation threshold ${body.correlationThreshold}; window ${body.correlationWindowMinutes} minutes; raw events ${body.rawEventDays} days; reports ${body.reportDays} days.`);
    return json(res, 200, { saved: true });
  }

  if (url.pathname === "/api/incidents" && req.method === "GET") {
    const filters = {
      ip: url.searchParams.get("ip"), deviceId: url.searchParams.get("deviceId"), websiteId: url.searchParams.get("websiteId"),
      rule: url.searchParams.get("rule"), severity: url.searchParams.get("severity"), status: url.searchParams.get("status"),
      from: dateFilter(url.searchParams.get("from"), false), to: dateFilter(url.searchParams.get("to"), true)
    };
    const clauses = [], values = [];
    if (filters.ip) { clauses.push("i.observed_ip=?"); values.push(filters.ip); }
    if (filters.deviceId) { clauses.push("(i.device_id=? OR EXISTS(SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE ie.incident_id=i.id AND e.device_id=?))"); values.push(filters.deviceId, filters.deviceId); }
    if (filters.websiteId && /^\d+$/.test(filters.websiteId)) { clauses.push("EXISTS(SELECT 1 FROM incident_events ie JOIN events e ON e.id=ie.event_id JOIN assets a ON a.id=e.asset_id WHERE ie.incident_id=i.id AND a.type='website' AND a.id=?)"); values.push(Number(filters.websiteId)); }
    if (filters.rule) { clauses.push("i.detection_rule=?"); values.push(filters.rule); }
    if (filters.severity && ["critical", "high", "medium", "low", "info"].includes(filters.severity)) { clauses.push("i.severity=?"); values.push(filters.severity); }
    if (filters.status && ["open", "investigating", "resolved"].includes(filters.status)) { clauses.push("i.status=?"); values.push(filters.status); }
    if (filters.from) { clauses.push("i.last_seen>=?"); values.push(filters.from); }
    if (filters.to) { clauses.push("i.first_seen<=?"); values.push(filters.to); }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = db.prepare(`SELECT i.*,a.name AS asset_name,d.name AS device_name FROM incidents i LEFT JOIN assets a ON a.id=i.asset_id LEFT JOIN device_agents d ON d.device_id=i.device_id ${where} ORDER BY i.last_seen DESC LIMIT 500`).all(...values);
    return json(res, 200, rows.map((row) => incidentListItem(db, row)));
  }
  const incidentReportRoute = url.pathname.match(/^\/api\/incidents\/([0-9a-f-]{36})\/report$/i);
  if (incidentReportRoute && req.method === "GET") {
    const detail = incidentDetail(db, incidentReportRoute[1]);
    if (!detail) return json(res, 404, { error: "Incident not found" });
    const format = url.searchParams.get("format") ?? "json";
    if (!['json', 'pdf'].includes(format)) return json(res, 400, { error: "Report format must be json or pdf" });
    const reportId = crypto.randomUUID(), createdAt = new Date().toISOString();
    const retention = db.prepare("SELECT report_days FROM incident_settings WHERE id=1").get().report_days;
    const payload = { generatedAt: createdAt, ...detail, evidence: detail.events, actions: detail.events.map(({ timestamp, source, action, reason, evidence }) => ({ timestamp, source, action, reason, evidence })), limitations: ["An IP address, user agent, or hostname does not identify a person.", "Correlation is based on configured fields and is not proof of common authorship or intent.", "Observed data may be incomplete; no IP location or network ownership enrichment is asserted.", "Evidence removed by the configured raw-event retention policy is not present in this snapshot."] };
    db.prepare("INSERT INTO incident_reports (id,incident_id,actor,payload_json,created_at,expires_at) VALUES (?,?,?,?,?,?)")
      .run(reportId, detail.id, admin.email, JSON.stringify(payload), createdAt, new Date(Date.now() + retention * 86400000).toISOString());
    recordAudit(db, admin.email, "incident.report_exported", `incident:${detail.id}`, `Exported ${format.toUpperCase()} report ${reportId}; snapshot expires after ${retention} days.`);
    if (format === "pdf") return download(res, 200, makeIncidentPdf(payload), "application/pdf", `sentrygate-incident-${detail.id}.pdf`);
    return download(res, 200, Buffer.from(JSON.stringify(payload, null, 2)), "application/json; charset=utf-8", `sentrygate-incident-${detail.id}.json`);
  }
  const incidentNoteRoute = url.pathname.match(/^\/api\/incidents\/([0-9a-f-]{36})\/notes$/i);
  if (incidentNoteRoute && req.method === "POST") {
    const body = await readJson(req);
    if (typeof body.note !== "string" || !body.note.trim() || body.note.length > 4000) return json(res, 400, { error: "Note is required and limited to 4000 characters" });
    if (!db.prepare("SELECT 1 FROM incidents WHERE id=?").get(incidentNoteRoute[1])) return json(res, 404, { error: "Incident not found" });
    const now = new Date().toISOString();
    db.prepare("INSERT INTO incident_notes (incident_id,actor,note,created_at) VALUES (?,?,?,?)").run(incidentNoteRoute[1], admin.email, body.note.trim(), now);
    recordAudit(db, admin.email, "incident.note_added", `incident:${incidentNoteRoute[1]}`, body.note.trim());
    return json(res, 201, { saved: true, createdAt: now });
  }
  const incidentStatusRoute = url.pathname.match(/^\/api\/incidents\/([0-9a-f-]{36})\/status$/i);
  if (incidentStatusRoute && req.method === "PATCH") {
    const body = await readJson(req);
    if (!["open", "investigating", "resolved"].includes(body.status)) return json(res, 400, { error: "Status must be open, investigating, or resolved" });
    const incident = db.prepare("SELECT status FROM incidents WHERE id=?").get(incidentStatusRoute[1]);
    if (!incident) return json(res, 404, { error: "Incident not found" });
    if (incident.status !== body.status) {
      db.prepare("UPDATE incidents SET status=?,updated_at=? WHERE id=?").run(body.status, new Date().toISOString(), incidentStatusRoute[1]);
      recordAudit(db, admin.email, "incident.status_changed", `incident:${incidentStatusRoute[1]}`, `Changed incident status from ${incident.status} to ${body.status}.`);
    }
    return json(res, 200, incidentDetail(db, incidentStatusRoute[1]));
  }
  const incidentMatch = url.pathname.match(/^\/api\/incidents\/([0-9a-f-]{36})$/i);
  if (incidentMatch && req.method === "GET") {
    const detail = incidentDetail(db, incidentMatch[1]);
    return detail ? json(res, 200, detail) : json(res, 404, { error: "Incident not found" });
  }

  if (url.pathname === "/api/firewall/rules" && req.method === "GET") {
    expireFirewallRules(db);
    return json(res, 200, db.prepare(`SELECT r.*,d.name AS device_name FROM firewall_rules r JOIN device_agents d USING(device_id) ORDER BY r.created_at DESC`).all().map(firewallRuleForDashboard));
  }
  if (url.pathname === "/api/firewall/rules" && req.method === "POST") {
    const body = await readJson(req);
    let backendAddresses = [];
    try {
      const backendHost = new URL(config.apiBaseUrl).hostname.replace(/^\[|\]$/g, "");
      backendAddresses = net.isIP(backendHost) ? [backendHost] : (await lookup(backendHost, { all: true })).map((entry) => entry.address);
    } catch { return json(res, 400, { error: "Could not resolve the configured backend address; refusing an unsafe rule preview" }); }
    const invalid = validateFirewallRule(body, db, Date.now(), backendAddresses);
    if (invalid) return json(res, 400, { error: invalid });
    if (body.incidentId != null) {
      const incident = typeof body.incidentId === "string" ? db.prepare("SELECT asset_id FROM incidents WHERE id=?").get(body.incidentId) : null;
      const deviceAsset = db.prepare("SELECT asset_id FROM device_agents WHERE device_id=? AND revoked_at IS NULL").get(body.deviceId);
      if (!incident) return json(res, 400, { error: "incidentId must reference an existing incident" });
      if (!deviceAsset || Number(incident.asset_id) !== Number(deviceAsset.asset_id)) return json(res, 409, { error: "Firewall rule device must belong to the incident's affected asset" });
    }
    try {
      if (backendAddresses.some((address) => overlaps(body.remoteCidr, address))) return json(res, 400, { error: "Rule overlaps a resolved SentryGate backend address" });
    } catch { return json(res, 500, { error: "Configured API address is invalid" }); }
    if (typeof body.idempotencyKey !== "string" || !/^[0-9a-f-]{36}$/i.test(body.idempotencyKey)) return json(res, 400, { error: "A UUID idempotencyKey is required" });
    const normalized = body.remoteCidr.trim(), expiresAt = new Date(body.expiresAt).toISOString();
    const existing = db.prepare("SELECT * FROM firewall_rules WHERE idempotency_key=?").get(body.idempotencyKey);
    const previewToken = crypto.createHmac("sha256", config.sessionSecret).update(`firewall-preview:${body.idempotencyKey}`).digest("base64url");
    if (existing) {
      const sameRequest = existing.device_id === body.deviceId && existing.remote_cidr === normalized && existing.protocol === body.protocol && existing.local_port === body.localPort && existing.reason === body.reason.trim() && existing.evidence === body.evidence.trim() && existing.expires_at === expiresAt && (existing.incident_id ?? null) === (body.incidentId ?? null);
      if (!sameRequest) return json(res, 409, { error: "Idempotency key was already used for a different firewall proposal" });
      return json(res, 200, { rule: firewallRuleForDashboard(existing), previewToken });
    }
    const id = crypto.randomUUID(), token = previewToken, now = new Date().toISOString();
    const preliminary = { id, device_id: body.deviceId, remote_cidr: normalized, protocol: body.protocol, local_port: body.localPort, reason: body.reason.trim(), evidence: body.evidence.trim(), expires_at: expiresAt };
    db.prepare(`INSERT INTO firewall_rules (id,device_id,remote_cidr,protocol,local_port,reason,evidence,expires_at,status,idempotency_key,preview_hash,created_by,created_at,updated_at,incident_id)
      VALUES (?,?,?,?,?,?,?,?,'proposed',?,?,?,?,?,?)`).run(id, body.deviceId, normalized, body.protocol, body.localPort, preliminary.reason, preliminary.evidence, preliminary.expires_at, body.idempotencyKey, tokenHash(token), admin.email, now, now, body.incidentId ?? null);
    const rule = db.prepare("SELECT * FROM firewall_rules WHERE id=?").get(id);
    recordHistory(db, rule, admin.email, "previewed", "Administrator prepared a rule preview; no firewall changes made.");
    recordAudit(db, admin.email, "firewall.rule_previewed", `firewall:${id}`, `${body.protocol} inbound ${normalized} to local port ${body.localPort}; preview only.`);
    return json(res, 201, { rule: firewallRuleForDashboard(rule), previewToken: token });
  }
  const firewallAction = url.pathname.match(/^\/api\/firewall\/rules\/([0-9a-f-]{36})\/(approve|rollback)$/i);
  if (firewallAction && req.method === "POST") {
    const [, id, action] = firewallAction, body = await readJson(req), rule = db.prepare("SELECT * FROM firewall_rules WHERE id=?").get(id);
    if (!rule) return json(res, 404, { error: "Firewall rule not found" });
    if (body.confirmed !== true) return json(res, 400, { error: "Explicit administrator confirmation is required" });
    const now = new Date().toISOString();
    if (action === "approve") {
      if (["approved", "active"].includes(rule.status) && rule.approved_by === admin.email) return json(res, 200, firewallRuleForDashboard(rule));
      if (rule.status !== "proposed") return json(res, 409, { error: "Only a proposed rule can be approved" });
      if (typeof body.previewToken !== "string" || !safeTokenMatches(body.previewToken, rule.preview_hash)) return json(res, 403, { error: "Preview confirmation token is invalid" });
      db.prepare("UPDATE firewall_rules SET status='approved',approved_by=?,approved_at=?,updated_at=? WHERE id=? AND status='proposed'").run(admin.email, now, now, id);
      const updated = db.prepare("SELECT * FROM firewall_rules WHERE id=?").get(id);
      recordHistory(db, updated, admin.email, "approved", "Administrator explicitly approved this exact preview; agent application pending.");
      recordAudit(db, admin.email, "firewall.rule_approved", `firewall:${id}`, `Approved inbound ${rule.protocol} ${rule.remote_cidr} to port ${rule.local_port}; agent application pending.`);
    } else {
      if (["removing", "removed"].includes(rule.status)) return json(res, 200, firewallRuleForDashboard(rule));
      if (rule.status === "proposed") return json(res, 409, { error: "Unapproved previews cannot be rolled back; reject by deleting the proposal" });
      db.prepare("UPDATE firewall_rules SET status='removing',rollback_at=?,updated_at=? WHERE id=?").run(now, now, id);
      recordHistory(db, rule, admin.email, "rollback_requested", "Administrator confirmed immediate rollback; removal awaits agent sync.");
      recordAudit(db, admin.email, "firewall.rule_rollback", `firewall:${id}`, "Immediate rollback requested; agent removal pending.");
    }
    return json(res, 200, firewallRuleForDashboard(db.prepare("SELECT * FROM firewall_rules WHERE id=?").get(id)));
  }
  if (url.pathname === "/api/firewall/settings" && req.method === "GET") return json(res, 200, JSON.parse(db.prepare("SELECT management_addresses FROM firewall_settings WHERE id=1").get().management_addresses));
  if (url.pathname === "/api/firewall/settings" && req.method === "PUT") {
    const body = await readJson(req);
    if (!Array.isArray(body.managementAddresses) || body.managementAddresses.length > 32 || body.managementAddresses.some((value) => typeof value !== "string" || !net.isIP(value)) || new Set(body.managementAddresses).size !== body.managementAddresses.length) return json(res, 400, { error: "Management addresses must be up to 32 unique exact IP addresses" });
    const protectedRules = db.prepare("SELECT * FROM firewall_rules WHERE status IN ('approved','active','failed','removing','expired')").all();
    for (const address of body.managementAddresses) {
      const conflict = protectedRules.find((rule) => overlaps(rule.remote_cidr, address));
      if (conflict) return json(res, 409, { error: `Address ${address} overlaps approved firewall rule ${conflict.id}; rollback it before protecting this address` });
    }
    db.prepare("UPDATE firewall_settings SET management_addresses=?,updated_at=? WHERE id=1").run(JSON.stringify(body.managementAddresses), new Date().toISOString());
    recordAudit(db, admin.email, "firewall.management_addresses_updated", "firewall:settings", "Updated protected administrator management addresses.");
    return json(res, 200, { saved: true });
  }

  if (url.pathname === "/api/devices/enroll" && req.method === "POST") {
    if (config.standalone && db.prepare("SELECT 1 FROM device_agents WHERE is_demo=0 AND revoked_at IS NULL LIMIT 1").get()) return json(res, 409, { error: "Standalone mode permits one active local Windows agent identity. Do not use this installation to enroll another computer." });
    const body = await readJson(req);
    const invalid = validateDeviceEnrollment(body);
    if (invalid) return json(res, 400, { error: invalid });
    let linkedAssetId = body.assetId === undefined || body.assetId === "" || body.assetId === null ? null : Number(body.assetId);
    if (linkedAssetId !== null && !db.prepare("SELECT 1 FROM assets WHERE id=? AND type='computer' AND removed_at IS NULL").get(linkedAssetId)) return json(res, 400, { error: "Linked asset must be an active registered computer" });
    if (linkedAssetId !== null && db.prepare("SELECT 1 FROM device_agents WHERE asset_id=? AND revoked_at IS NULL").get(linkedAssetId)) return json(res, 409, { error: "A computer asset can be linked to only one active agent" });
    const deviceId = crypto.randomUUID();
    const credential = crypto.randomBytes(32).toString("base64url");
    const enrolledAt = new Date().toISOString();
    if (linkedAssetId === null) {
      const created = db.prepare(`INSERT INTO assets (name,type,owner,status,address,description,created_at) VALUES (?,'computer',?,'unknown',?,?,?)`)
        .run(body.name.trim(), admin.email, body.hostname.trim(), "Enrolled Windows computer", enrolledAt);
      linkedAssetId = Number(created.lastInsertRowid);
    }
    db.prepare(`INSERT INTO device_agents (device_id,name,hostname,os_version,agent_version,credential_hash,enrolled_at,asset_id)
      VALUES (?,?,?,?,?,?,?,?)`).run(deviceId, body.name.trim(), body.hostname.trim(), body.osVersion.trim(), body.agentVersion.trim(), tokenHash(credential), enrolledAt, linkedAssetId);
    const device = db.prepare("SELECT * FROM device_agents WHERE device_id=?").get(deviceId);
    queueDeviceConfig(db, device, enrolledAt);
    recordAudit(db, admin.email, "device.enrolled", `device:${deviceId}`, `Enrolled Windows device ${body.name.trim()}.`);
    recordAudit(db, admin.email, "asset.device_linked", `asset:${linkedAssetId}`, `Linked Windows agent ${deviceId} to its dedicated computer asset.`);
    return json(res, 201, { deviceId, assetId: linkedAssetId, credential, enrolledAt, shownOnce: true });
  }

  if (url.pathname === "/api/devices" && req.method === "GET") {
    const devices = db.prepare(`SELECT device_id AS deviceId,name,asset_id AS assetId,hostname,os_version AS osVersion,agent_version AS agentVersion,
      enrolled_at AS enrolledAt,last_heartbeat AS lastHeartbeat,CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
      WHEN last_heartbeat IS NULL OR datetime(last_heartbeat) < datetime('now', '-' || (collection_interval_seconds * 3) || ' seconds') THEN 'stale'
      ELSE health_status END AS healthStatus,revoked_at AS revokedAt,
      health_detail AS healthDetail,
      collection_processes AS collectionProcesses,collection_connections AS collectionConnections,collection_applications AS collectionApplications,
      collection_services AS collectionServices,collection_startup AS collectionStartup,collection_security AS collectionSecurity,
      collection_interval_seconds AS collectionIntervalSeconds,outbound_connection_threshold AS outboundConnectionThreshold,
      retained_days AS retainedDays,is_demo AS isDemo,config_version AS policyVersion,
      (SELECT COUNT(*) FROM alerts al WHERE al.device_id=device_agents.device_id AND al.status='open') AS openAlertCount,
      (SELECT status FROM device_config_updates q WHERE q.device_id=device_agents.device_id ORDER BY version DESC LIMIT 1) AS configStatus,
      (SELECT attempts FROM device_config_updates q WHERE q.device_id=device_agents.device_id ORDER BY version DESC LIMIT 1) AS configAttempts FROM device_agents ORDER BY name`).all().map((device) => {
        const snapshot = db.prepare("SELECT services_json FROM device_snapshots WHERE device_id=?").get(device.deviceId);
        const service = snapshot ? JSON.parse(snapshot.services_json).find((item) => String(item.name).toLowerCase() === "sentrygateagent") : null;
        return { ...device, agentServiceState: service?.state ?? "Not reported", agentServiceStartMode: service?.startMode ?? "Unknown" };
      });
    return json(res, 200, devices);
  }

  const deviceSettings = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})\/settings$/i);
  if (deviceSettings && req.method === "PUT") {
    const id = deviceSettings[1];
    const body = await readJson(req);
    const invalid = validateDeviceSettings(body);
    if (invalid) return json(res, 400, { error: invalid });
    if (!db.prepare("SELECT 1 FROM device_agents WHERE device_id=?").get(id)) return json(res, 404, { error: "Device not found" });
    db.prepare(`UPDATE device_agents SET collection_processes=?,collection_connections=?,collection_applications=?,collection_services=?,collection_startup=?,collection_security=?,collection_interval_seconds=?,config_version=config_version+1,
      outbound_connection_threshold=?,retained_days=? WHERE device_id=?`)
      .run(+body.collectProcesses, +body.collectConnections, +(body.collectApplications ?? true), +(body.collectServices ?? true), +(body.collectStartup ?? true), +(body.collectSecurity ?? true), body.intervalSeconds, body.outboundConnectionThreshold, body.retainedDays, id);
    queueDeviceConfig(db, db.prepare("SELECT * FROM device_agents WHERE device_id=?").get(id), new Date().toISOString());
    recordAudit(db, admin.email, "device.settings_updated", `device:${id}`, "Updated collection and retention settings.");
    return json(res, 200, { saved: true });
  }

  const deviceCredential = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})\/credential\/(rotate|revoke)$/i);
  if (deviceCredential && req.method === "POST") {
    const id = deviceCredential[1];
    const device = db.prepare("SELECT device_id,name FROM device_agents WHERE device_id=?").get(id);
    if (!device) return json(res, 404, { error: "Device not found" });
    if (deviceCredential[2] === "revoke") {
      db.prepare("UPDATE device_agents SET revoked_at=? WHERE device_id=?").run(new Date().toISOString(), id);
      recordAudit(db, admin.email, "device.credential_revoked", `device:${id}`, `Revoked credentials for ${device.name}.`);
      return json(res, 200, { revoked: true });
    }
    const credential = crypto.randomBytes(32).toString("base64url");
    db.prepare("UPDATE device_agents SET credential_hash=?,revoked_at=NULL WHERE device_id=?").run(tokenHash(credential), id);
    recordAudit(db, admin.email, "device.credential_rotated", `device:${id}`, `Rotated credentials for ${device.name}.`);
    return json(res, 200, { credential, shownOnce: true });
  }

  const deviceDetail = url.pathname.match(/^\/api\/devices\/([0-9a-f-]{36})$/i);
  if (deviceDetail && req.method === "GET") {
    const device = db.prepare(`SELECT device_id AS deviceId,name,asset_id AS assetId,(SELECT name FROM assets WHERE id=device_agents.asset_id) AS assetName,hostname,os_version AS osVersion,agent_version AS agentVersion,
      enrolled_at AS enrolledAt,last_heartbeat AS lastHeartbeat,CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
      WHEN last_heartbeat IS NULL OR datetime(last_heartbeat) < datetime('now', '-' || (collection_interval_seconds * 3) || ' seconds') THEN 'offline'
      ELSE health_status END AS healthStatus,health_detail AS healthDetail,revoked_at AS revokedAt,is_demo AS isDemo,
      collection_processes AS collectionProcesses,collection_connections AS collectionConnections,collection_applications AS collectionApplications,
      collection_services AS collectionServices,collection_startup AS collectionStartup,collection_security AS collectionSecurity,collection_interval_seconds AS collectionIntervalSeconds,
      config_version AS policyVersion,(SELECT COUNT(*) FROM alerts al WHERE al.device_id=device_agents.device_id AND al.status='open') AS openAlertCount,
      outbound_connection_threshold AS outboundConnectionThreshold,retained_days AS retainedDays
      FROM device_agents WHERE device_id=?`).get(deviceDetail[1]);
    if (!device) return json(res, 404, { error: "Device not found" });
    const snapshot = db.prepare("SELECT captured_at AS capturedAt,processes_json AS processes,connections_json AS connections,applications_json AS installedApplications,services_json AS services,startup_entries_json AS startupEntries,security_settings_json AS securitySettings FROM device_snapshots WHERE device_id=?").get(device.deviceId);
    const services = snapshot ? JSON.parse(snapshot.services) : [];
    const agentService = services.find((item) => String(item.name).toLowerCase() === "sentrygateagent") ?? null;
    const recentAlerts = db.prepare("SELECT id,title,severity,status,evidence,created_at AS createdAt FROM alerts WHERE device_id=? ORDER BY created_at DESC LIMIT 50").all(device.deviceId);
    return json(res, 200, { ...device, recentAlerts, agentServiceState: agentService?.state ?? "Not reported", agentServiceStartMode: agentService?.startMode ?? "Unknown", capturedAt: snapshot?.capturedAt ?? null, processes: snapshot ? JSON.parse(snapshot.processes) : [], connections: snapshot ? JSON.parse(snapshot.connections) : [], installedApplications: snapshot ? JSON.parse(snapshot.installedApplications) : [], services, startupEntries: snapshot ? JSON.parse(snapshot.startupEntries) : [], securitySettings: snapshot ? JSON.parse(snapshot.securitySettings) : {} });
  }

  if (url.pathname === "/api/logout" && req.method === "POST") {
    const raw=parseCookies(req.headers.cookie??"")[cookieName(config)],session=verifySession(raw,config.sessionSecret);
    if(session)db.prepare("INSERT OR IGNORE INTO revoked_sessions(session_id,expires_at,revoked_at) VALUES(?,?,?)").run(session.jti,session.exp,new Date().toISOString());
    recordAudit(db, admin.email, "admin.logout", "administrator", "Administrator logged out.");
    clearCookie(res, config);
    return empty(res, 204);
  }

  if (url.pathname === "/api/summary" && req.method === "GET") {
    const cutoff = new Date(Date.now() - 86_400_000).toISOString();
    return json(res, 200, {
      assets: db.prepare("SELECT COUNT(*) AS count FROM assets").get().count,
      openAlerts: db.prepare("SELECT COUNT(*) AS count FROM alerts WHERE status NOT IN ('closed','false_positive')").get().count,
      openIncidents: db.prepare("SELECT COUNT(*) AS count FROM incidents WHERE status != 'resolved'").get().count,
      events24h: db.prepare("SELECT COUNT(*) AS count FROM events WHERE created_at >= ?").get(cutoff).count,
      audit24h: db.prepare("SELECT COUNT(*) AS count FROM audit_log WHERE created_at >= ?").get(cutoff).count
    });
  }

  if(url.pathname==="/api/pilot/metrics"&&req.method==="GET"){
    const days=Number(url.searchParams.get("days")??7);
    if(!Number.isInteger(days)||days<1||days>90)return json(res,400,{error:"Pilot metrics window must be 1 to 90 days"});
    return json(res,200,pilotMetrics(db,{days}));
  }

  if(url.pathname==="/api/pilot/report"&&req.method==="GET"){
    const days=Number(url.searchParams.get("days")??7),assetIdRaw=url.searchParams.get("assetId");
    if(!Number.isInteger(days)||days<1||days>90||assetIdRaw!==null&&!/^\d+$/.test(assetIdRaw))return json(res,400,{error:"Invalid report scope"});
    const report=generatePilotReport(db,{days,...(assetIdRaw===null?{}:{assetId:Number(assetIdRaw)})});
    recordAudit(db,admin.email,"pilot.report_exported","pilot",`Exported controlled-pilot report for ${days} days${assetIdRaw?` and asset ${assetIdRaw}`:""}.`);
    res.setHeader("Content-Disposition",`attachment; filename=sentrygate-pilot-${new Date().toISOString().slice(0,10)}.json`);
    return json(res,200,report);
  }

  const falsePositiveRoute=url.pathname.match(/^\/api\/events\/(\d+)\/false-positive$/);
  if(falsePositiveRoute&&req.method==="POST"){
    const eventId=Number(falsePositiveRoute[1]),body=await readJson(req);
    if(typeof body.falsePositive!=="boolean")return json(res,400,{error:"falsePositive must be a boolean"});
    const event=db.prepare("SELECT id,source,detection_rule FROM events WHERE id=?").get(eventId);
    if(!event||event.source!=="website-gateway"||event.detection_rule==="none"||event.detection_rule==="allowlist")return json(res,404,{error:"Reviewable gateway detection event not found"});
    const now=new Date().toISOString();
    db.prepare("UPDATE events SET false_positive=?,reviewed_by=?,reviewed_at=? WHERE id=?").run(body.falsePositive?1:0,admin.email,now,eventId);
    recordAudit(db,admin.email,body.falsePositive?"pilot.false_positive_marked":"pilot.false_positive_cleared",`event:${eventId}`,`Administrator ${body.falsePositive?"marked this detection as a false positive":"cleared the false-positive label"}; original evidence was preserved.`);
    return json(res,200,{eventId,falsePositive:body.falsePositive,reviewedBy:admin.email,reviewedAt:now});
  }

  if (url.pathname === "/api/assets" && req.method === "GET") {
    return json(res, 200, db.prepare(`SELECT a.id,a.name,a.type,a.owner,a.status,a.address,a.description,a.created_at AS createdAt,
      a.removed_at AS removedAt,d.device_id AS deviceId,COALESCE(d.agent_version,g.gateway_version) AS version,COALESCE(d.last_heartbeat,g.last_heartbeat) AS lastHeartbeat,
      CASE WHEN d.device_id IS NOT NULL THEN CASE WHEN d.revoked_at IS NOT NULL THEN 'revoked' WHEN d.last_heartbeat IS NULL OR datetime(d.last_heartbeat)<datetime('now','-' || (d.collection_interval_seconds*3) || ' seconds') THEN 'offline' ELSE d.health_status END
      WHEN a.type='website' THEN CASE WHEN a.upstream_url='' THEN 'not-configured' WHEN g.last_heartbeat IS NULL OR datetime(g.last_heartbeat)<datetime('now','-90 seconds') THEN 'offline' ELSE g.health_status END ELSE a.status END AS connectionStatus,
      (SELECT status FROM device_config_updates q WHERE q.device_id=d.device_id ORDER BY version DESC LIMIT 1) AS configStatus
      FROM assets a LEFT JOIN device_agents d ON d.asset_id=a.id LEFT JOIN website_gateway_status g ON g.asset_id=a.id WHERE a.removed_at IS NULL ORDER BY a.name`).all());
  }

  if (url.pathname === "/api/assets" && req.method === "POST") {
    const body = await readJson(req);
    const validation = validateAsset(body);
    if (validation) return json(res, 400, { error: validation });
    const createdAt = new Date().toISOString();
    const result = db.prepare(`INSERT INTO assets (name, type, owner, status, address, description, created_at)
      VALUES (?, ?, ?, 'healthy', ?, ?, ?)`)
      .run(body.name.trim(), body.type, admin.email, body.address.trim(), body.description.trim(), createdAt);
    if (body.type === "website") db.prepare("INSERT INTO gateway_rules (asset_id, updated_at) VALUES (?, ?)").run(Number(result.lastInsertRowid), createdAt);
    if (body.type === "website") rotateAssetCredential(db, config.sessionSecret, Number(result.lastInsertRowid));
    recordAudit(db, admin.email, "asset.created", `asset:${result.lastInsertRowid}`, `Registered ${body.type} asset ${body.name.trim()}.`);
    return json(res, 201, { id: Number(result.lastInsertRowid) });
  }

  const websiteCredential = url.pathname.match(/^\/api\/assets\/(\d+)\/credential\/rotate$/);
  if (websiteCredential && req.method === "POST") {
    const id=Number(websiteCredential[1]),asset=db.prepare("SELECT id,name FROM assets WHERE id=? AND type='website' AND removed_at IS NULL").get(id);
    if(!asset)return json(res,404,{error:"Active website asset not found"});
    const credential=rotateAssetCredential(db,config.sessionSecret,id);
    recordAudit(db,admin.email,"asset.credential_rotated",`asset:${id}`,`Rotated the gateway credential for website ${asset.name}.`);
    return json(res,200,{credential,assetId:id,shownOnce:true});
  }

  const assetDetail = url.pathname.match(/^\/api\/assets\/(\d+)$/);
  if (assetDetail && req.method === "GET") {
    const id = Number(assetDetail[1]);
    const asset = db.prepare(`SELECT a.*,d.device_id AS deviceId,COALESCE(d.agent_version,g.gateway_version) AS version,COALESCE(d.last_heartbeat,g.last_heartbeat) AS lastHeartbeat,
      CASE WHEN d.device_id IS NOT NULL THEN d.health_status ELSE g.health_status END AS healthStatus,
      d.health_detail AS healthDetail,d.revoked_at AS revokedAt,d.collection_interval_seconds AS heartbeatInterval
      FROM assets a LEFT JOIN device_agents d ON d.asset_id=a.id LEFT JOIN website_gateway_status g ON g.asset_id=a.id WHERE a.id=? AND a.removed_at IS NULL`).get(id);
    if (!asset) return json(res, 404, { error: "Asset not found" });
    const recentEvents = db.prepare("SELECT id,source,action,reason,evidence,severity,observed_source_ip,request_details,process_details,detection_rule,created_at AS createdAt FROM events WHERE asset_id=? ORDER BY created_at DESC LIMIT 50").all(id);
    const activeRules = asset.deviceId ? db.prepare("SELECT id,status,remote_cidr AS remoteCidr,protocol,local_port AS localPort,expires_at AS expiresAt,failure FROM firewall_rules WHERE device_id=? AND status IN ('approved','active','failed','removing','expired') ORDER BY created_at DESC").all(asset.deviceId) : [];
    const pendingConfig = asset.deviceId ? db.prepare("SELECT version,status,attempts,last_attempt_at AS lastAttemptAt,detail FROM device_config_updates WHERE device_id=? ORDER BY version DESC LIMIT 1").get(asset.deviceId) : null;
    return json(res, 200, { asset, recentEvents, activeRules, pendingConfig, recentAlerts: db.prepare("SELECT id,title,severity,status,created_at AS createdAt FROM alerts WHERE asset_id=? ORDER BY created_at DESC LIMIT 10").all(id) });
  }

  const assetRemoval = url.pathname.match(/^\/api\/assets\/(\d+)\/remove$/);
  if (assetRemoval && req.method === "POST") {
    const id = Number(assetRemoval[1]), body = await readJson(req);
    if (body.confirmed !== true) return json(res, 400, { error: "Explicit confirmation is required" });
    const asset = db.prepare("SELECT * FROM assets WHERE id=? AND removed_at IS NULL").get(id);
    if (!asset) return json(res, 404, { error: "Asset not found" });
    const device = db.prepare("SELECT * FROM device_agents WHERE asset_id=? AND revoked_at IS NULL").get(id);
    const outstanding = device ? db.prepare("SELECT id,status FROM firewall_rules WHERE device_id=? AND status IN ('proposed','approved','active','failed','removing','expired')").all(device.device_id) : [];
    if (outstanding.length) return json(res, 409, { error: "Asset has SentryGate-owned firewall rules that must be rolled back and confirmed removed before asset removal", rules: outstanding });
    const activeGatewayActions = db.prepare("SELECT action_id,expires_at FROM gateway_ip_blocks WHERE asset_id=?").all(id);
    if (activeGatewayActions.length) return json(res, 409, { error: "Website asset has active SentryGate gateway actions; roll them back or wait for expiry before removal", actions: activeGatewayActions });
    const now = new Date().toISOString();
    db.prepare("UPDATE assets SET removed_at=?,status='removed' WHERE id=?").run(now,id);
    if (device) db.prepare("UPDATE device_agents SET revoked_at=? WHERE device_id=?").run(now,device.device_id);
    db.prepare("UPDATE asset_credentials SET revoked_at=? WHERE asset_id=?").run(now,id);
    db.prepare("DELETE FROM gateway_ip_blocks WHERE asset_id=?").run(id);
    recordAudit(db, admin.email, "asset.removed", `asset:${id}`, `Soft-removed ${asset.type} asset ${asset.name}; evidence retained${device ? ` and agent ${device.device_id} credential revoked` : ""}.`);
    return json(res, 200, { removed: true, evidenceRetained: true, revokedDeviceId: device?.device_id ?? null });
  }

  if (url.pathname === "/api/admins" && (req.method === "GET" || req.method === "POST")) {
    if (req.method === "GET") return json(res, 200, db.prepare("SELECT id,email,role,created_at AS createdAt FROM admins ORDER BY id").all());
    const body = await readJson(req), validation = validateCredentials(body, true);
    if (validation) return json(res, 400, { error: validation });
    if (!["owner","security_analyst","read_only_viewer"].includes(body.role)) return json(res, 400, { error: "Role must be owner, security_analyst, or read_only_viewer" });
    const email=body.email.toLowerCase(), {salt,hash}=hashPassword(body.password), now=new Date().toISOString();
    try { const created=db.prepare("INSERT INTO admins(email,password_hash,password_salt,role,created_at) VALUES(?,?,?,?,?)").run(email,hash,salt,body.role,now);
      recordAudit(db,admin.email,"admin.created",`admin:${created.lastInsertRowid}`,`Created ${body.role} administrator ${email}.`); return json(res,201,{id:Number(created.lastInsertRowid),email,role:body.role}); }
    catch { return json(res,409,{error:"Administrator email already exists"}); }
  }

  const protectionMatch = url.pathname.match(/^\/api\/assets\/(\d+)\/protection$/);
  if (protectionMatch) {
    const assetId = Number(protectionMatch[1]);
    const asset = db.prepare("SELECT id,type,upstream_url AS upstreamUrl FROM assets WHERE id = ?").get(assetId);
    if (!asset || asset.type !== "website") return json(res, 404, { error: "Protected website not found" });
    if (req.method === "GET") {
      const rule = db.prepare(`SELECT enabled,mode,failure_mode AS failureMode,rate_limit_count AS rateLimitCount,window_seconds AS windowSeconds,
        sensitive_paths_enabled AS sensitivePathsEnabled,updated_at AS updatedAt FROM gateway_rules WHERE asset_id = ?`).get(assetId);
      const allowlist = db.prepare("SELECT ip FROM gateway_allowlist WHERE asset_id = ? ORDER BY ip").all(assetId).map((row) => row.ip);
      return json(res, 200, { upstreamUrl: asset.upstreamUrl, rule, allowlist });
    }
    if (req.method === "PUT") {
      const body = await readJson(req);
      const validation = validateProtection(body);
      if (validation) return json(res, 400, { error: validation });
      const upstream=new URL(body.upstreamUrl);
      const loopbackUpstream=["127.0.0.1","::1","localhost"].includes(upstream.hostname.replace(/^\[|\]$/g,""));
      if(upstream.protocol!=="https:" && (!loopbackUpstream || process.env.NODE_ENV==="production")) return json(res,400,{error:"Non-loopback website upstreams must use HTTPS; HTTP is permitted only for loopback development"});
      const old = db.prepare(`SELECT mode,enabled,failure_mode AS failureMode,rate_limit_count AS rateLimitCount,window_seconds AS windowSeconds,
        sensitive_paths_enabled AS sensitivePathsEnabled FROM gateway_rules WHERE asset_id = ?`).get(assetId);
      const priorAllowlist = db.prepare("SELECT ip FROM gateway_allowlist WHERE asset_id = ? ORDER BY ip").all(assetId).map((row) => row.ip);
      const timestamp = new Date().toISOString();
      db.exec("BEGIN");
      try {
        db.prepare("UPDATE assets SET upstream_url = ? WHERE id = ?").run(body.upstreamUrl.trim(), assetId);
        db.prepare(`INSERT INTO gateway_rules (asset_id,enabled,mode,failure_mode,rate_limit_count,window_seconds,sensitive_paths_enabled,updated_at)
          VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET enabled=excluded.enabled,mode=excluded.mode,
          failure_mode=excluded.failure_mode,rate_limit_count=excluded.rate_limit_count,window_seconds=excluded.window_seconds,
          sensitive_paths_enabled=excluded.sensitive_paths_enabled,updated_at=excluded.updated_at`)
          .run(assetId, body.enabled ? 1 : 0, body.mode, body.failureMode ?? old?.failureMode ?? "open", body.rateLimitCount, body.windowSeconds, body.sensitivePathsEnabled ? 1 : 0, timestamp);
        db.prepare("DELETE FROM gateway_allowlist WHERE asset_id = ?").run(assetId);
        const insertAllowlist = db.prepare("INSERT INTO gateway_allowlist (asset_id,ip,created_at) VALUES (?,?,?)");
        for (const ip of body.allowlist) insertAllowlist.run(assetId, ip, timestamp);
        db.exec("COMMIT");
      } catch (error) { db.exec("ROLLBACK"); throw error; }
      const changed = [];
      if (asset.upstreamUrl !== body.upstreamUrl.trim()) changed.push("upstream URL");
      if (old?.mode !== body.mode || Number(old?.enabled) !== Number(body.enabled)) changed.push("rule mode/enabled state");
      if (old?.failureMode !== (body.failureMode ?? old?.failureMode ?? "open")) changed.push("gateway failure behavior");
      if (old?.rateLimitCount !== body.rateLimitCount || old?.windowSeconds !== body.windowSeconds) changed.push("rate limit");
      if (Number(old?.sensitivePathsEnabled) !== Number(body.sensitivePathsEnabled)) changed.push("sensitive-path rule");
      if (changed.length) recordAudit(db, admin.email, "protection.updated", `asset:${assetId}`, `Changed ${changed.join(", ")}.`);
      if (JSON.stringify([...priorAllowlist].sort()) !== JSON.stringify([...body.allowlist].sort())) {
        recordAudit(db, admin.email, "allowlist.updated", `asset:${assetId}`, `Set ${body.allowlist.length} allowlisted IP address(es).`);
      }
      return json(res, 200, { saved: true });
    }
    return json(res, 405, { error: "Method not allowed" });
  }

  if (url.pathname === "/api/gateway/settings" && (req.method === "GET" || req.method === "PUT")) {
    if (req.method === "GET") {
      const row = db.prepare("SELECT trusted_proxies FROM gateway_settings WHERE id = 1").get();
      return json(res, 200, { trustedProxies: JSON.parse(row.trusted_proxies) });
    }
    const body = await readJson(req);
    if (!Array.isArray(body.trustedProxies) || body.trustedProxies.length > 32 || body.trustedProxies.some((ip) => typeof ip !== "string" || !net.isIP(ip))) {
      return json(res, 400, { error: "Trusted proxies must be up to 32 exact IPv4 or IPv6 addresses" });
    }
    const trustedProxies = [...new Set(body.trustedProxies)];
    const previous = db.prepare("SELECT trusted_proxies FROM gateway_settings WHERE id = 1").get().trusted_proxies;
    db.prepare("UPDATE gateway_settings SET trusted_proxies = ?, updated_at = ? WHERE id = 1").run(JSON.stringify(trustedProxies), new Date().toISOString());
    if (JSON.stringify(trustedProxies) !== previous) recordAudit(db, admin.email, "trusted_proxies.updated", "gateway", `Configured ${trustedProxies.length} trusted proxy peer(s).`);
    return json(res, 200, { saved: true, trustedProxies });
  }

  if (url.pathname === "/api/agent/credential/rotate" && req.method === "POST") {
    const credential = rotateAgentCredential(db, config.sessionSecret);
    recordAudit(db, admin.email, "agent.credential_rotated", "gateway-agent", "Rotated the gateway event-ingestion credential.");
    return json(res, 200, { credential, shownOnce: true });
  }

  const alertMatch = url.pathname.match(/^\/api\/alerts\/(\d+)$/);
  if (alertMatch && req.method === "GET") {
    const alert = db.prepare(`SELECT alerts.id, alerts.asset_id AS assetId, assets.name AS assetName, alerts.title,
        alerts.severity, alerts.status, alerts.evidence, alerts.observed_facts AS observedFacts, alerts.estimate,
        device_agents.name AS deviceName, device_agents.device_id AS deviceId, device_agents.os_version AS deviceOsVersion, assets.type AS assetType,
        events.id AS eventId, events.source AS eventSource, events.observed_source_ip AS observedSourceIp,
        events.method, events.request_path AS requestPath, events.user_agent AS userAgent,
        events.request_details AS requestDetails, events.process_details AS processDetails,
        events.detection_rule AS detectionRule, events.action AS eventAction, events.response_status AS responseStatus,
        alerts.created_at AS createdAt
        FROM alerts LEFT JOIN assets ON assets.id = alerts.asset_id LEFT JOIN device_agents ON device_agents.device_id=alerts.device_id
        LEFT JOIN events ON events.id=alerts.event_id WHERE alerts.id = ?`).get(Number(alertMatch[1]));
    return alert ? json(res, 200, alert) : json(res, 404, { error: "Alert not found" });
  }

  const alertResponse = url.pathname.match(/^\/api\/alerts\/(\d+)\/respond$/);
  if (alertResponse && req.method === "POST") {
    const id = Number(alertResponse[1]), body = await readJson(req);
    const alert = db.prepare(`SELECT al.*,ev.source AS event_source,ev.observed_source_ip,ev.id AS linked_event_id,
      a.type AS asset_type,a.name AS asset_name FROM alerts al
      LEFT JOIN events ev ON ev.id=al.event_id LEFT JOIN assets a ON a.id=al.asset_id WHERE al.id=?`).get(id);
    if (!alert) return json(res, 404, { error: "Alert not found" });
    if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.trim().length > 500) return json(res, 400, { error: "A response reason is required (maximum 500 characters)" });
    const now = new Date().toISOString();
    if (body.action === "dismiss") {
      if (!alert.linked_event_id) return json(res, 409, { error: "This alert has no retained source event to classify" });
      db.prepare("UPDATE alerts SET status='false_positive' WHERE id=?").run(id);
      db.prepare("UPDATE events SET false_positive=1,reviewed_by=?,reviewed_at=? WHERE id=?").run(admin.email, now, alert.linked_event_id);
      recordAudit(db, admin.email, "alert.dismissed_false_positive", `alert:${id}`, `Dismissed alert as a false positive. Reason: ${body.reason.trim()}. Source event ${alert.linked_event_id} and original evidence were preserved.`);
      return json(res, 200, { id, status: "false_positive", eventId: alert.linked_event_id, reviewedBy: admin.email, reviewedAt: now });
    }
    if (body.action === "allowlist") {
      if (admin.role !== "owner") return json(res, 403, { error: "Only an owner can change an asset allowlist" });
      const ip = alert.observed_source_ip;
      if (alert.event_source !== "website-gateway" || alert.asset_type !== "website" || !ip || !net.isIP(ip)) return json(res, 409, { error: "Only an exact source IP observed by a website gateway can be allowlisted from this alert" });
      db.prepare("INSERT OR IGNORE INTO gateway_allowlist(asset_id,ip,created_at) VALUES(?,?,?)").run(alert.asset_id, ip, now);
      recordAudit(db, admin.email, "alert.source_ip_allowlisted", `alert:${id}`, `Added exact observed IP ${ip} to website asset ${alert.asset_id} allowlist. Reason: ${body.reason.trim()}. This is scoped to this website only.`);
      return json(res, 200, { id, assetId: alert.asset_id, ip, scope: "single website asset" });
    }
    return json(res, 400, { error: "Action must be dismiss or allowlist; blocks must be created from a reviewed firewall preview" });
  }

  if (url.pathname === "/api/alerts" && req.method === "GET") {
    const clauses = [];
    const values = [];
    for (const [param, column] of [["deviceId", "device_id"], ["severity", "severity"]]) {
      const value = url.searchParams.get(param);
      if (value) { clauses.push(`alerts.${column} = ?`); values.push(value); }
    }
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    if (from && /^\d{4}-\d{2}-\d{2}$/.test(from)) { clauses.push("alerts.created_at >= ?"); values.push(`${from}T00:00:00.000Z`); }
    if (to && /^\d{4}-\d{2}-\d{2}$/.test(to)) { clauses.push("alerts.created_at <= ?"); values.push(`${to}T23:59:59.999Z`); }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    return json(
      res,
      200,
      db
        .prepare(
          `SELECT alerts.id, alerts.asset_id AS assetId, alerts.device_id AS deviceId, alerts.title, alerts.severity, alerts.status, alerts.evidence,
        alerts.observed_facts AS observedFacts, alerts.estimate, device_agents.name AS deviceName, alerts.created_at AS createdAt
        FROM alerts LEFT JOIN device_agents ON device_agents.device_id=alerts.device_id ${where} ORDER BY alerts.created_at DESC LIMIT 100`
        )
        .all(...values)
    );
  }

  if (url.pathname === "/api/events" && req.method === "GET") {
    const clauses = [];
    const values = [];
    for (const key of ["assetId", "severity", "deviceId"]) {
      const value = url.searchParams.get(key);
      if (value) { clauses.push(`events.${key === "assetId" ? "asset_id" : key === "deviceId" ? "device_id" : "severity"} = ?`); values.push(value); }
    }
    for (const [param, column, operator] of [["from", "created_at", ">="], ["to", "created_at", "<="], ["sourceIp", "observed_source_ip", "="], ["action", "action", "="]]) {
      let value = url.searchParams.get(param);
      if (value && (param === "from" || param === "to") && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
        value = `${value}T${param === "from" ? "00:00:00.000" : "23:59:59.999"}Z`;
      }
      if (value) { clauses.push(`events.${column} ${operator} ?`); values.push(value); }
    }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const events = db.prepare(`SELECT events.id, events.asset_id AS assetId, assets.name AS assetName, events.source, events.category, events.action, events.reason, events.evidence,
      events.observed_source_ip AS observedSourceIp, events.request_details AS requestDetails, events.process_details AS processDetails,
      events.severity, events.method, events.request_path AS path, events.user_agent AS userAgent, events.response_status AS responseStatus,
      events.false_positive AS falsePositive,events.reviewed_by AS reviewedBy,events.reviewed_at AS reviewedAt,
      events.detection_rule AS detectionRule, events.device_id AS deviceId, device_agents.name AS deviceName, events.created_at AS createdAt FROM events LEFT JOIN assets ON assets.id = events.asset_id LEFT JOIN device_agents ON device_agents.device_id=events.device_id
      ${where} ORDER BY events.created_at DESC LIMIT 500`).all(...values);
    return json(res, 200, events);
  }

  if (url.pathname === "/api/audit-log" && req.method === "GET") {
    return json(
      res,
      200,
      db.prepare("SELECT id, actor, action, target, detail, created_at AS createdAt FROM audit_log ORDER BY created_at DESC LIMIT 250").all()
    );
  }

  if (url.pathname === "/api/retention/run" && req.method === "POST") {
    const body = await readJson(req);
    const settings = db.prepare("SELECT raw_event_days,report_days FROM incident_settings WHERE id=1").get();
    const rawEventDays = body.rawEventDays ?? body.days ?? settings.raw_event_days;
    const reportDays = body.reportDays ?? settings.report_days;
    if (!Number.isInteger(rawEventDays) || rawEventDays < 1 || rawEventDays > 3650 || !Number.isInteger(reportDays) || reportDays < 1 || reportDays > 3650) return json(res, 400, { error: "Raw-event and report retention must each be 1 to 3650 days" });
    const cutoff = new Date(Date.now() - rawEventDays * 86_400_000).toISOString();
    const reportCutoff = new Date(Date.now() - reportDays * 86_400_000).toISOString();
    const deletedEvents = db.prepare("DELETE FROM events WHERE created_at < ?").run(cutoff).changes;
    const deletedGatewayMetrics = db.prepare("DELETE FROM gateway_request_metrics WHERE observed_at < ?").run(cutoff).changes;
    const deletedGatewayOutbox = db.prepare("DELETE FROM gateway_event_outbox WHERE created_at < ?").run(cutoff).changes;
    const deletedReports = db.prepare("DELETE FROM incident_reports WHERE expires_at<=? OR created_at<?").run(new Date().toISOString(), reportCutoff).changes;
    const deletedAudit = db.prepare("DELETE FROM audit_log WHERE created_at < ?").run(cutoff).changes;
    if(deletedEvents||deletedGatewayMetrics||deletedGatewayOutbox||deletedReports||deletedAudit)db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
    recordAudit(db, admin.email, "retention.run", "local-data", `Deleted ${deletedEvents} event rows, ${deletedGatewayMetrics} gateway timing rows, ${deletedGatewayOutbox} queued gateway events, ${deletedReports} report snapshots, and ${deletedAudit} audit rows; raw retention ${rawEventDays} days, report retention ${reportDays} days.`);
    return json(res, 200, { deletedEvents, deletedGatewayMetrics, deletedGatewayOutbox, deletedReports, deletedAudit, cutoff, reportCutoff });
  }

  if (url.pathname.startsWith("/api/")) {
    return json(res, 404, { error: "Not found" });
  }

  return serveStatic(req, res, config.webRoot);
}

function incidentListItem(db, row) {
  const assets = db.prepare(`SELECT DISTINCT a.id,a.name,a.type FROM incident_events ie JOIN events e ON e.id=ie.event_id JOIN assets a ON a.id=e.asset_id WHERE ie.incident_id=? ORDER BY a.name`).all(row.id);
  const devices = db.prepare(`SELECT DISTINCT d.device_id AS id,d.name FROM incident_events ie JOIN events e ON e.id=ie.event_id JOIN device_agents d ON d.device_id=e.device_id WHERE ie.incident_id=? ORDER BY d.name`).all(row.id);
  const retainedEvidenceCount = db.prepare("SELECT COUNT(*) AS count FROM incident_events WHERE incident_id=?").get(row.id).count;
  return { id: row.id, severity: row.severity, status: row.status, detectionRule: row.detection_rule, observedIp: row.observed_ip, firstSeen: row.first_seen, lastSeen: row.last_seen, eventCount: row.event_count, retainedEvidenceCount, assets, devices };
}

function dateFilter(value, end) {
  if (!value) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return `${value}T${end ? "23:59:59.999" : "00:00:00.000"}Z`;
  return validDate(value) ? value : null;
}

function download(res, status, content, contentType, filename) {
  res.writeHead(status, { "Content-Type": contentType, "Content-Length": Buffer.byteLength(content), "Content-Disposition": `attachment; filename="${filename}"`, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" });
  res.end(content);
}

function setupRequired(db) {
  return db.prepare("SELECT COUNT(*) AS count FROM admins").get().count === 0;
}

function currentAdmin(req, db, config) {
  const token = parseCookies(req.headers.cookie ?? "")[cookieName(config)];
  const session = verifySession(token, config.sessionSecret);
  if (!session) {
    return null;
  }
  if(db.prepare("SELECT 1 FROM revoked_sessions WHERE session_id=?").get(session.jti))return null;
  return db.prepare("SELECT id, email, role FROM admins WHERE id = ?").get(Number(session.sub)) ?? null;
}

function queueDeviceConfig(db, device, createdAt) {
  const version = Number(device.config_version);
  const config = { collectProcesses: Boolean(device.collection_processes), collectConnections: Boolean(device.collection_connections),
    collectApplications: Boolean(device.collection_applications), collectServices: Boolean(device.collection_services), collectStartup: Boolean(device.collection_startup), collectSecurity: Boolean(device.collection_security),
    intervalSeconds: device.collection_interval_seconds, outboundConnectionThreshold: device.outbound_connection_threshold, retainedDays: device.retained_days };
  db.prepare("INSERT INTO device_config_updates(device_id,version,config_json,status,created_at) VALUES(?,?,?,'pending',?) ON CONFLICT(device_id,version) DO UPDATE SET config_json=excluded.config_json")
    .run(device.device_id, version, JSON.stringify(config), createdAt);
}

function validateCredentials(body, setup) {
  if (!body || typeof body.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email) || body.email.length > 254) {
    return "A valid email address is required";
  }
  if (typeof body.password !== "string" || body.password.length < (setup ? 12 : 1) || body.password.length > 1024) {
    return setup ? "Password must be 12 to 1024 characters" : "Password must be 1 to 1024 characters";
  }
  return null;
}

function validateAsset(body) {
  if (!body || typeof body !== "object") return "Asset details are required";
  if (typeof body.name !== "string" || !body.name.trim() || body.name.trim().length > 100) return "Name is required (maximum 100 characters)";
  if (!["website", "application", "computer"].includes(body.type)) return "Type must be website, application, or computer";
  if (typeof body.address !== "string" || !body.address.trim() || body.address.trim().length > 255) return "Address is required (maximum 255 characters)";
  if (typeof body.description !== "string" || body.description.length > 1000) return "Description is required (maximum 1000 characters)";
  return null;
}

function validateProtection(body) {
  if (!body || typeof body !== "object") return "Protection settings are required";
  if (typeof body.upstreamUrl !== "string" || body.upstreamUrl.length > 2048) return "A valid upstream URL is required";
  try {
    const upstream = new URL(body.upstreamUrl);
    if (!["http:", "https:"].includes(upstream.protocol) || !upstream.hostname || upstream.username || upstream.password || upstream.hash) return "Upstream must be HTTP or HTTPS without embedded credentials or a fragment";
  } catch { return "A valid upstream URL is required"; }
  if (typeof body.enabled !== "boolean" || !["observe", "challenge-ready", "block"].includes(body.mode)) return "Rule enabled state or mode is invalid";
  if (body.failureMode !== undefined && !["open","closed"].includes(body.failureMode)) return "Failure behavior must be open or closed";
  if (!Number.isInteger(body.rateLimitCount) || body.rateLimitCount < 1 || body.rateLimitCount > 100000) return "Rate limit must be from 1 to 100000 requests";
  if (!Number.isInteger(body.windowSeconds) || body.windowSeconds < 1 || body.windowSeconds > 3600) return "Rate window must be from 1 to 3600 seconds";
  if (typeof body.sensitivePathsEnabled !== "boolean") return "Sensitive-path enabled state must be boolean";
  if (!Array.isArray(body.allowlist) || body.allowlist.length > 100 || body.allowlist.some((ip) => typeof ip !== "string" || !net.isIP(ip))) return "Allowlist must contain up to 100 exact IPv4 or IPv6 addresses";
  if (new Set(body.allowlist).size !== body.allowlist.length) return "Allowlist addresses must be unique";
  return null;
}

function validateGatewayEvent(body) {
  if (!body || !Number.isInteger(body.assetId)) return "A valid asset ID is required";
  if (typeof body.timestamp !== "string" || !Number.isFinite(Date.parse(body.timestamp))) return "A valid timestamp is required";
  if (typeof body.sourceIp !== "string" || !net.isIP(body.sourceIp)) return "A valid observed source IP is required";
  if (typeof body.method !== "string" || !/^[A-Z]{1,20}$/.test(body.method)) return "A valid HTTP method is required";
  if (typeof body.path !== "string" || !body.path.startsWith("/") || body.path.length > 2048 || /[\r\n]/.test(body.path)) return "A valid request path is required";
  if (typeof body.userAgent !== "string" || body.userAgent.length > 1000) return "User agent must be 1000 characters or fewer";
  if (!Number.isInteger(body.responseStatus) || body.responseStatus < 100 || body.responseStatus > 599) return "A valid response status is required";
  if (typeof body.detectionRule !== "string" || !/^(none|sensitive_path|rate_limit|upstream_unavailable|allowlist|websocket_unsupported|approved_block)$/.test(body.detectionRule)) return "Unknown detection rule";
  if (typeof body.action !== "string" || !/^(forwarded|observed|challenge-ready|blocked|allowlisted|upstream-error|unsupported)$/.test(body.action)) return "Unknown action";
  if (typeof body.severity !== "string" || !/^(info|low|medium|high|critical)$/.test(body.severity)) return "Unknown event severity";
  if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 2000) return "A detection reason is required";
  return null;
}

function alertTitle(rule) {
  return ({
    sensitive_path: "Sensitive path request",
    rate_limit: "Per-IP rate limit exceeded",
    upstream_unavailable: "Protected website upstream unavailable",
    websocket_unsupported: "WebSocket request not supported",
    approved_block: "Administrator-approved temporary block"
  })[rule] ?? "Gateway detection";
}

function tokenHash(token) { return crypto.createHash("sha256").update(token).digest("hex"); }
function firewallRuleForAgent(rule) {
  const remove = ["removing", "expired", "removed"].includes(rule.status) || Date.parse(rule.expires_at) <= Date.now();
  return { id: rule.id, name: `SentryGate-${rule.id}`, group: "SentryGate", kind: "inbound", status: rule.status, operation: remove ? "remove" : "ensure", remoteAddress: rule.remote_cidr, protocol: rule.protocol, localPort: rule.local_port, expiresAt: rule.expires_at };
}
function firewallRuleForDashboard(rule) {
  return { id: rule.id, deviceId: rule.device_id, deviceName: rule.device_name ?? "", incidentId: rule.incident_id ?? null, remoteCidr: rule.remote_cidr, protocol: rule.protocol, localPort: rule.local_port, reason: rule.reason, evidence: rule.evidence, expiresAt: rule.expires_at, status: rule.status, createdBy: rule.created_by, createdAt: rule.created_at, approvedBy: rule.approved_by, approvedAt: rule.approved_at, appliedAt: rule.applied_at, actualState: rule.actual_state ? JSON.parse(rule.actual_state) : null, failure: rule.failure, rollbackAt: rule.rollback_at };
}
function deviceSettingsFor(device) { return { collectProcesses: Boolean(device.collection_processes), collectConnections: Boolean(device.collection_connections), collectApplications: Boolean(device.collection_applications), collectServices: Boolean(device.collection_services), collectStartup: Boolean(device.collection_startup), collectSecurity: Boolean(device.collection_security), intervalSeconds: device.collection_interval_seconds, outboundConnectionThreshold: device.outbound_connection_threshold, retainedDays: device.retained_days }; }
function applicationPolicyForAgent(policy) {
  const remove = ["removing", "expired", "removed"].includes(policy.status) || Date.parse(policy.expires_at) <= Date.now();
  return { id: policy.id, name: `SentryGate-App-${policy.id}`, group: "SentryGate", kind: "application", operation: remove ? "remove" : "ensure",
    programPath: policy.program_path, policyMode: policy.mode, action: policy.mode === "allow" ? "Allow" : "Block", direction: "Inbound",
    expiresAt: policy.expires_at, status: policy.status };
}
function applicationPolicyForDashboard(policy) {
  return { id: policy.id, deviceId: policy.device_id, deviceName: policy.device_name ?? "", applicationName: policy.application_name,
    programPath: policy.program_path, mode: policy.mode, reason: policy.reason, evidence: policy.evidence, expiresAt: policy.expires_at,
    status: policy.status, createdBy: policy.created_by, createdAt: policy.created_at, approvedBy: policy.approved_by, approvedAt: policy.approved_at,
    preview: JSON.parse(policy.preview_json), actualState: policy.actual_state ? JSON.parse(policy.actual_state) : null, failure: policy.failure, rollbackAt: policy.rollback_at };
}
function expireApplicationPolicies(db, now = new Date().toISOString()) {
  const expired = db.prepare("SELECT id FROM application_network_policies WHERE status IN ('proposed','approved','active','failed','review') AND expires_at<=?").all(now);
  for (const row of expired) {
    db.prepare("UPDATE application_network_policies SET status='expired',updated_at=? WHERE id=?").run(now, row.id);
    recordAudit(db, "system", "firewall.application_policy_expired", `application-policy:${row.id}`, "Policy expiry reached; authenticated device helper removal is queued.");
  }
}
function validateApplicationPolicy(body, db, now = Date.now()) {
  if (!body || typeof body !== "object") return "Application policy details are required";
  if (typeof body.deviceId !== "string" || !/^[a-f0-9-]{36}$/i.test(body.deviceId)) return "Select a valid enrolled device";
  if (typeof body.applicationName !== "string" || !body.applicationName.trim() || body.applicationName.length > 260) return "Application name is required (maximum 260 characters)";
  if (typeof body.programPath !== "string" || body.programPath.length > 2048 || !path.win32.isAbsolute(body.programPath) || !/\.exe$/i.test(body.programPath) || /[\r\n\0"]/.test(body.programPath)) return "An absolute Windows executable path is required";
  if (!["allow", "block", "review"].includes(body.mode)) return "Mode must be allow, block, or review";
  if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 500 || typeof body.evidence !== "string" || !body.evidence.trim() || body.evidence.length > 2000) return "A reason and evidence (up to 2000 characters) are required";
  if (!validDate(body.expiresAt) || Date.parse(body.expiresAt) <= now || Date.parse(body.expiresAt) > now + 365 * 86_400_000) return "Expiry must be in the future and within one year";
  if (typeof body.idempotencyKey !== "string" || !/^[a-f0-9-]{36}$/i.test(body.idempotencyKey)) return "A UUID idempotency key is required";
  if (!db.prepare("SELECT 1 FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(body.deviceId)) return "Select a non-demo enrolled device";
  return null;
}
function safeTokenMatches(token, expectedHex) {
  if (typeof token !== "string" || token.length < 32 || token.length > 256) return false;
  const actual = Buffer.from(tokenHash(token), "hex");
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function validateDeviceEnrollment(body) {
  if (!body || typeof body !== "object") return "Device details are required";
  for (const key of ["name", "hostname", "osVersion", "agentVersion"]) {
    if (typeof body[key] !== "string" || !body[key].trim() || body[key].length > 200) return `${key} is required (maximum 200 characters)`;
  }
  return null;
}

function validateActionPolicy(body, db) {
  if (!body || typeof body !== "object") return "Policy details are required";
  if (typeof body.name !== "string" || !body.name.trim() || body.name.length > 100) return "Policy name is required (maximum 100 characters)";
  if (!Number.isInteger(body.assetId) || !db.prepare("SELECT 1 FROM assets WHERE id=? AND removed_at IS NULL").get(body.assetId)) return "Select an existing active affected asset";
  if (body.detectionRule !== undefined && (typeof body.detectionRule !== "string" || body.detectionRule.length > 100 || !/^[a-zA-Z0-9_.:*:-]+$/.test(body.detectionRule))) return "Detection rule must be a rule identifier or *";
  if (!['low', 'medium', 'high', 'critical'].includes(body.minimumSeverity)) return "Minimum severity must be low, medium, high, or critical";
  if (!Number.isInteger(body.minimumEventCount) || body.minimumEventCount < 2 || body.minimumEventCount > 100) return "Minimum event count must be from 2 to 100";
  if (!Number.isInteger(body.windowMinutes) || body.windowMinutes < 1 || body.windowMinutes > 1440) return "Policy window must be from 1 to 1440 minutes";
  if (!['device', 'website'].includes(body.targetType) || typeof body.targetId !== 'string' && typeof body.targetId !== 'number') return "Select a device or website destination";
  if (!['observe','recommend','enforce'].includes(body.mode ?? 'observe')) return "Mode must be observe, recommend, or enforce";
  if ((body.mode ?? 'observe') === 'enforce' && body.targetType !== 'device') return "Enforce mode is currently limited to an enrolled Windows computer";
  if (!Number.isInteger(body.durationMinutes) || body.durationMinutes < 1 || body.durationMinutes > 1440) return "Temporary action duration must be from 1 to 1440 minutes";
  if (body.targetType === "device") {
    const target = db.prepare("SELECT asset_id FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(String(body.targetId));
    if (!target) return "Choose an enrolled, active Windows device";
    if (Number(target.asset_id) !== Number(body.assetId)) return "Destination computer must be the same asset as the policy evidence";
    if (!['TCP', 'UDP'].includes(body.protocol) || !Number.isInteger(body.localPort) || body.localPort < 1 || body.localPort > 65535) return "Device actions require TCP or UDP and a valid destination port";
  } else {
    const target = db.prepare("SELECT type FROM assets WHERE id=? AND removed_at IS NULL").get(Number(body.targetId));
    if (!target || target.type !== "website" || Number(body.targetId) !== Number(body.assetId)) return "Website destination must be the same active asset as the policy evidence";
  }
  return null;
}

function actionPolicyForDashboard(policy) {
  return { id: policy.id, name: policy.name, enabled: Boolean(policy.enabled), mode: policy.mode === "suggestion-only" ? "recommend" : policy.mode, assetId: policy.asset_id,
    assetName: policy.asset_name ?? "", detectionRule: policy.detection_rule, minimumSeverity: policy.minimum_severity,
    minimumEventCount: policy.minimum_event_count, windowMinutes: policy.window_minutes, targetType: policy.target_type,
    targetId: policy.target_id, protocol: policy.protocol, localPort: policy.local_port, durationMinutes: policy.duration_minutes,
    createdBy: policy.created_by, createdAt: policy.created_at };
}

function validateDeviceSettings(body) {
  if (!body || typeof body.collectProcesses !== "boolean" || typeof body.collectConnections !== "boolean" || ["collectApplications", "collectServices", "collectStartup", "collectSecurity"].some((key) => body[key] !== undefined && typeof body[key] !== "boolean")) return "Collection settings must be boolean";
  if (!Number.isInteger(body.intervalSeconds) || body.intervalSeconds < 10 || body.intervalSeconds > 3600) return "Interval must be 10 to 3600 seconds";
  if (!Number.isInteger(body.outboundConnectionThreshold) || body.outboundConnectionThreshold < 5 || body.outboundConnectionThreshold > 10000) return "Outbound threshold must be 5 to 10000";
  if (!Number.isInteger(body.retainedDays) || body.retainedDays < 1 || body.retainedDays > 3650) return "Retention must be 1 to 3650 days";
  return null;
}

function validateDeviceReport(body, deviceId) {
  if (!body || body.device?.deviceId !== deviceId) return "Report device identity does not match";
  if (!["healthy", "degraded"].includes(body.healthStatus) || !validDate(body.timestamp)) return "Report timestamp or health status is invalid";
  if (body.collectionErrors !== undefined && (!Array.isArray(body.collectionErrors) || body.collectionErrors.length > 10 || body.collectionErrors.some((error) => typeof error !== "string" || error.length > 300))) return "Invalid collection health details";
  if (body.backendAddresses !== undefined && (!Array.isArray(body.backendAddresses) || body.backendAddresses.length > 64 || body.backendAddresses.some((address) => typeof address !== "string" || !net.isIP(address)))) return "Invalid backend connection address metadata";
  for (const [key, limit] of [["processes", 10000], ["connections", 20000], ["events", 200]]) {
    if (!Array.isArray(body[key]) || body[key].length > limit) return `${key} must contain no more than ${limit} records`;
  }
  if (body.commandAckNonce !== undefined && (typeof body.commandAckNonce !== "string" || !/^[a-f0-9-]{36}$/i.test(body.commandAckNonce))) return "Invalid one-time command acknowledgement";
  for (const [key, limit] of [["installedApplications", 5000], ["services", 5000], ["startupEntries", 2000]]) if (body[key] !== undefined && (!Array.isArray(body[key]) || body[key].length > limit)) return `Invalid ${key} inventory`;
  for (const field of ["hostname", "osVersion", "agentVersion"]) if (typeof body.device[field] !== "string" || body.device[field].length > 200) return `Invalid device ${field}`;
  for (const process of body.processes) {
    if (!Number.isInteger(process.pid) || process.pid < 0 || typeof process.name !== "string" || process.name.length > 260 || (process.executablePath !== undefined && (typeof process.executablePath !== "string" || process.executablePath.length > 2048))) return "Invalid process metadata";
  }
  for (const app of body.installedApplications ?? []) if (typeof app.name !== "string" || app.name.length > 260 || [app.version,app.publisher,app.installLocation,app.installDate].some((v) => v !== undefined && (typeof v !== "string" || v.length > 2048))) return "Invalid installed application metadata";
  for (const service of body.services ?? []) if (typeof service.name !== "string" || service.name.length > 260 || typeof service.state !== "string" || service.state.length > 30 || typeof service.startMode !== "string" || service.startMode.length > 30 || !Number.isInteger(service.processId)) return "Invalid service metadata";
  for (const entry of body.startupEntries ?? []) if (typeof entry.name !== "string" || entry.name.length > 260 || typeof entry.executablePath !== "string" || entry.executablePath.length > 2048 || typeof entry.source !== "string" || entry.source.length > 500) return "Invalid startup metadata";
  if (body.securitySettings !== undefined && (!body.securitySettings || typeof body.securitySettings !== "object" || !Array.isArray(body.securitySettings.firewallProfiles) || body.securitySettings.firewallProfiles.length > 10 || body.securitySettings.firewallProfiles.some((p) => typeof p.name !== "string" || p.name.length > 30 || typeof p.enabled !== "boolean") || body.securitySettings.defenderRealtimeProtection !== null && typeof body.securitySettings.defenderRealtimeProtection !== "boolean")) return "Invalid security setting metadata";
  for (const connection of body.connections) {
    if (!Number.isInteger(connection.pid) || typeof connection.state !== "string" || connection.state.length > 30 ||
        !Number.isInteger(connection.localPort) || connection.localPort < 0 || connection.localPort > 65535 ||
        !Number.isInteger(connection.remotePort) || connection.remotePort < 0 || connection.remotePort > 65535 ||
        [connection.localAddress, connection.remoteAddress].some((address) => typeof address !== "string" || address.length > 64) ||
        !validDate(connection.timestamp)) return "Invalid network connection metadata";
  }
  for (const item of body.events) {
    if (typeof item.eventId !== "string" || item.eventId.length > 80 || !validDate(item.timestamp) ||
        typeof item.category !== "string" || item.category.length > 100 ||
        typeof item.rule !== "string" || !/^[a-zA-Z0-9_.:-]{1,100}$/.test(item.rule) ||
        typeof item.title !== "string" || item.title.length > 200 || typeof item.reason !== "string" || item.reason.length > 2000 ||
        [item.processDetails, item.connectionDetails].some((value) => value !== undefined && (typeof value !== "string" || value.length > 2000)) ||
        (item.remoteAddress !== undefined && (typeof item.remoteAddress !== "string" || item.remoteAddress.length > 64 || (item.remoteAddress && !net.isIP(item.remoteAddress)))) ||
        !["low", "medium", "high", "critical"].includes(item.severity)) return "Invalid detection event";
  }
  return null;
}
function validDate(value) { return typeof value === "string" && Number.isFinite(Date.parse(value)); }

async function readJson(req, maxBytes = 1_000_000) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > maxBytes) {
      throw Object.assign(new Error("Request body too large"), { statusCode: 413 });
    }
  }
  try { return raw ? JSON.parse(raw) : {}; }
  catch { throw Object.assign(new Error("Invalid JSON"), { statusCode: 400 }); }
}

function json(res, status, body) {
  const content = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(content),
    "X-Content-Type-Options": "nosniff"
  });
  res.end(content);
}

function empty(res, status) {
  res.writeHead(status);
  res.end();
}

function setCookie(res, token, config) {
  const secure = config.cookieSecure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${cookieName(config)}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
}

function clearCookie(res, config) {
  const secure = config.cookieSecure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${cookieName(config)}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

function databaseCapacityReached(config) {
  const total=databaseBytes(config.dbPath);
  if(total<config.maxDbBytes)return false;
  logOperational("error","storage.limit_reached",{bytes:total,limitBytes:config.maxDbBytes});
  return true;
}

function storageStatus(config,bytes) {
  let freeBytes=null;
  try { const stats=fs.statfsSync(config.dataDir??path.dirname(config.dbPath)); freeBytes=stats.bavail*stats.bsize; } catch { /* Filesystem free-space reporting is not available on every platform. */ }
  const usedPercent=Math.min(100,Math.round(bytes/config.maxDbBytes*100));
  const warningPercent=config.storageWarningPercent??80;
  const lowDisk=freeBytes!==null&&config.minFreeDiskBytes>0&&freeBytes<=config.minFreeDiskBytes;
  return { dataDirectory:path.resolve(config.dataDir??path.dirname(config.dbPath)), databasePath:path.resolve(config.dbPath), storageBytes:bytes, storageLimitBytes:config.maxDbBytes, storageUsedPercent:usedPercent, freeBytes, minimumFreeBytes:config.minFreeDiskBytes, warningPercent, warning:usedPercent>=warningPercent||bytes>=config.maxDbBytes||lowDisk, lowDisk, full:bytes>=config.maxDbBytes };
}

function sameRequestOrigin(origin,req){const parsed=new URL(origin),scheme=req.socket.encrypted?"https:":"http:";return parsed.protocol===scheme&&parsed.host===req.headers.host&&!parsed.username&&!parsed.password;}

function parseCookies(header) {
  return Object.fromEntries(
    header
      .split(";")
      .map((pair) => pair.trim())
      .filter(Boolean)
      .map((pair) => {
        const index = pair.indexOf("=");
        return [pair.slice(0, index), pair.slice(index + 1)];
      })
  );
}

function serveStatic(req, res, webRoot) {
  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
  const filePath = path.resolve(webRoot, `.${pathname}`);
  if (!filePath.startsWith(path.resolve(webRoot))) {
    return empty(res, 403);
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    return empty(res, 404);
  }
  res.writeHead(200, {
    "Content-Type": mimeType(filePath),
    "X-Content-Type-Options": "nosniff"
  });
  fs.createReadStream(filePath).pipe(res);
}

function mimeType(filePath) {
  if (filePath.endsWith(".html")) return "text/html; charset=utf-8";
  if (filePath.endsWith(".css")) return "text/css; charset=utf-8";
  if (filePath.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (filePath.endsWith(".svg")) return "image/svg+xml";
  return "application/octet-stream";
}
