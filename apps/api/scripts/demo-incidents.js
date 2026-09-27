import crypto from "node:crypto";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { correlateEvent } from "../src/incidents.js";
import { evaluateIncidentPolicies } from "../src/actions.js";
import { recordAudit } from "../src/audit.js";

const config = loadConfig();
const db = openDatabase(config.dbPath);
const runId = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
const now = Date.now();
const timestamp = (minutesAgo) => new Date(now - minutesAgo * 60_000).toISOString();
const sourceIp = "198.51.100.77";

try {
  const addAsset = db.prepare("INSERT INTO assets (name,type,owner,status,address,description,created_at) VALUES (?,?,?,?,?,?,?)");
  const websiteId = Number(addAsset.run(`Demo website ${runId}`, "website", "SentryGate demo", "healthy", "https://demo.invalid", "Synthetic incident demonstration asset", timestamp(5)).lastInsertRowid);
  const computerId = Number(addAsset.run(`Demo workstation ${runId}`, "computer", "SentryGate demo", "healthy", "SG-DEMO-01", "Synthetic incident demonstration asset", timestamp(5)).lastInsertRowid);
  const deviceId = crypto.randomUUID();
  db.prepare(`INSERT INTO device_agents (device_id,name,hostname,os_version,agent_version,credential_hash,enrolled_at,last_heartbeat,health_status,is_demo,asset_id)
    VALUES (?,?,?,?,?,?,?,?,?,1,?)`).run(deviceId, `Demo device ${runId}`, "SG-DEMO-01", "Windows (simulated)", "0.5.0-demo", crypto.randomBytes(32).toString("hex"), timestamp(5), timestamp(0), "healthy", computerId);

  const insertEvent = db.prepare(`INSERT INTO events (asset_id,source,category,action,reason,evidence,observed_source_ip,request_details,process_details,severity,method,request_path,user_agent,response_status,detection_rule,device_id,source_event_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const ids = [];
  for (const [i, item] of [
    { assetId: websiteId, source: "gateway", category: "request", details: "GET /.env", path: "/.env", rule: "sensitive_path", reason: "Sensitive configuration path requested", action: "observed", severity: "medium", device: null },
    { assetId: websiteId, source: "application", category: "security", details: "Application reported a request to /.env", path: "/.env", rule: "sensitive_path", reason: "Application reported a sensitive-path request", action: "recorded", severity: "medium", device: null },
    { assetId: websiteId, source: "gateway", category: "request", details: "GET /.git/config", path: "/.git/config", rule: "sensitive_path", reason: "Sensitive repository metadata path requested", action: "observed", severity: "high", device: null },
    { assetId: computerId, source: "windows-agent", category: "endpoint-detection", details: "PID 4120 · sample-worker.exe · TCP outbound", path: "", rule: "outbound_connection_volume", reason: "Process exceeded the configured outbound connection threshold", action: "observed", severity: "medium", device: deviceId },
    { assetId: computerId, source: "windows-agent", category: "endpoint-detection", details: "PID 4120 · sample-worker.exe · TCP outbound", path: "", rule: "outbound_connection_volume", reason: "Process exceeded the configured outbound connection threshold", action: "observed", severity: "medium", device: deviceId },
    { assetId: computerId, source: "windows-agent", category: "endpoint-detection", details: "PID 4120 · sample-worker.exe · TCP outbound", path: "", rule: "outbound_connection_volume", reason: "Process exceeded the configured outbound connection threshold", action: "observed", severity: "medium", device: deviceId }
  ].entries()) {
    const createdAt = timestamp(4 - i * 0.4);
    const id = Number(insertEvent.run(item.assetId, item.source, item.category, item.action, item.reason,
      JSON.stringify({ simulated: true, sample: i + 1, details: item.details }), sourceIp, item.details,
      item.device ? "PID 4120 · sample-worker.exe" : "", item.severity, item.method || "GET", item.path,
      "SentryGate synthetic demonstration client (unverified)", 200, item.rule, item.device,
      crypto.randomUUID(), createdAt).lastInsertRowid);
    ids.push(id);
    correlateEvent(db, id);
  }
  const policyId = crypto.randomUUID(), policyName = `Demo suggestion policy ${runId}`, policyTime = new Date().toISOString();
  db.prepare(`INSERT INTO action_policies (id,name,enabled,mode,asset_id,detection_rule,minimum_severity,minimum_event_count,window_minutes,target_type,target_id,protocol,local_port,duration_minutes,created_by,created_at,updated_at)
    VALUES (?, ?, 1, 'suggestion-only', ?, 'sensitive_path', 'high', 3, 10, 'website', ?, 'TCP', 443, 5, 'demo-command', ?, ?)`).run(policyId, policyName, websiteId, String(websiteId), policyTime, policyTime);
  const webIncident = db.prepare("SELECT id FROM incidents WHERE asset_id=? AND observed_ip=? AND detection_rule='sensitive_path' ORDER BY created_at DESC LIMIT 1").get(websiteId, sourceIp);
  const actionIds = webIncident ? evaluateIncidentPolicies(db, webIncident.id) : [];
  recordAudit(db, "demo-command", "incident.demo_seeded", `demo:${runId}`, `Inserted ${ids.length} synthetic website, application, and device events from ${sourceIp}. No traffic was sent and no firewall action was taken.`);
  const incidents = db.prepare(`SELECT i.id,i.severity,i.status,i.event_count AS eventCount,i.detection_rule AS rule,i.observed_ip AS observedIp,
    a.name AS assetName FROM incidents i LEFT JOIN assets a ON a.id=i.asset_id WHERE i.asset_id IN (?,?) AND i.first_seen>=? ORDER BY i.first_seen`).all(websiteId, computerId, timestamp(10));
  console.log(`Inserted ${ids.length} synthetic events and created/updated ${incidents.length} incidents in ${config.dbPath}.`);
  for (const incident of incidents) console.log(`${incident.id} | ${incident.assetName} | ${incident.eventCount} events | ${incident.severity} | ${incident.rule} | observed endpoint ${incident.observedIp}`);
  for (const id of actionIds) console.log(`Suggestion-only action proposal: ${id} | website ${websiteId} | ${sourceIp} | expires in 5 minutes | no block applied`);
  console.log("Open Investigation and Actions after signing in. All generated records are synthetic; no traffic or firewall rules were changed.");
} finally {
  db.close();
}
