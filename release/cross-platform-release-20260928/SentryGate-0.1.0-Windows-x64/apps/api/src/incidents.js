import crypto from "node:crypto";
import net from "node:net";
import { recordAudit } from "./audit.js";
import { evaluateIncidentPolicies } from "./actions.js";

const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function correlateEvent(db, eventId) {
  const event = db.prepare("SELECT * FROM events WHERE id=?").get(eventId);
  if (!event || !event.detection_rule || event.detection_rule === "none" || event.detection_rule === "allowlist" || event.severity === "info" || !net.isIP(event.observed_source_ip)) return null;
  if (!event.asset_id && !event.device_id) return null;
  const scopeType = event.asset_id ? "asset" : "device";
  const scopeId = event.asset_id ?? event.device_id;
  const key = `${scopeType}:${scopeId}|${event.observed_source_ip}|${event.detection_rule}`;
  const settings = db.prepare("SELECT correlation_threshold,correlation_window_minutes FROM incident_settings WHERE id=1").get();
  const windowMs = settings.correlation_window_minutes * 60_000;
  const timestamp = Date.parse(event.created_at);
  const lower = new Date(timestamp - windowMs).toISOString();
  const upper = event.created_at;
  const matching = db.prepare(`SELECT id,created_at,severity FROM events WHERE observed_source_ip=? AND detection_rule=? AND severity<>'info'
    AND created_at>=? AND created_at<=? AND ${scopeType === "asset" ? "asset_id=?" : "asset_id IS NULL AND device_id=?"} ORDER BY created_at,id`)
    .all(event.observed_source_ip, event.detection_rule, lower, upper, scopeId);
  const current = db.prepare("SELECT * FROM incidents WHERE correlation_key=? AND last_seen>=? AND last_seen<=? ORDER BY last_seen DESC LIMIT 1").get(key, lower, new Date(timestamp + windowMs).toISOString());
  const now = new Date().toISOString();
  if (current) {
    const linked = db.prepare("INSERT OR IGNORE INTO incident_events (incident_id,event_id,linked_at) VALUES (?,?,?)").run(current.id, event.id, now);
    if (linked.changes) {
      const firstSeen = event.created_at < current.first_seen ? event.created_at : current.first_seen;
      const lastSeen = event.created_at > current.last_seen ? event.created_at : current.last_seen;
      const severity = severityRank[event.severity] > severityRank[current.severity] ? event.severity : current.severity;
      const status = current.status === "resolved" ? "open" : current.status;
      db.prepare("UPDATE incidents SET first_seen=?,last_seen=?,event_count=event_count+1,severity=?,status=?,updated_at=? WHERE id=?")
        .run(firstSeen, lastSeen, severity, status, now, current.id);
      if (current.status === "resolved") recordAudit(db, "system", "incident.reopened", `incident:${current.id}`, "A new matching event arrived within the configured correlation window.");
    }
    evaluateIncidentPolicies(db, current.id);
    return current.id;
  }
  if (matching.length < settings.correlation_threshold) return null;
  const id = crypto.randomUUID();
  const maxSeverity = matching.reduce((max, item) => severityRank[item.severity] > severityRank[max] ? item.severity : max, "info");
  const firstSeen = matching[0].created_at, lastSeen = matching.at(-1).created_at;
  db.prepare(`INSERT INTO incidents (id,correlation_key,asset_id,device_id,observed_ip,detection_rule,severity,status,first_seen,last_seen,event_count,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,'open',?,?,?,?,?)`).run(id, key, event.asset_id, event.device_id, event.observed_source_ip, event.detection_rule, maxSeverity, firstSeen, lastSeen, matching.length, now, now);
  const link = db.prepare("INSERT OR IGNORE INTO incident_events (incident_id,event_id,linked_at) VALUES (?,?,?)");
  for (const item of matching) link.run(id, item.id, now);
  recordAudit(db, "system", "incident.created", `incident:${id}`, `Created from ${matching.length} distinct events matching ${scopeType} ${scopeId}, observed endpoint ${event.observed_source_ip}, rule ${event.detection_rule} within ${settings.correlation_window_minutes} minutes.`);
  evaluateIncidentPolicies(db, id);
  return id;
}

export function incidentDetail(db, incidentId) {
  const incident = db.prepare(`SELECT i.*,a.name AS asset_name,d.name AS device_name FROM incidents i
    LEFT JOIN assets a ON a.id=i.asset_id LEFT JOIN device_agents d ON d.device_id=i.device_id WHERE i.id=?`).get(incidentId);
  if (!incident) return null;
  const events = db.prepare(`SELECT e.id,e.created_at AS timestamp,e.source,e.category,e.action,e.reason,e.evidence,
    e.observed_source_ip AS observedSourceIp,e.request_details AS requestDetails,e.process_details AS processDetails,
    e.method,e.request_path AS path,e.user_agent AS userAgent,e.response_status AS responseStatus,
    e.detection_rule AS detectionRule,e.severity,a.id AS assetId,a.name AS assetName,d.device_id AS deviceId,d.name AS deviceName
    FROM incident_events ie JOIN events e ON e.id=ie.event_id LEFT JOIN assets a ON a.id=e.asset_id
    LEFT JOIN device_agents d ON d.device_id=e.device_id WHERE ie.incident_id=? ORDER BY e.created_at,e.id`).all(incidentId);
  const notes = db.prepare("SELECT id,actor,note,created_at AS createdAt FROM incident_notes WHERE incident_id=? ORDER BY created_at,id").all(incidentId);
  const activity = db.prepare("SELECT actor,action,detail,created_at AS createdAt FROM audit_log WHERE target=? ORDER BY created_at,id").all(`incident:${incidentId}`);
  const assets = [...new Map(events.filter((e) => e.assetId).map((e) => [e.assetId, { id: e.assetId, name: e.assetName }])).values()];
  const devices = [...new Map(events.filter((e) => e.deviceId).map((e) => [e.deviceId, { id: e.deviceId, name: e.deviceName }])).values()];
  const actionsTaken = [...new Set(events.map((item) => `${item.source}: ${item.action}`))];
  return { id: incident.id, severity: incident.severity, status: incident.status, detectionRule: incident.detection_rule, observedIp: incident.observed_ip, firstSeen: incident.first_seen, lastSeen: incident.last_seen, eventCount: incident.event_count, retainedEvidenceCount: events.length, assets, devices, events, notes, activity, actionsTaken,
    observedFacts: `${incident.event_count} distinct matching event records were associated with this incident. ${events.length} raw evidence records are currently retained for ${incident.observed_ip} under rule ${incident.detection_rule}. The IP address is an observed network endpoint, not a verified person's identity.`,
    inference: "Correlation means the configured asset/endpoint/rule/time conditions matched. It does not establish common authorship, intent, geographic location, or a person's identity." };
}

export function makeIncidentPdf(report) {
  const lines = ["SentryGate Incident Report", `Incident: ${report.id}`, `Status: ${report.status}    Severity: ${report.severity}`, `Rule: ${report.detectionRule}`, `Observed network endpoint: ${report.observedIp}`, `First seen: ${report.firstSeen}`, `Last seen: ${report.lastSeen}`, `Events: ${report.eventCount}    Evidence retained: ${report.retainedEvidenceCount}`, `Affected assets: ${report.assets.map((x) => x.name).join(", ") || "None recorded"}`, `Devices: ${report.devices.map((x) => x.name).join(", ") || "None recorded"}`, "", "Observed facts", report.observedFacts, "", "Inference and limitations", report.inference, "", "Timeline and evidence"];
  for (const item of report.events) {
    lines.push(`${item.timestamp} | ${item.source} | ${item.severity} | ${item.detectionRule} | ${item.action}`);
    lines.push(`Asset/device: ${item.assetName || "—"} / ${item.deviceName || "—"}; observed IP: ${item.observedSourceIp || "—"}`);
    lines.push(`Request/process: ${item.requestDetails || item.processDetails || "—"}; status: ${item.responseStatus || "—"}`);
    lines.push(`Reason: ${item.reason}`); lines.push(`Evidence: ${item.evidence}`);
    if (item.path) lines.push(`Path: ${item.path}`);
    if (item.userAgent) lines.push(`User agent (unverified client string): ${item.userAgent}`);
    lines.push("");
  }
  lines.push("Analyst notes and status history");
  for (const note of report.notes) lines.push(`${note.createdAt} | ${note.actor} | Note: ${note.note}`);
  for (const entry of report.activity) lines.push(`${entry.createdAt} | ${entry.actor} | ${entry.action}: ${entry.detail}`);
  lines.push("", "Limitations: event observations may be incomplete, duplicated by upstream systems, or influenced by NAT/proxies. An IP address, user agent, or hostname does not identify a person. No IP location or ownership enrichment is asserted.");
  return pdfFromLines(lines);
}

function pdfFromLines(lines) {
  const wrapped = lines.flatMap((line) => wrap(ascii(line), 94));
  const pages = [];
  for (let i = 0; i < wrapped.length; i += 48) pages.push(wrapped.slice(i, i + 48));
  const objects = [];
  const pageIds = pages.map((_, index) => 4 + index * 2);
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
  pages.forEach((page, index) => {
    const pageId = pageIds[index], contentId = pageId + 1;
    const text = page.map((line, row) => `BT /F1 9 Tf 42 ${755 - row * 15} Td (${pdfEscape(line)}) Tj ET`).join("\n");
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`;
    objects[contentId] = `<< /Length ${Buffer.byteLength(text, "ascii")} >>\nstream\n${text}\nendstream`;
  });
  let output = "%PDF-1.4\n%SentryGate\n", offsets = [0];
  for (let id = 1; id < objects.length; id++) { offsets[id] = Buffer.byteLength(output, "ascii"); output += `${id} 0 obj\n${objects[id]}\nendobj\n`; }
  const xref = Buffer.byteLength(output, "ascii");
  output += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id++) output += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
  output += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(output, "ascii");
}

function wrap(value, width) { if (!value) return [""]; const words = value.split(/\s+/), lines = []; let line = ""; for (const word of words) { if (line && `${line} ${word}`.length > width) { lines.push(line); line = word.slice(0, width); } else line = line ? `${line} ${word}` : word; } if (line) lines.push(line); return lines; }
function ascii(value) { return String(value ?? "").replace(/[^\x20-\x7e]/g, "?"); }
function pdfEscape(value) { return value.replaceAll("\\", "\\\\").replaceAll("(", "\\(").replaceAll(")", "\\)"); }
