import crypto from "node:crypto";
import net from "node:net";
import { overlaps, recordHistory, validateFirewallRule } from "./firewall.js";
import { recordAudit } from "./audit.js";

const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function evaluateIncidentPolicies(db, incidentId, now = Date.now()) {
  const settings = db.prepare("SELECT emergency_paused,enforce_enabled,max_active_blocks FROM action_settings WHERE id=1").get();
  if (settings?.emergency_paused) return [];
  const incident = db.prepare("SELECT * FROM incidents WHERE id=? AND status IN ('open','investigating')").get(incidentId);
  if (!incident) return [];
  const policies = db.prepare("SELECT * FROM action_policies WHERE enabled=1 AND mode IN ('recommend','enforce','suggestion-only') AND asset_id=?").all(incident.asset_id)
    .filter((policy) => policy.mode !== "enforce" || settings?.enforce_enabled);
  const created = [];
  for (const policy of policies) {
    if (policy.detection_rule !== "*" && policy.detection_rule !== incident.detection_rule) continue;
    const windowStart = new Date(now - policy.window_minutes * 60_000).toISOString();
    const evidence = db.prepare(`SELECT e.id,e.created_at AS timestamp,e.source,e.detection_rule AS rule,e.severity,e.action,e.reason,e.evidence
      FROM incident_events ie JOIN events e ON e.id=ie.event_id
      WHERE ie.incident_id=? AND e.created_at>=? AND e.created_at<=? AND e.severity<>'info'
      ORDER BY e.created_at,e.id`).all(incidentId, windowStart, new Date(now).toISOString());
    if (evidence.length < policy.minimum_event_count) continue;
    const evidenceSeverity = evidence.reduce((highest, item) => severityRank[item.severity] > severityRank[highest] ? item.severity : highest, "info");
    if (severityRank[evidenceSeverity] < severityRank[policy.minimum_severity]) continue;
    if (!validDestination(db, policy, incident.observed_ip)) {
      recordAudit(db, "system", "action.suggestion_suppressed", `incident:${incidentId}`, `Policy ${policy.name} did not create a proposal because target ${incident.observed_ip} matched a protected or allowlisted address.`);
      continue;
    }
    const existing = db.prepare("SELECT id FROM proposed_actions WHERE policy_id=? AND incident_id=?").get(policy.id, incidentId);
    if (existing) continue;
    const asset = db.prepare("SELECT name,type FROM assets WHERE id=?").get(policy.asset_id);
    const target = policy.target_type === "device"
      ? db.prepare("SELECT name FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(policy.target_id)
      : db.prepare("SELECT name FROM assets WHERE id=? AND type='website'").get(Number(policy.target_id));
    if (!target) continue;
    const id = crypto.randomUUID(), createdAt = new Date(now).toISOString();
    const expiresAt = new Date(now + policy.duration_minutes * 60_000).toISOString();
    const expectedEffect = policy.target_type === "website"
      ? `Temporarily deny gateway requests from ${incident.observed_ip} to website ${target.name} until ${expiresAt}.`
      : `Temporarily block inbound ${policy.protocol} traffic from ${incident.observed_ip} to port ${policy.local_port} on device ${target.name} until ${expiresAt}.`;
    const proof = { incidentId, asset: { id: policy.asset_id, ...asset }, observedIp: incident.observed_ip, detectionRule: incident.detection_rule, severity: evidenceSeverity, incidentSeverity: incident.severity, qualifyingEventCount: evidence.length, threshold: policy.minimum_event_count, windowMinutes: policy.window_minutes, eventIds: evidence.map((item) => item.id), events: evidence };
    db.prepare(`INSERT INTO proposed_actions (id,idempotency_key,policy_id,incident_id,target_type,target_id,target_address,target_protocol,target_port,expected_effect,evidence_json,expires_at,status,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'proposed',?,?)`).run(id, `policy:${policy.id}:incident:${incidentId}`, policy.id, incidentId, policy.target_type, policy.target_id, incident.observed_ip, policy.protocol, policy.local_port, expectedEffect, JSON.stringify(proof), expiresAt, createdAt, createdAt);
    if (policy.mode === "enforce") applyEnforcePolicy(db, policy, db.prepare("SELECT * FROM proposed_actions WHERE id=?").get(id), incident, settings, now);
    else recordAudit(db, "system", "action.proposed", `action:${id}`, `Recommend policy ${policy.name} proposed a temporary ${policy.target_type} action for incident ${incidentId}; no blocking was applied.`);
    created.push(id);
  }
  return created;
}

export function validateActionTarget(db, action, deviceBackendAddresses = []) {
  if (!net.isIP(action.target_address)) return "Action target must be one observed IP address";
  const target = action.target_address.includes(":") ? `${action.target_address}/128` : `${action.target_address}/32`;
  const protectedNetworks = ["127.0.0.0/8", "::1/128", "::ffff:7f00:0/104"];
  protectedNetworks.push(...JSON.parse(db.prepare("SELECT management_addresses FROM firewall_settings WHERE id=1").get()?.management_addresses ?? "[]"));
  protectedNetworks.push(...JSON.parse(db.prepare("SELECT trusted_proxies FROM gateway_settings WHERE id=1").get()?.trusted_proxies ?? "[]"));
  protectedNetworks.push(...deviceBackendAddresses);
  const allowlisted = db.prepare("SELECT 1 FROM gateway_allowlist WHERE ip=? LIMIT 1").get(action.target_address);
  if (allowlisted) return "Action target is present in an existing website allowlist";
  for (const address of protectedNetworks) {
    if (overlaps(target, address)) return `Action target overlaps protected address ${address}`;
  }
  return null;
}

function validDestination(db, policy, ip) {
  if (policy.target_type === "device") {
    const device = db.prepare("SELECT asset_id,backend_addresses FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(policy.target_id);
    if (!device) return false;
    if (validateActionTarget(db, { target_address: ip }, JSON.parse(device.backend_addresses ?? "[]"))) return false;
    if (!Number.isInteger(policy.local_port) || policy.local_port < 1 || policy.local_port > 65535 || !["TCP", "UDP"].includes(policy.protocol)) return false;
    return true;
  }
  const site = db.prepare("SELECT id FROM assets WHERE id=? AND type='website'").get(Number(policy.target_id));
  return Boolean(site && !validateActionTarget(db, { target_address: ip }));
}

export function expireGatewayActions(db, now = new Date().toISOString()) {
  const staleProposals = db.prepare("SELECT id FROM proposed_actions WHERE status='proposed' AND expires_at<=?").all(now);
  for (const item of staleProposals) {
    db.prepare("UPDATE proposed_actions SET status='expired',updated_at=? WHERE id=? AND status='proposed'").run(now, item.id);
    recordAudit(db, "system", "action.proposal_expired", `action:${item.id}`, "Unapproved temporary action proposal expired without applying a block.");
  }
  const expired = db.prepare("SELECT b.action_id,a.status FROM gateway_ip_blocks b JOIN proposed_actions a ON a.id=b.action_id WHERE b.expires_at<=?").all(now);
  for (const item of expired) {
    db.prepare("DELETE FROM gateway_ip_blocks WHERE action_id=?").run(item.action_id);
    db.prepare("UPDATE proposed_actions SET status='expired',updated_at=? WHERE id=? AND status='active'").run(now, item.action_id);
    if (item.status === "active") recordAudit(db, "system", "action.expired", `action:${item.action_id}`, "Temporary website gateway block expired and was removed from the active deny list.");
  }
}

export function actionForDashboard(db, action) {
  const policy = db.prepare("SELECT name FROM action_policies WHERE id=?").get(action.policy_id);
  const incident = db.prepare("SELECT observed_ip,detection_rule,severity,event_count FROM incidents WHERE id=?").get(action.incident_id);
  const target = action.target_type === "device"
    ? db.prepare("SELECT name,last_heartbeat,health_status FROM device_agents WHERE device_id=?").get(action.target_id)
    : db.prepare("SELECT name,status AS health_status,NULL AS last_heartbeat FROM assets WHERE id=?").get(Number(action.target_id));
  const firewallRule = action.firewall_rule_id ? db.prepare("SELECT status,actual_state,failure,approved_by,approved_at,rollback_at FROM firewall_rules WHERE id=?").get(action.firewall_rule_id) : null;
  return { id: action.id, status: action.status, policyId: action.policy_id, policyName: policy?.name ?? "Removed policy", incidentId: action.incident_id,
    targetType: action.target_type, targetId: action.target_id, targetName: target?.name ?? "Unavailable target", targetAddress: action.target_address,
    expectedEffect: action.expected_effect, evidence: JSON.parse(action.evidence_json), expiresAt: action.expires_at, createdAt: action.created_at,
    approvedBy: action.approved_by ?? firewallRule?.approved_by ?? null, approvedAt: action.approved_at ?? firewallRule?.approved_at ?? null,
    failure: action.failure || firewallRule?.failure || "", firewallStatus: firewallRule?.status ?? null,
    actualState: firewallRule?.actual_state ? JSON.parse(firewallRule.actual_state) : null, rollbackAt: action.rollback_at ?? firewallRule?.rollback_at ?? null,
    targetHealth: target?.health_status ?? "unknown", targetLastHeartbeat: target?.last_heartbeat ?? null, incident, autoBlocking: Boolean(action.automatic) };
}

function applyEnforcePolicy(db, policy, action, incident, settings, now) {
  const fail = (reason) => {
    db.prepare("UPDATE proposed_actions SET status='failed',failure=?,updated_at=? WHERE id=?").run(reason, new Date(now).toISOString(), action.id);
    recordAudit(db, "system", "action.enforce_failed", `action:${action.id}`, `Enforce policy ${policy.name} did not apply a block: ${reason}`);
  };
  if (policy.target_type !== "device") return fail("Enforce policies currently support enrolled Windows devices only.");
  const device = db.prepare("SELECT * FROM device_agents WHERE device_id=? AND revoked_at IS NULL AND is_demo=0").get(policy.target_id);
  if (!device || Number(device.asset_id) !== Number(policy.asset_id)) return fail("The enrolled destination device is unavailable or outside the policy asset.");
  const active = db.prepare("SELECT COUNT(*) AS count FROM firewall_rules WHERE rollback_at IS NULL AND (status IN ('approved','active','failed','removing') OR status='expired')").get().count;
  if (active >= settings.max_active_blocks) return fail(`Global active temporary block limit (${settings.max_active_blocks}) reached.`);
  const remoteCidr = incident.observed_ip.includes(":") ? `${incident.observed_ip}/128` : `${incident.observed_ip}/32`;
  const rule = { remoteCidr, protocol: policy.protocol, localPort: policy.local_port, deviceId: device.device_id,
    reason: `Enforce policy ${policy.name} matched incident ${incident.id}`,
    evidence: `Observed ${action.evidence_json.length > 0 ? JSON.parse(action.evidence_json).qualifyingEventCount : 0} matching events for ${incident.detection_rule}; incident ${incident.id}.`,
    expiresAt: action.expires_at };
  const invalid = validateFirewallRule(rule, db, now);
  if (invalid) return fail(invalid);
  const ruleId = crypto.randomUUID(), createdAt = new Date(now).toISOString();
  const previewHash = crypto.createHash("sha256").update(`${policy.id}:${action.id}:${remoteCidr}:${policy.protocol}:${policy.local_port}:${action.expires_at}`).digest("hex");
  db.prepare(`INSERT INTO firewall_rules (id,device_id,remote_cidr,protocol,local_port,reason,evidence,expires_at,status,idempotency_key,preview_hash,created_by,created_at,approved_by,approved_at,updated_at,incident_id,action_id)
    VALUES (?,?,?,?,?,?,?,?,'approved',?,?,?,?,?,?,?,?,?)`).run(ruleId, device.device_id, remoteCidr, policy.protocol, policy.local_port, rule.reason, rule.evidence,
    action.expires_at, `enforce:${action.id}`, previewHash, policy.created_by, createdAt, policy.created_by, createdAt, createdAt, incident.id, action.id);
  const savedRule = db.prepare("SELECT * FROM firewall_rules WHERE id=?").get(ruleId);
  recordHistory(db, savedRule, policy.created_by, "enforce_policy_queued", "Rule queued for authenticated agent application under the explicitly enabled policy.");
  db.prepare("UPDATE proposed_actions SET status='approved',automatic=1,approved_by=?,approved_at=?,firewall_rule_id=?,updated_at=? WHERE id=?")
    .run(policy.created_by, createdAt, ruleId, createdAt, action.id);
  recordAudit(db, "system", "action.enforce_queued", `action:${action.id}`, `Policy ${policy.name} queued temporary inbound block ${ruleId} for ${remoteCidr}, ${policy.protocol}/${policy.local_port}, expiry ${action.expires_at}; awaiting agent OS verification.`);
}
