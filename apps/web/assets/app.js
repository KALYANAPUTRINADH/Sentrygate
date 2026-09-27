import { escapeHtml } from "./escape.js";
import { renderIncidentEvidence } from "./incident-render.js";

const app = document.querySelector("#app");
const state = { session: null, data: null, page: "overview", error: "", alert: null, incident: null, protection: null, device: null, firewallPreview: null, firewallManagement: [], newAgentCredential: "", newDeviceCredential: null };

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "include", headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }, ...options });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `Request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

async function refresh() {
  state.session = await api("/api/session");
  if (state.session.authenticated) {
    const [summary, assets, alerts, events, auditLog, gatewaySettings, devices, firewallRules, firewallManagement, incidentSettings, incidents, actionPolicies, actions, actionSettings] = await Promise.all([
      api("/api/summary"), api("/api/assets"), api("/api/alerts"), api("/api/events"), api("/api/audit-log"), api("/api/gateway/settings"), api("/api/devices"), api("/api/firewall/rules"), api("/api/firewall/settings"), api("/api/incidents/settings"), api("/api/incidents"), api("/api/action-policies"), api("/api/actions"), api("/api/actions/settings")
    ]);
    state.data = { summary, assets, alerts, events, auditLog, gatewaySettings, devices, firewallRules, incidentSettings, incidents, actionPolicies, actions, actionSettings };
    state.firewallManagement = firewallManagement;
    state.error = "";
  }
  render();
}

function render() {
  if (!state.session) { app.innerHTML = '<div class="loading">Loading SentryGate...</div>'; return; }
  if (!state.session.authenticated) { renderAuth(); return; }
  const { summary, assets, alerts, events, auditLog, devices } = state.data;
  const pages = ["overview", "assets", "devices", "firewall", "investigation", "actions", "alerts", "events", "settings"];
  app.innerHTML = `
    <aside class="sidebar">
      <a class="brand" href="#overview"><span class="brand-mark">S</span><span>SentryGate<small>SECURITY OPERATIONS</small></span></a>
      <nav aria-label="Main navigation">${pages.map((page) => `<button class="nav-item ${state.page === page ? "active" : ""}" data-page="${page}"><span>${navIcon(page)}</span>${pageLabel(page)}</button>`).join("")}</nav>
      <div class="sidebar-bottom"><span class="connection-dot"></span> Local system <button id="logout" class="icon-button" title="Sign out" aria-label="Sign out">↩</button></div>
    </aside>
    <main class="main-area">
      <header class="page-header"><div><p class="eyebrow">SENTRYGATE / ${pageLabel(state.page).toUpperCase()}</p><h1>${pageTitle(state.page)}</h1></div><div class="user-menu"><span class="avatar">${escapeHtml(state.session.admin.email.slice(0, 1).toUpperCase())}</span><span>${escapeHtml(state.session.admin.email)}</span></div></header>
      <div class="page-content">${state.error ? `<p class="notice">${escapeHtml(state.error)}</p>` : ""}${pageContent({ summary, assets, alerts, events, auditLog, gatewaySettings: state.data.gatewaySettings, devices, incidents: state.data.incidents, incidentSettings: state.data.incidentSettings })}</div>
    </main>`;
  document.querySelectorAll("[data-page]").forEach((button) => button.addEventListener("click", async () => { state.page = button.dataset.page; state.alert = null; state.incident = null; state.device = null; state.protection = null; state.firewallPreview = null; if (["overview", "devices", "firewall", "investigation", "actions", "events", "alerts"].includes(state.page)) await refresh(); else render(); }));
  document.querySelector("#logout").addEventListener("click", async () => { await api("/api/logout", { method: "POST" }); state.session = null; await refresh(); });
  document.querySelector("#asset-form")?.addEventListener("submit", createAsset);
  document.querySelectorAll("[data-alert]").forEach((button) => button.addEventListener("click", () => openAlert(button.dataset.alert)));
  document.querySelectorAll("[data-device]").forEach((button) => button.addEventListener("click", () => openDevice(button.dataset.device)));
  document.querySelector("#event-filter")?.addEventListener("submit", filterEvents);
  document.querySelector("#alert-filter")?.addEventListener("submit", filterAlerts);
  document.querySelector("#reset-filters")?.addEventListener("click", async () => { document.querySelector("#event-filter").reset(); await loadEvents(); });
  document.querySelector("#run-retention")?.addEventListener("click", runRetention);
  document.querySelectorAll("[data-protection]").forEach((button) => button.addEventListener("click", () => openProtection(button.dataset.protection)));
  document.querySelector("#protection-form")?.addEventListener("submit", saveProtection);
  document.querySelector("#close-protection")?.addEventListener("click", () => { state.protection = null; render(); });
  document.querySelector("#trusted-proxy-form")?.addEventListener("submit", saveTrustedProxies);
  document.querySelector("#rotate-credential")?.addEventListener("click", rotateCredential);
  document.querySelector("#hide-credential")?.addEventListener("click", () => { state.newAgentCredential = ""; render(); });
  document.querySelector("#device-enroll")?.addEventListener("submit", enrollDevice);
  document.querySelector("#device-settings")?.addEventListener("submit", saveDeviceSettings);
  document.querySelector("#rotate-device")?.addEventListener("click", rotateDeviceCredential);
  document.querySelector("#revoke-device")?.addEventListener("click", revokeDeviceCredential);
  document.querySelector("#hide-device-credential")?.addEventListener("click", () => { state.newDeviceCredential = null; render(); });
  document.querySelector("#back-devices")?.addEventListener("click", () => { state.device = null; render(); });
  document.querySelector("#firewall-form")?.addEventListener("submit", previewFirewallRule);
  document.querySelector("#firewall-approve")?.addEventListener("click", approveFirewallRule);
  document.querySelectorAll("[data-firewall-rollback]").forEach((button) => button.addEventListener("click", () => rollbackFirewallRule(button.dataset.firewallRollback)));
  document.querySelector("#firewall-management-form")?.addEventListener("submit", saveFirewallManagement);
  document.querySelector("#incident-filter")?.addEventListener("submit", filterIncidents);
  document.querySelector("#reset-incidents")?.addEventListener("click", () => setTimeout(loadIncidents, 0));
  document.querySelectorAll("[data-incident]").forEach((button) => button.addEventListener("click", () => openIncident(button.dataset.incident)));
  document.querySelector("#back-incidents")?.addEventListener("click", () => { state.incident = null; render(); });
  document.querySelector("#incident-note-form")?.addEventListener("submit", addIncidentNote);
  document.querySelector("#incident-status")?.addEventListener("change", changeIncidentStatus);
  document.querySelectorAll("[data-incident-report]").forEach((button) => button.addEventListener("click", () => downloadIncidentReport(button.dataset.incidentReport)));
  document.querySelector("#incident-settings-form")?.addEventListener("submit", saveIncidentSettings);
  document.querySelector("#action-policy-form")?.addEventListener("submit", createActionPolicy);
  document.querySelector("#emergency-pause")?.addEventListener("click", toggleEmergencyPause);
  document.querySelectorAll("[data-action-approve]").forEach((button) => button.addEventListener("click", () => approveAction(button.dataset.actionApprove)));
  document.querySelectorAll("[data-action-rollback]").forEach((button) => button.addEventListener("click", () => rollbackAction(button.dataset.actionRollback)));
  document.querySelectorAll("[data-policy-toggle]").forEach((button) => button.addEventListener("click", () => toggleActionPolicy(button.dataset.policyToggle, button.dataset.enabled === "true")));
}

function pageContent(data) {
  if (state.alert) return alertDetail(state.alert);
  if (state.incident) return incidentInvestigationDetail(state.incident);
  if (state.page === "devices") return devicesPage(data.devices);
  if (state.page === "firewall") return firewallPage(data.firewallRules, data.devices, data.incidents);
  if (state.page === "investigation") return investigationPage(data.incidents, data.assets, data.devices);
  if (state.page === "actions") return actionsPage(data.actions, data.actionPolicies, data.actionSettings, data.assets, data.devices);
  if (state.page === "overview") return overview(data);
  if (state.page === "assets") return assetsPage(data.assets);
  if (state.page === "alerts") return alertsPage(data.alerts);
  if (state.page === "events") return eventsPage(data.events, data.assets, data.devices);
  return settingsPage(data.auditLog, data.gatewaySettings, data.incidentSettings);
}

function overview({ summary, assets, alerts, events, incidents }) {
  return `<section class="metrics">${metric("Assets", summary.assets, "green", "◈")}${metric("Enrolled devices", state.data.devices.length, "blue", "⌘")}${metric("Open incidents", summary.openIncidents, "red", "⚑")}${metric("Events · 24h", summary.events24h, "amber", "⌁")}</section>
    <section class="content-grid"><section class="section-block"><div class="section-heading"><div><p class="eyebrow">INVENTORY</p><h2>Protected assets</h2></div><button class="text-button" data-page="assets">View all <span>→</span></button></div>${assetTable(assets.slice(0, 5))}</section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">NEEDS REVIEW</p><h2>Recent alerts</h2></div><button class="text-button" data-page="alerts">View all <span>→</span></button></div>${alertList(alerts.slice(0, 4))}</section></section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">CORRELATED ACTIVITY</p><h2>Recent incidents</h2></div><button class="text-button" data-page="investigation">Investigate <span>→</span></button></div>${incidentTable((incidents ?? []).slice(0, 5))}</section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">LATEST ACTIVITY</p><h2>Event history</h2></div><button class="text-button" data-page="events">View events <span>→</span></button></div>${eventTable(events.slice(0, 6))}</section>`;
}

function assetsPage(assets) {
  const selected = state.protection ? assets.find((asset) => asset.id === state.protection.assetId) : null;
  return `${selected ? protectionPanel(selected, state.protection.settings) : ""}<section class="section-block"><div class="section-heading"><div><p class="eyebrow">INVENTORY</p><h2>Registered assets</h2></div><span class="subtle">${assets.length} total</span></div>${assetTable(assets, true)}</section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">NEW ASSET</p><h2>Register an asset</h2></div></div><form id="asset-form" class="asset-form"><label>Asset name<input name="name" maxlength="100" required placeholder="Production website"></label><label>Type<select name="type"><option value="website">Website</option><option value="application">Application</option><option value="computer">Computer</option></select></label><label class="wide">Address<input name="address" maxlength="255" required placeholder="https://example.com or device name"></label><label class="wide">Description<textarea name="description" maxlength="1000" rows="3" placeholder="What does this asset do?"></textarea></label><p class="form-error" id="asset-error"></p><button class="primary-button">Register asset</button></form></section>`;
}

function alertsPage(alerts) {
  return `<section class="section-block"><div class="section-heading"><div><p class="eyebrow">INVESTIGATION QUEUE</p><h2>Security alerts</h2></div><span class="subtle">${alerts.length} records</span></div><form id="alert-filter" class="filters"><label>Device<select name="deviceId"><option value="">All devices</option>${state.data.devices.map((device) => `<option value="${escapeHtml(device.deviceId)}">${escapeHtml(device.name)}</option>`).join("")}</select></label><label>Severity<select name="severity"><option value="">All severities</option>${["critical", "high", "medium", "low", "info"].map((v) => `<option>${v}</option>`).join("")}</select></label><label>From<input type="date" name="from"></label><label>To<input type="date" name="to"></label><button class="primary-button">Apply filters</button></form><div id="alert-results">${alertList(alerts)}</div></section>`;
}

function investigationPage(incidents, assets, devices) {
  const websites = assets.filter((asset) => asset.type === "website");
  const rules = [...new Set(incidents.map((incident) => incident.detectionRule))];
  return `<section class="section-block"><div class="section-heading"><div><p class="eyebrow">CORRELATED SECURITY ACTIVITY</p><h2>Investigation queue</h2></div><span class="subtle">${incidents.length} incidents</span></div><form id="incident-filter" class="filters"><label>Observed IP<input name="ip" placeholder="203.0.113.10"></label><label>Device<select name="deviceId"><option value="">All devices</option>${devices.map((d) => `<option value="${escapeHtml(d.deviceId)}">${escapeHtml(d.name)}</option>`).join("")}</select></label><label>Website<select name="websiteId"><option value="">All websites</option>${websites.map((a) => `<option value="${a.id}">${escapeHtml(a.name)}</option>`).join("")}</select></label><label>Rule<select name="rule"><option value="">All rules</option>${rules.map((r) => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`).join("")}</select></label><label>Severity<select name="severity"><option value="">All severities</option>${["critical", "high", "medium", "low", "info"].map((s) => `<option>${s}</option>`).join("")}</select></label><label>Status<select name="status"><option value="">All statuses</option>${["open", "investigating", "resolved"].map((s) => `<option>${s}</option>`).join("")}</select></label><label>From<input type="date" name="from"></label><label>To<input type="date" name="to"></label><button class="primary-button">Filter incidents</button><button type="reset" id="reset-incidents" class="quiet-button">Reset</button></form><div id="incident-results">${incidentTable(incidents)}</div></section>`;
}

function incidentInvestigationDetail(incident) {
  const assets = incident.assets.map((item) => `${escapeHtml(item.name)} (${escapeHtml(item.type)})`).join(", ") || "None linked";
  const devices = incident.devices.map((item) => escapeHtml(item.name)).join(", ") || "None linked";
  return `<button id="back-incidents" class="text-button">← Back to investigations</button><section class="section-block"><div class="section-heading"><div><p class="eyebrow">INCIDENT · ${escapeHtml(incident.id)}</p><h2>${escapeHtml(incident.detectionRule)}</h2></div><span class="severity ${escapeHtml(incident.severity)}">${escapeHtml(incident.severity)}</span></div><div class="incident-summary"><div><span>First seen</span><strong>${new Date(incident.firstSeen).toLocaleString()}</strong></div><div><span>Last seen</span><strong>${new Date(incident.lastSeen).toLocaleString()}</strong></div><div><span>Events</span><strong>${incident.eventCount} (${incident.retainedEvidenceCount} retained)</strong></div><div><span>Observed endpoint</span><strong class="mono">${escapeHtml(incident.observedIp)}</strong></div><div><span>Affected assets</span><strong>${assets}</strong></div><div><span>Devices</span><strong>${devices}</strong></div></div><p class="notice caution">${escapeHtml(incident.inference)}</p><label class="incident-status-control">Status<select id="incident-status"><option value="open" ${incident.status === "open" ? "selected" : ""}>Open</option><option value="investigating" ${incident.status === "investigating" ? "selected" : ""}>Investigating</option><option value="resolved" ${incident.status === "resolved" ? "selected" : ""}>Resolved</option></select></label><div class="report-actions"><button class="quiet-button" data-incident-report="json">Download JSON</button><button class="quiet-button" data-incident-report="pdf">Download PDF</button></div></section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">OBSERVED EVIDENCE</p><h2>Timeline</h2></div><span class="subtle">Original event records retained separately</span></div>${incident.events.length ? `<div class="incident-timeline">${incident.events.map(renderIncidentEvidence).join("")}</div>` : emptyState("Raw evidence expired under the configured retention policy.")}</section>
    <section class="content-grid"><section class="section-block"><div class="section-heading"><div><p class="eyebrow">ANALYST NOTES</p><h2>Investigation notes</h2></div></div>${incident.notes.length ? `<div class="audit-list">${incident.notes.map((n) => `<div class="audit-entry"><time>${new Date(n.createdAt).toLocaleString()}</time><strong>${escapeHtml(n.actor)}</strong><p>${escapeHtml(n.note)}</p></div>`).join("")}</div>` : emptyState("No analyst notes yet.")}<form id="incident-note-form" class="note-form"><label>Add note<textarea name="note" maxlength="4000" rows="3" required></textarea></label><p class="form-error" id="incident-note-error"></p><button class="primary-button">Add note</button></form></section><section class="section-block"><div class="section-heading"><div><p class="eyebrow">AUDIT TRAIL</p><h2>Investigation activity</h2></div></div>${incident.activity.length ? `<div class="audit-list">${incident.activity.map(auditRow).join("")}</div>` : emptyState("No status or export activity recorded.")}</section></section>`;
}

function incidentTable(incidents) {
  if (!incidents.length) return emptyState("No incidents match the current filters.");
  return `<div class="table-wrap"><table><thead><tr><th>Severity / status</th><th>First / last seen</th><th>Asset / device</th><th>Observed IP</th><th>Rule</th><th>Events</th><th></th></tr></thead><tbody>${incidents.map((item) => `<tr><td><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><small class="cell-sub">${escapeHtml(item.status)}</small></td><td>${new Date(item.firstSeen).toLocaleString()}<small class="cell-sub">Last ${new Date(item.lastSeen).toLocaleString()}</small></td><td>${escapeHtml(item.assets.map((a) => a.name).join(", ") || "—")}<small class="cell-sub">${escapeHtml(item.devices.map((d) => d.name).join(", ") || "—")}</small></td><td class="mono">${escapeHtml(item.observedIp)}</td><td>${escapeHtml(item.detectionRule)}</td><td>${item.eventCount}<small class="cell-sub">${item.retainedEvidenceCount} retained</small></td><td><button class="quiet-button compact" data-incident="${escapeHtml(item.id)}">Investigate</button></td></tr>`).join("")}</tbody></table></div>`;
}

function actionStatusLabel(status) { return ({ "rollback-pending": "Removal pending", rolled_back: "Rolled back" })[status] ?? status; }

function actionsPage(actions, policies, settings, assets, devices) {
  const targets = [
    ...devices.filter((device) => !device.revokedAt && !device.isDemo).map((device) => `<option value="device:${escapeHtml(device.deviceId)}">Device · ${escapeHtml(device.name)}</option>`),
    ...assets.filter((asset) => asset.type === "website").map((asset) => `<option value="website:${asset.id}">Website · ${escapeHtml(asset.name)}</option>`)
  ].join("");
  const policyRows = policies.length ? `<div class="table-wrap"><table><thead><tr><th>Policy</th><th>Criteria</th><th>Destination</th><th>Mode</th><th></th></tr></thead><tbody>${policies.map((policy) => `<tr><td><strong>${escapeHtml(policy.name)}</strong><small class="cell-sub">Affected asset: ${escapeHtml(policy.assetName)}</small></td><td>${escapeHtml(policy.minimumSeverity)} · ${policy.minimumEventCount}+ events / ${policy.windowMinutes} min<small class="cell-sub">${escapeHtml(policy.detectionRule === "*" ? "Any rule" : policy.detectionRule)}</small></td><td>${escapeHtml(policy.targetType)} · ${escapeHtml(policy.targetType === "device" ? devices.find((d) => d.deviceId === policy.targetId)?.name ?? "Unavailable" : assets.find((a) => String(a.id) === policy.targetId)?.name ?? "Unavailable")}</td><td>Suggestion only · ${policy.enabled ? "enabled" : "disabled"}</td><td><button class="quiet-button compact" data-policy-toggle="${escapeHtml(policy.id)}" data-enabled="${policy.enabled}">${policy.enabled ? "Disable" : "Enable"}</button></td></tr>`).join("")}</tbody></table></div>` : emptyState("No action policies configured.");
  const actionRows = actions.length ? `<div class="table-wrap"><table><thead><tr><th>Status</th><th>Target</th><th>Proposed effect</th><th>Evidence</th><th>Expiry / approval</th><th></th></tr></thead><tbody>${actions.map((action) => `<tr><td><span class="status ${action.status === "failed" ? "at-risk" : action.status === "active" ? "healthy" : "watch"}">${escapeHtml(actionStatusLabel(action.status))}</span><small class="cell-sub">${escapeHtml(action.policyName)}</small></td><td>${escapeHtml(action.targetType)} · ${escapeHtml(action.targetName)}<small class="cell-sub mono">${escapeHtml(action.targetAddress)}</small></td><td>${escapeHtml(action.expectedEffect)}${action.firewallStatus ? `<small class="cell-sub">Windows rule state: ${escapeHtml(action.firewallStatus)}${action.firewallStatus === "expired" ? " · awaiting verified removal on agent sync" : ""}</small><small class="cell-sub">OS-reported state: ${escapeHtml(action.actualState ? JSON.stringify(action.actualState) : "not yet reported")}</small>` : ""}${action.failure ? `<small class="cell-sub danger-text">${escapeHtml(action.failure)}</small>` : ""}</td><td>${action.evidence.qualifyingEventCount} events · ${escapeHtml(action.evidence.severity)} · ${escapeHtml(action.evidence.detectionRule)}<small class="cell-sub">Affected asset: ${escapeHtml(action.evidence.asset.name)}</small><small class="cell-sub">Incident ${escapeHtml(action.incidentId)}</small><details><summary>Review evidence</summary>${action.evidence.events.map((item) => `<p class="action-evidence-item"><time>${escapeHtml(item.timestamp)}</time> · ${escapeHtml(item.source)} · ${escapeHtml(item.action)}<br>${escapeHtml(item.reason)}<br>${escapeHtml(item.evidence)}</p>`).join("")}</details></td><td>${new Date(action.expiresAt).toLocaleString()}${action.approvedBy ? `<small class="cell-sub">Approved by ${escapeHtml(action.approvedBy)} · ${new Date(action.approvedAt).toLocaleString()}</small>` : ""}${action.targetType === "device" && action.status === "approved" ? `<small class="cell-sub">Agent: ${escapeHtml(action.targetHealth)} · last seen ${escapeHtml(action.targetLastHeartbeat ?? "never")}</small>` : ""}</td><td>${action.status === "proposed" ? `<button class="primary-button compact" data-action-approve="${escapeHtml(action.id)}">Review / approve</button>` : ["active", "approved"].includes(action.status) ? `<button class="quiet-button compact" data-action-rollback="${escapeHtml(action.id)}">Rollback</button>` : ""}</td></tr>`).join("")}</tbody></table></div>` : emptyState("No response actions yet.");
  return `<section class="section-block action-emergency"><div><p class="eyebrow">HUMAN CONTROL</p><h2>${settings.emergencyPaused ? "Emergency pause is active" : "Suggestions only · automatic blocking disabled"}</h2><p>Pause prevents new suggestions and approvals. It does not silently change rules already active on a device.</p></div><button id="emergency-pause" class="${settings.emergencyPaused ? "primary-button" : "quiet-button"}">${settings.emergencyPaused ? "Resume suggestions" : "Emergency pause"}</button></section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">POLICY</p><h2>Suggestion policies</h2></div><span class="subtle">Every policy is suggestion-only</span></div>${policyRows}<form id="action-policy-form" class="action-policy-form"><label>Policy name<input name="name" maxlength="100" required placeholder="Repeated sensitive-path activity"></label><label>Affected asset<select name="assetId" required><option value="">Select asset</option>${assets.map((asset) => `<option value="${asset.id}">${escapeHtml(asset.name)} · ${escapeHtml(asset.type)}</option>`).join("")}</select></label><label>Detection rule<input name="detectionRule" maxlength="100" value="*" required></label><label>Minimum severity<select name="minimumSeverity"><option>medium</option><option selected>high</option><option>critical</option><option>low</option></select></label><label>Event threshold<input type="number" name="minimumEventCount" min="2" max="100" value="5" required></label><label>Window (minutes)<input type="number" name="windowMinutes" min="1" max="1440" value="10" required></label><label>Destination<select name="destination" required><option value="">Select target</option>${targets}</select></label><label>Temporary duration (minutes)<input type="number" name="durationMinutes" min="1" max="1440" value="30" required></label><label>Device protocol<select name="protocol"><option>TCP</option><option>UDP</option></select></label><label>Device destination port<input type="number" name="localPort" min="1" max="65535" value="443"></label><p class="form-error wide" id="action-policy-error"></p><button class="primary-button">Create suggestion policy</button></form></section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">PROPOSED AND COMPLETED</p><h2>Response actions</h2></div><span class="subtle">${actions.length} actions</span></div>${actionRows}</section>`;
}

function devicesPage(devices) {
  if (state.device) {
    const device = state.device;
      return `<button id="back-devices" class="text-button">← Back to devices</button><section class="section-block"><div class="section-heading"><div><p class="eyebrow">ENDPOINT TELEMETRY${Number(device.isDemo) ? " · SIMULATED" : ""}</p><h2>${escapeHtml(device.name)}</h2></div><span class="status ${device.revokedAt ? "at-risk" : device.healthStatus === "healthy" ? "healthy" : "watch"}">${device.revokedAt ? "revoked" : escapeHtml(device.healthStatus)}</span></div><div class="device-summary"><span><strong>Hostname</strong>${escapeHtml(device.hostname)}</span><span><strong>Linked asset</strong>${escapeHtml(device.assetName || "Unlinked")}</span><span><strong>Windows</strong>${escapeHtml(device.osVersion)}</span><span><strong>Agent</strong>${escapeHtml(device.agentVersion)}</span><span><strong>Last heartbeat</strong>${device.lastHeartbeat ? new Date(device.lastHeartbeat).toLocaleString() : "Never"}</span></div>${device.healthDetail ? `<p class="notice">${escapeHtml(device.healthDetail)}</p>` : ""}${device.isDemo ? '<p class="notice">Synthetic test device. No host was enrolled and no operating-system data was collected.</p>' : `<div class="device-actions"><button id="rotate-device" class="quiet-button">Rotate credential</button><button id="revoke-device" class="quiet-button">Revoke device</button></div>`}${state.newDeviceCredential ? `<div class="credential-reveal"><label>New device credential · shown once<input readonly value="${escapeHtml(state.newDeviceCredential)}"></label><button id="hide-device-credential" class="quiet-button">Hide credential</button></div>` : ""}</section>
      <section class="section-block"><div class="section-heading"><div><p class="eyebrow">COLLECTION POLICY</p><h2>Agent settings</h2></div></div><form id="device-settings" class="device-settings"><label class="toggle-row"><input type="checkbox" name="collectProcesses" ${Number(device.collectionProcesses) ? "checked" : ""}>Collect process metadata</label><label class="toggle-row"><input type="checkbox" name="collectConnections" ${Number(device.collectionConnections) ? "checked" : ""}>Collect TCP connection metadata</label><label>Sample interval (seconds)<input type="number" name="intervalSeconds" min="10" max="3600" value="${device.collectionIntervalSeconds ?? 30}"></label><label>Outbound alert threshold<input type="number" name="outboundConnectionThreshold" min="5" max="10000" value="${device.outboundConnectionThreshold ?? 40}"></label><label>Retain device events (days)<input type="number" name="retainedDays" min="1" max="3650" value="${device.retainedDays ?? 30}"></label><button class="primary-button">Save collection settings</button><p class="form-error" id="device-settings-error"></p></form></section>
      <section class="section-block"><div class="section-heading"><div><p class="eyebrow">PROCESS INVENTORY</p><h2>Running processes</h2></div><span class="subtle">${device.processes.length} observed</span></div>${simpleTable(["PID", "Parent PID", "Process", "Started"], device.processes.map((p) => [p.pid, p.parentPid, p.name, p.startedAt ? new Date(p.startedAt).toLocaleString() : "—"]))}</section>
      <section class="section-block"><div class="section-heading"><div><p class="eyebrow">NETWORK METADATA</p><h2>Active TCP connections</h2></div><span class="subtle">${device.connections.length} observed</span></div>${simpleTable(["PID", "State", "Local endpoint", "Remote endpoint", "Observed"], device.connections.map((c) => [c.pid, c.state, `${c.localAddress}:${c.localPort}`, `${c.remoteAddress}:${c.remotePort}`, new Date(c.timestamp).toLocaleString()]))}</section>`;
  }
  return `<section class="section-block"><div class="section-heading"><div><p class="eyebrow">WINDOWS ENDPOINTS</p><h2>Enrolled devices</h2></div><span class="subtle">${devices.length} total</span></div>${devices.length ? `<div class="table-wrap"><table><thead><tr><th>Device</th><th>Hostname</th><th>Version</th><th>Health</th><th>Heartbeat</th><th></th></tr></thead><tbody>${devices.map((d) => `<tr><td><strong>${escapeHtml(d.name)}</strong>${Number(d.isDemo) ? '<small class="cell-sub">SIMULATED</small>' : ""}</td><td>${escapeHtml(d.hostname)}</td><td>${escapeHtml(d.osVersion)}<small class="cell-sub">Agent ${escapeHtml(d.agentVersion)}</small></td><td><span class="status ${d.revokedAt ? "at-risk" : d.healthStatus === "healthy" ? "healthy" : "watch"}">${d.revokedAt ? "revoked" : escapeHtml(d.healthStatus)}</span></td><td>${d.lastHeartbeat ? new Date(d.lastHeartbeat).toLocaleString() : "Never"}</td><td><button class="quiet-button compact" data-device="${escapeHtml(d.deviceId)}">Inspect</button></td></tr>`).join("")}</tbody></table></div>` : emptyState("No devices enrolled.")}</section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">ENROLLMENT</p><h2>Enroll a Windows agent</h2></div></div><form id="device-enroll" class="asset-form"><label>Display name<input name="name" maxlength="200" required placeholder="Admin workstation"></label><label>Hostname<input name="hostname" maxlength="200" required placeholder="SG-WIN-01"></label><label>Windows version<input name="osVersion" maxlength="200" required placeholder="Windows 11 24H2"></label><label>Agent version<input name="agentVersion" maxlength="200" required value="0.4.0"></label><label class="wide">Computer asset<select name="assetId"><option value="">No linked asset</option>${state.data.assets.filter((a) => a.type === "computer").map((a) => `<option value="${a.id}">${escapeHtml(a.name)}</option>`).join("")}</select></label><p class="form-error" id="device-enroll-error"></p><button class="primary-button">Create enrollment credential</button></form>${state.newDeviceCredential ? `<div class="credential-reveal"><label>One-time device credential<input readonly value="${escapeHtml(state.newDeviceCredential.credential)}"></label><p>Store it immediately with the configure command. The dashboard cannot show it again.</p><code>./apps/agent/scripts/configure-agent.ps1 -DeviceId ${escapeHtml(state.newDeviceCredential.deviceId)} -ApiBaseUrl ${escapeHtml(location.origin)} -AgentRoot "$env:LOCALAPPDATA/SentryGate/Agent"</code><button id="hide-device-credential" class="quiet-button">Hide credential</button></div>` : ""}</section>`;
}

function simpleTable(headers, rows) { return rows.length ? `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(value ?? "—")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` : emptyState("No snapshot data received yet."); }

function protectionPanel(asset, settings) {
  const rule = settings.rule;
  return `<section class="section-block"><div class="section-heading"><div><p class="eyebrow">WEBSITE GATEWAY</p><h2>${escapeHtml(asset.name)} protection</h2></div><span class="subtle">Requests use /site/${asset.id}/</span></div><form id="protection-form" class="protection-form"><label class="wide">Upstream URL<input name="upstreamUrl" type="url" required maxlength="2048" value="${escapeHtml(settings.upstreamUrl)}" placeholder="http://127.0.0.1:4320"></label><label class="toggle-row"><input name="enabled" type="checkbox" ${Number(rule.enabled) ? "checked" : ""}>Enable gateway rules</label><label>Rule mode<select name="mode"><option value="observe" ${rule.mode === "observe" ? "selected" : ""}>Observe</option><option value="challenge-ready" ${rule.mode === "challenge-ready" ? "selected" : ""}>Challenge-ready placeholder</option><option value="block" ${rule.mode === "block" ? "selected" : ""}>Block</option></select></label><label>Requests per IP<input type="number" name="rateLimitCount" min="1" max="100000" value="${rule.rateLimitCount}"></label><label>Window seconds<input type="number" name="windowSeconds" min="1" max="3600" value="${rule.windowSeconds}"></label><label class="toggle-row"><input name="sensitivePathsEnabled" type="checkbox" ${Number(rule.sensitivePathsEnabled) ? "checked" : ""}>Detect /.env and /.git paths</label><label class="wide">Allowlisted IP addresses<textarea name="allowlist" rows="3" placeholder="One exact IP address per line">${escapeHtml(settings.allowlist.join("\n"))}</textarea></label><small class="wide">Allowlisted addresses bypass path and rate rules. Use exact IPv4 or IPv6 addresses.</small><p id="protection-error" class="form-error wide"></p><div class="form-actions wide"><button class="primary-button">Save protection settings</button><button type="button" id="close-protection" class="quiet-button">Close</button></div></form></section>`;
}

function eventsPage(events, assets, devices) {
  return `<section class="section-block"><div class="section-heading"><div><p class="eyebrow">ACTIVITY RECORD</p><h2>Event history</h2></div><span class="subtle">${events.length} records · up to 500</span></div>
    <form id="event-filter" class="filters"><label>Asset<select name="assetId"><option value="">All assets</option>${assets.map((asset) => `<option value="${asset.id}">${escapeHtml(asset.name)}</option>`).join("")}</select></label><label>Device<select name="deviceId"><option value="">All devices</option>${devices.map((device) => `<option value="${escapeHtml(device.deviceId)}">${escapeHtml(device.name)}</option>`).join("")}</select></label><label>Severity<select name="severity"><option value="">All severities</option>${["critical", "high", "medium", "low", "info"].map((v) => `<option>${v}</option>`).join("")}</select></label><label>Source IP<input name="sourceIp" placeholder="203.0.113.10"></label><label>Action<select name="action"><option value="">All actions</option>${[...new Set(events.map((event) => event.action))].map((v) => `<option>${escapeHtml(v)}</option>`).join("")}</select></label><label>From<input type="date" name="from"></label><label>To<input type="date" name="to"></label><button class="primary-button">Apply filters</button><button type="button" id="reset-filters" class="quiet-button">Reset</button></form>
    <div id="event-results">${eventTable(events)}</div></section>`;
}

function firewallPage(rules, devices, incidents) {
  const form = `<section class="section-block"><div class="section-heading"><div><p class="eyebrow">PREVIEW MODE · AUTOMATION DISABLED</p><h2>Propose inbound rule</h2></div></div><form id="firewall-form" class="firewall-form"><label>Windows device<select name="deviceId" required><option value="">Select device</option>${devices.filter((d) => !d.revokedAt && !d.isDemo).map((d) => `<option value="${escapeHtml(d.deviceId)}">${escapeHtml(d.name)} · ${escapeHtml(d.healthStatus)}</option>`).join("")}</select></label><label>Remote IP or CIDR<input name="remoteCidr" required maxlength="64" placeholder="198.51.100.24/32"></label><label>Protocol<select name="protocol"><option>TCP</option><option>UDP</option></select></label><label>Local port<input name="localPort" type="number" min="1" max="65535" required></label><label>Expiry time<input name="expiresAt" type="datetime-local" required></label><label>Link to incident<select name="incidentId"><option value="">No incident link</option>${incidents.map((incident) => `<option value="${escapeHtml(incident.id)}">${escapeHtml(incident.severity)} · ${escapeHtml(incident.observedIp)} · ${escapeHtml(incident.detectionRule)}</option>`).join("")}</select></label><label class="wide">Reason<input name="reason" maxlength="500" required placeholder="Temporary containment for an observed source"></label><label class="wide">Evidence<textarea name="evidence" maxlength="2000" rows="2" required placeholder="Reference observed event IDs or facts"></textarea></label><p class="form-error" id="firewall-error"></p><button class="primary-button">Preview rule</button></form></section>`;
  const preview = state.firewallPreview ? `<section class="section-block firewall-preview"><div class="section-heading"><div><p class="eyebrow">NO CHANGE HAS BEEN APPLIED</p><h2>Review exact proposal</h2></div></div><dl class="facts"><dt>Device</dt><dd>${escapeHtml(state.firewallPreview.deviceName)}</dd><dt>Rule</dt><dd class="mono">${escapeHtml(state.firewallPreview.protocol)} inbound · block ${escapeHtml(state.firewallPreview.remoteCidr)} to local port ${state.firewallPreview.localPort}</dd><dt>Expiry</dt><dd>${new Date(state.firewallPreview.expiresAt).toLocaleString()}</dd><dt>Reason</dt><dd>${escapeHtml(state.firewallPreview.reason)}</dd><dt>Evidence</dt><dd>${escapeHtml(state.firewallPreview.evidence)}</dd><dt>Safeguards</dt><dd>Loopback, backend, and configured management addresses are protected. Firewall remains unchanged until explicit approval and agent sync.</dd></dl><button id="firewall-approve" class="primary-button">Approve and apply</button></section>` : "";
  const sections = ["proposed", "approved", "active", "removing", "expired", "removed", "failed"].map((status) => {
    const entries = rules.filter((rule) => rule.status === status);
    if (!entries.length) return "";
    return `<section class="section-block"><div class="section-heading"><div><p class="eyebrow">RULE STATE</p><h2>${status[0].toUpperCase() + status.slice(1)}</h2></div><span class="subtle">${entries.length}</span></div><div class="table-wrap"><table><thead><tr><th>Device / remote</th><th>Rule</th><th>Reason / evidence</th><th>Expiry</th><th>Approval / result</th><th></th></tr></thead><tbody>${entries.map((r) => `<tr><td><strong>${escapeHtml(r.deviceName)}</strong><small class="cell-sub mono">${escapeHtml(r.remoteCidr)}</small></td><td>${escapeHtml(r.protocol)} · ${r.localPort}<small class="cell-sub">Inbound block</small></td><td>${escapeHtml(r.reason)}<small class="cell-sub">${escapeHtml(r.evidence)}</small></td><td>${new Date(r.expiresAt).toLocaleString()}</td><td>${escapeHtml(r.approvedBy || r.createdBy || "—")}<small class="cell-sub">${escapeHtml(r.failure || JSON.stringify(r.actualState ?? "Awaiting agent"))}</small></td><td>${["approved", "active", "failed"].includes(status) ? `<button class="quiet-button" data-firewall-rollback="${escapeHtml(r.id)}">Rollback</button>` : ""}</td></tr>`).join("")}</tbody></table></div></section>`;
  }).join("");
  const addresses = state.firewallManagement.join("\n");
  return `${form}${preview}<section class="section-block"><div class="section-heading"><div><p class="eyebrow">PROTECTED ADMINISTRATOR ACCESS</p><h2>Management addresses</h2></div></div><form id="firewall-management-form" class="proxy-settings"><label>Exact IP addresses, one per line<textarea name="addresses" rows="2" placeholder="192.0.2.10">${escapeHtml(addresses)}</textarea></label><small>Any proposed CIDR overlapping these addresses is rejected.</small><button class="quiet-button">Save protected addresses</button></form></section>${sections || `<section class="section-block">${emptyState("No firewall rule proposals yet.")}</section>`}`;
}

function settingsPage(auditLog, gatewaySettings, incidentSettings) {
  return `<section class="section-block settings-intro"><p class="eyebrow">LOCAL CONFIGURATION</p><h2>Settings</h2><p>Gateway ingestion credential and trusted proxy peers.</p><div class="settings-row"><div><strong>Event ingestion credential</strong><p>Rotate to revoke the current gateway credential immediately.</p></div><button id="rotate-credential" class="quiet-button">Rotate credential</button></div>${state.newAgentCredential ? `<div class="credential-reveal"><label>New credential · shown once<input readonly value="${escapeHtml(state.newAgentCredential)}"></label><button id="hide-credential" class="quiet-button">Hide credential</button></div>` : ""}<form id="trusted-proxy-form" class="proxy-settings"><label>Trusted proxy IP addresses, one per line<textarea name="trustedProxies" rows="3" placeholder="127.0.0.1">${escapeHtml(gatewaySettings.trustedProxies.join("\n"))}</textarea></label><small>Only these immediate peer IPs may supply X-Forwarded-For. Exact IPv4/IPv6 addresses are accepted.</small><button class="quiet-button">Save trusted proxies</button></form></section><section class="section-block"><div class="section-heading"><div><p class="eyebrow">CORRELATION AND RETENTION</p><h2>Incident settings</h2></div></div><form id="incident-settings-form" class="incident-settings-form"><label>Events to open incident<input type="number" name="correlationThreshold" min="2" max="100" value="${incidentSettings.correlationThreshold}"></label><label>Correlation window (minutes)<input type="number" name="correlationWindowMinutes" min="1" max="1440" value="${incidentSettings.correlationWindowMinutes}"></label><label>Raw-event retention (days)<input type="number" name="rawEventDays" min="1" max="3650" value="${incidentSettings.rawEventDays}"></label><label>Report snapshot retention (days)<input type="number" name="reportDays" min="1" max="3650" value="${incidentSettings.reportDays}"></label><p class="form-error wide" id="incident-settings-error"></p><button class="primary-button">Save incident settings</button></form><div class="settings-row"><div><strong>Delete expired data now</strong><p>Raw events, stored report snapshots, and audit records follow the values above.</p></div><button id="run-retention" class="quiet-button">Run cleanup</button></div><p id="notice" class="notice hidden"></p></section><section class="section-block"><div class="section-heading"><div><p class="eyebrow">ADMINISTRATOR ACTIVITY</p><h2>Audit log</h2></div><span class="subtle">${auditLog.length} latest entries</span></div>${auditLog.length ? `<div class="audit-list">${auditLog.map(auditRow).join("")}</div>` : emptyState("No administrator actions recorded.")}</section>`;
}

function alertDetail(alert) {
  return `<button id="back-alerts" class="text-button">← Back to alerts</button><article class="detail-view"><div class="detail-top"><span class="severity ${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span><span class="subtle">${escapeHtml(alert.status)}</span></div><h2>${escapeHtml(alert.title)}</h2><p class="subtle">${escapeHtml(alert.deviceName ?? alert.assetName ?? "Unassigned asset")} · ${new Date(alert.createdAt).toLocaleString()}</p><div class="evidence-box"><p class="eyebrow">EVIDENCE</p><p>${escapeHtml(alert.evidence)}</p></div><dl class="facts"><dt>Observed facts</dt><dd>${escapeHtml(alert.observedFacts)}</dd><dt>Assessment</dt><dd>${escapeHtml(alert.estimate ?? "No estimate recorded")}</dd></dl></article>`;
}

function metric(label, value, tone, icon) { return `<article class="metric"><span class="metric-icon ${tone}">${icon}</span><span class="metric-label">${label}</span><strong>${value}</strong></article>`; }
function assetTable(assets, showActions = false) {
  if (!assets.length) return emptyState("No assets registered yet.");
  return `<div class="table-wrap"><table><thead><tr><th>Asset</th><th>Type</th><th>Address</th><th>Description</th><th>Status</th>${showActions ? "<th>Gateway</th>" : ""}</tr></thead><tbody>${assets.map((a) => `<tr><td><strong>${escapeHtml(a.name)}</strong></td><td>${escapeHtml(a.type)}</td><td class="mono">${escapeHtml(a.address)}</td><td>${escapeHtml(a.description || "—")}</td><td><span class="status ${escapeHtml(a.status)}">${escapeHtml(a.status)}</span></td>${showActions ? `<td>${a.type === "website" ? `<button class="quiet-button compact" data-protection="${a.id}">Configure</button>` : "—"}</td>` : ""}</tr>`).join("")}</tbody></table></div>`;
}
function alertList(alerts) {
  if (!alerts.length) return emptyState("No alerts to review.");
  return `<div class="alert-list">${alerts.map((alert) => `<button class="alert-row" data-alert="${alert.id}"><span class="severity-dot ${escapeHtml(alert.severity)}"></span><span class="alert-copy"><strong>${escapeHtml(alert.title)}</strong><small>${escapeHtml(alert.evidence)}</small></span><span class="severity ${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span><span class="row-arrow">→</span></button>`).join("")}</div>`;
}
function eventTable(events) {
  if (!events.length) return emptyState("No events match these filters.");
  return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Asset / device</th><th>Source IP</th><th>Request / process</th><th>Response</th><th>Rule / reason</th><th>Action</th></tr></thead><tbody>${events.map((event) => `<tr><td>${new Date(event.createdAt).toLocaleString()}</td><td>${escapeHtml(event.deviceName || event.assetName || event.assetId || "—")}</td><td class="mono">${escapeHtml(event.observedSourceIp || "—")}</td><td><strong>${escapeHtml(event.method || event.source)}</strong><small class="cell-sub mono">${escapeHtml(event.path || event.requestDetails || event.processDetails || event.category)}</small><small class="cell-sub">${escapeHtml(event.userAgent || "")}</small></td><td>${event.responseStatus || "—"}</td><td><strong>${escapeHtml(event.detectionRule || "none")}</strong><small class="cell-sub">${escapeHtml(event.reason)}</small></td><td>${escapeHtml(event.action)}</td></tr>`).join("")}</tbody></table></div>`;
}
function auditRow(entry) { return `<div class="audit-entry"><time>${new Date(entry.createdAt).toLocaleString()}</time><strong>${escapeHtml(entry.action)}</strong><span>${escapeHtml(entry.actor)}</span><p>${escapeHtml(entry.detail)}</p></div>`; }
function emptyState(text) { return `<div class="empty-state">${text}</div>`; }
function pageLabel(page) { return ({ overview: "Overview", assets: "Protected Assets", devices: "Devices", firewall: "Firewall", investigation: "Investigation", actions: "Actions", alerts: "Alerts", events: "Events", settings: "Settings" })[page]; }
function pageTitle(page) { return ({ overview: "Overview", assets: "Protected assets", devices: "Windows devices", firewall: "Firewall rules", investigation: "Incident investigation", actions: "Response actions", alerts: "Alerts", events: "Events", settings: "Settings" })[page]; }
function navIcon(page) { return ({ overview: "⌂", assets: "◈", devices: "▣", firewall: "▤", investigation: "⌕", actions: "⚑", alerts: "!", events: "⌁", settings: "⚙" })[page]; }

async function createAsset(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  try { await api("/api/assets", { method: "POST", body: JSON.stringify(values) }); state.error = ""; await refresh(); }
  catch (error) { document.querySelector("#asset-error").textContent = error.message; }
}

async function openProtection(assetId) {
  try {
    state.protection = { assetId: Number(assetId), settings: await api(`/api/assets/${assetId}/protection`) };
    render();
  } catch (error) { state.error = error.message; }
}

async function saveProtection(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  const body = {
    upstreamUrl: values.upstreamUrl,
    enabled: form.elements.enabled.checked,
    mode: values.mode,
    rateLimitCount: Number(values.rateLimitCount),
    windowSeconds: Number(values.windowSeconds),
    sensitivePathsEnabled: form.elements.sensitivePathsEnabled.checked,
    allowlist: values.allowlist.split(/[\r\n,]+/).map((ip) => ip.trim()).filter(Boolean)
  };
  try {
    await api(`/api/assets/${state.protection.assetId}/protection`, { method: "PUT", body: JSON.stringify(body) });
    state.protection.settings = await api(`/api/assets/${state.protection.assetId}/protection`);
    await refresh();
  } catch (error) { document.querySelector("#protection-error").textContent = error.message; }
}

async function saveTrustedProxies(event) {
  event.preventDefault();
  const trustedProxies = new FormData(event.currentTarget).get("trustedProxies").split(/[\r\n,]+/).map((ip) => ip.trim()).filter(Boolean);
  try { await api("/api/gateway/settings", { method: "PUT", body: JSON.stringify({ trustedProxies }) }); await refresh(); }
  catch (error) { const notice = document.querySelector("#notice"); notice.textContent = error.message; notice.classList.remove("hidden"); }
}

async function previewFirewallRule(event) {
  event.preventDefault();
  const form = event.currentTarget, values = Object.fromEntries(new FormData(form));
  if (!values.incidentId) delete values.incidentId;
  const device = state.data.devices.find((item) => item.deviceId === values.deviceId);
  const expiresAt = new Date(values.expiresAt).toISOString();
  try {
    const result = await api("/api/firewall/rules", { method: "POST", body: JSON.stringify({ ...values, localPort: Number(values.localPort), expiresAt, idempotencyKey: crypto.randomUUID() }) });
    state.firewallPreview = { ...result.rule, previewToken: result.previewToken, deviceName: device?.name ?? result.rule.deviceName };
    await refresh();
  } catch (error) { document.querySelector("#firewall-error").textContent = error.message; }
}

async function approveFirewallRule() {
  const preview = state.firewallPreview;
  if (!preview || !confirm(`Apply this inbound ${preview.protocol} block rule on ${preview.deviceName}?\n${preview.remoteCidr} to port ${preview.localPort}\nExpires ${new Date(preview.expiresAt).toLocaleString()}`)) return;
  try {
    await api(`/api/firewall/rules/${preview.id}/approve`, { method: "POST", body: JSON.stringify({ confirmed: true, previewToken: preview.previewToken }) });
    state.firewallPreview = null; await refresh();
  } catch (error) { alert(error.message); }
}

async function rollbackFirewallRule(id) {
  if (!confirm("Remove this SentryGate-owned firewall rule from the device?")) return;
  try { await api(`/api/firewall/rules/${id}/rollback`, { method: "POST", body: JSON.stringify({ confirmed: true }) }); await refresh(); }
  catch (error) { alert(error.message); }
}

async function saveFirewallManagement(event) {
  event.preventDefault();
  const managementAddresses = new FormData(event.currentTarget).get("addresses").split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
  try { await api("/api/firewall/settings", { method: "PUT", body: JSON.stringify({ managementAddresses }) }); await refresh(); }
  catch (error) { alert(error.message); }
}

async function rotateCredential() {
  try { const result = await api("/api/agent/credential/rotate", { method: "POST" }); state.newAgentCredential = result.credential; render(); }
  catch (error) { const notice = document.querySelector("#notice"); notice.textContent = error.message; notice.classList.remove("hidden"); }
}

async function openAlert(id) {
  try { state.alert = await api(`/api/alerts/${id}`); render(); document.querySelector("#back-alerts").addEventListener("click", () => { state.alert = null; render(); }); }
  catch (error) { state.error = error.message; }
}

async function filterEvents(event) {
  event.preventDefault();
  const params = new URLSearchParams(new FormData(event.currentTarget));
  for (const [key, value] of [...params]) if (!value) params.delete(key);
  const results = await api(`/api/events?${params}`);
  document.querySelector("#event-results").innerHTML = eventTable(results);
}

async function filterAlerts(event) {
  event.preventDefault();
  const params = new URLSearchParams(new FormData(event.currentTarget));
  for (const [key, value] of [...params]) if (!value) params.delete(key);
  const results = await api(`/api/alerts?${params}`);
  document.querySelector("#alert-results").innerHTML = alertList(results);
  document.querySelectorAll("[data-alert]").forEach((button) => button.addEventListener("click", () => openAlert(button.dataset.alert)));
}

async function filterIncidents(event) {
  event.preventDefault();
  const params = new URLSearchParams(new FormData(event.currentTarget));
  for (const [key, value] of [...params]) if (!value) params.delete(key);
  const incidents = await api(`/api/incidents?${params}`);
  document.querySelector("#incident-results").innerHTML = incidentTable(incidents);
  document.querySelectorAll("[data-incident]").forEach((button) => button.addEventListener("click", () => openIncident(button.dataset.incident)));
}

async function loadIncidents() {
  const incidents = await api("/api/incidents"), results = document.querySelector("#incident-results");
  if (!results) return;
  results.innerHTML = incidentTable(incidents);
  document.querySelectorAll("[data-incident]").forEach((button) => button.addEventListener("click", () => openIncident(button.dataset.incident)));
}

async function openIncident(id) {
  try { state.incident = await api(`/api/incidents/${encodeURIComponent(id)}`); state.page = "investigation"; render(); }
  catch (error) { state.error = error.message; }
}

async function addIncidentNote(event) {
  event.preventDefault();
  const note = new FormData(event.currentTarget).get("note");
  try { await api(`/api/incidents/${state.incident.id}/notes`, { method: "POST", body: JSON.stringify({ note }) }); await openIncident(state.incident.id); }
  catch (error) { document.querySelector("#incident-note-error").textContent = error.message; }
}

async function changeIncidentStatus(event) {
  try { state.incident = await api(`/api/incidents/${state.incident.id}/status`, { method: "PATCH", body: JSON.stringify({ status: event.currentTarget.value }) }); render(); }
  catch (error) { alert(error.message); }
}

async function downloadIncidentReport(format) {
  try {
    const response = await fetch(`/api/incidents/${state.incident.id}/report?format=${format}`, { credentials: "include" });
    if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.error ?? `Report download failed (${response.status})`); }
    const blob = await response.blob(), link = document.createElement("a");
    link.href = URL.createObjectURL(blob); link.download = `sentrygate-incident-${state.incident.id}.${format}`; link.click(); URL.revokeObjectURL(link.href);
  } catch (error) { alert(error.message); }
}

async function saveIncidentSettings(event) {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.currentTarget));
  for (const key of Object.keys(body)) body[key] = Number(body[key]);
  try { await api("/api/incidents/settings", { method: "PUT", body: JSON.stringify(body) }); await refresh(); }
  catch (error) { document.querySelector("#incident-settings-error").textContent = error.message; }
}

async function createActionPolicy(event) {
  event.preventDefault();
  const values = Object.fromEntries(new FormData(event.currentTarget));
  const [targetType, targetId] = values.destination.split(":", 2);
  const body = { name: values.name, assetId: Number(values.assetId), detectionRule: values.detectionRule, minimumSeverity: values.minimumSeverity,
    minimumEventCount: Number(values.minimumEventCount), windowMinutes: Number(values.windowMinutes), targetType, targetId,
    protocol: values.protocol, localPort: Number(values.localPort), durationMinutes: Number(values.durationMinutes) };
  try { await api("/api/action-policies", { method: "POST", body: JSON.stringify(body) }); await refresh(); }
  catch (error) { document.querySelector("#action-policy-error").textContent = error.message; }
}

async function toggleEmergencyPause() {
  const emergencyPaused = !state.data.actionSettings.emergencyPaused;
  try { await api("/api/actions/settings", { method: "PUT", body: JSON.stringify({ emergencyPaused }) }); await refresh(); }
  catch (error) { state.error = error.message; render(); }
}

async function toggleActionPolicy(id, enabled) {
  try { await api(`/api/action-policies/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ enabled: !enabled }) }); await refresh(); }
  catch (error) { state.error = error.message; render(); }
}

async function approveAction(id) {
  const action = state.data.actions.find((item) => item.id === id);
  if (!action || !confirm(`Approve this temporary action?\n${action.expectedEffect}\n\nThis records your approval. Automatic blocking remains disabled.`)) return;
  try { await api(`/api/actions/${encodeURIComponent(id)}/approve`, { method: "POST", body: JSON.stringify({ confirmed: true }) }); await refresh(); }
  catch (error) { state.error = error.message; render(); }
}

async function rollbackAction(id) {
  const action = state.data.actions.find((item) => item.id === id);
  if (!action || !confirm(`Roll back this SentryGate-owned action?\n${action.expectedEffect}\n\nDevice removal may wait for the enrolled agent to reconnect.`)) return;
  try { await api(`/api/actions/${encodeURIComponent(id)}/rollback`, { method: "POST", body: JSON.stringify({ confirmed: true }) }); await refresh(); }
  catch (error) { state.error = error.message; render(); }
}

async function openDevice(id) {
  try { state.device = await api(`/api/devices/${encodeURIComponent(id)}`); state.newDeviceCredential = null; render(); }
  catch (error) { state.error = error.message; }
}

async function enrollDevice(event) {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.currentTarget));
  body.assetId = body.assetId ? Number(body.assetId) : null;
  try { state.newDeviceCredential = await api("/api/devices/enroll", { method: "POST", body: JSON.stringify(body) }); await refresh(); state.page = "devices"; render(); }
  catch (error) { document.querySelector("#device-enroll-error").textContent = error.message; }
}

async function saveDeviceSettings(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const body = { collectProcesses: form.elements.collectProcesses.checked, collectConnections: form.elements.collectConnections.checked,
    intervalSeconds: Number(form.elements.intervalSeconds.value), outboundConnectionThreshold: Number(form.elements.outboundConnectionThreshold.value), retainedDays: Number(form.elements.retainedDays.value) };
  try { await api(`/api/devices/${state.device.deviceId}/settings`, { method: "PUT", body: JSON.stringify(body) }); await refresh(); await openDevice(state.device.deviceId); }
  catch (error) { document.querySelector("#device-settings-error").textContent = error.message; }
}

async function rotateDeviceCredential() {
  try { const result = await api(`/api/devices/${state.device.deviceId}/credential/rotate`, { method: "POST" }); state.newDeviceCredential = result.credential; render(); }
  catch (error) { state.error = error.message; render(); }
}

async function revokeDeviceCredential() {
  if (!confirm("Revoke this device credential? The agent will stop reporting.")) return;
  try { await api(`/api/devices/${state.device.deviceId}/credential/revoke`, { method: "POST" }); await refresh(); await openDevice(state.device.deviceId); }
  catch (error) { state.error = error.message; render(); }
}

async function loadEvents() { const results = await api("/api/events"); document.querySelector("#event-results").innerHTML = eventTable(results); }
async function runRetention() {
  try { const result = await api("/api/retention/run", { method: "POST", body: JSON.stringify({}) }); await refresh(); const notice = document.querySelector("#notice"); notice.textContent = `Removed ${result.deletedEvents} raw events, ${result.deletedReports} report snapshots, and ${result.deletedAudit} audit entries.`; notice.classList.remove("hidden"); }
  catch (error) { const notice = document.querySelector("#notice"); notice.textContent = error.message; notice.classList.remove("hidden"); }
}

function renderAuth() {
  const setup = state.session.setupRequired;
  app.innerHTML = `<main class="auth-shell"><section class="auth-brand"><span class="brand-mark">S</span><p class="eyebrow">LOCAL SECURITY OPERATIONS</p><h1>SentryGate</h1><p>One clear view of the assets you protect and the evidence that matters.</p></section><form class="auth-card" id="auth-form"><p class="eyebrow">ADMINISTRATOR ACCESS</p><h2>${setup ? "Create your administrator" : "Sign in"}</h2><label>Email<input id="email" type="email" autocomplete="username" required maxlength="254" value=""></label><label>Password<input id="password" type="password" minlength="${setup ? 12 : 1}" autocomplete="${setup ? "new-password" : "current-password"}" required></label>${state.error ? `<p class="form-error">${escapeHtml(state.error)}</p>` : ""}<button class="primary-button">${setup ? "Create account" : "Sign in"}</button>${setup ? '<small>Use at least 12 characters. This password cannot be recovered.</small>' : ""}</form></main>`;
  document.querySelector("#auth-form").addEventListener("submit", submitAuth);
}
async function submitAuth(event) {
  event.preventDefault();
  const setup = state.session.setupRequired;
  try { await api(setup ? "/api/setup" : "/api/login", { method: "POST", body: JSON.stringify({ email: document.querySelector("#email").value, password: document.querySelector("#password").value }) }); state.error = ""; await refresh(); }
  catch (error) { state.error = error.message; renderAuth(); }
}
refresh().catch((error) => { state.error = error.message; state.session = { authenticated: false, setupRequired: true }; render(); });
