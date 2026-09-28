import { randomUUID } from "node:crypto";

export function createDetector({ initialState = null, onState = () => {} } = {}) {
  let listeningPorts = Array.isArray(initialState?.listeningPorts) ? new Set(initialState.listeningPorts) : null;
  let startupBaseline = Array.isArray(initialState?.startupEntries) ? new Map(initialState.startupEntries.map((entry) => [`${entry.name}\n${entry.executablePath}`, entry])) : null;
  let securityIssue = typeof initialState?.securityIssue === "string" ? initialState.securityIssue : null;
  let outageFailures = 0;
  let outageReported = false;
  return {
    inspect({ connections, processes, startupEntries = [], services = [], securitySettings = {}, threshold = 40, now = new Date().toISOString() }) {
      const events = [];
      const listeners = new Map(connections.filter((entry) => entry.state === "Listen").map((entry) => [`${entry.localAddress}:${entry.localPort}`, entry]));
      if (listeningPorts) for (const [endpoint, connection] of listeners) if (!listeningPorts.has(endpoint)) {
        const processName = processes.find((entry) => entry.pid === connection.pid)?.name ?? "unknown";
        events.push(makeEvent("new_listening_port", "New listening TCP port", `A TCP listener appeared at ${endpoint} for process ${processName} (PID ${connection.pid}) since the previous sample.`, { endpoint, pid: connection.pid, processName }, now, "medium"));
      }
      listeningPorts = new Set(listeners.keys());
      const currentStartup = new Map(startupEntries.map((entry) => [`${entry.name}\n${entry.executablePath}`, entry]));
      if (startupBaseline) for (const [key, entry] of currentStartup) if (!startupBaseline.has(key)) {
        events.push(makeEvent("new_startup_entry", "New startup entry", `A startup entry appeared since the previous sample: ${entry.name}${entry.executablePath ? ` (${entry.executablePath})` : ""}.`, { name: entry.name, executablePath: entry.executablePath, source: entry.source }, now, "medium"));
      }
      startupBaseline = currentStartup;
      const disabledProfiles = (securitySettings.firewallProfiles ?? []).filter((profile) => profile.enabled === false).map((profile) => profile.name);
      const disabledServices = services.filter((service) => ["windefend", "mpssvc", "bfe"].includes(String(service.name).toLowerCase()) && (service.state !== "Running" || service.startMode === "Disabled")).map((service) => ({ name: service.name, state: service.state, startMode: service.startMode }));
      const issues = [...disabledProfiles.map((name) => `Windows Firewall profile ${name} is disabled`), ...(securitySettings.defenderRealtimeProtection === false ? ["Microsoft Defender real-time protection is disabled"] : []), ...disabledServices.map((service) => `Security service ${service.name} reports ${service.state}/${service.startMode}`)];
      const currentIssue = issues.sort().join("; ");
      if (currentIssue && currentIssue !== securityIssue) events.push(makeEvent("security_protection_disabled", "Windows protection setting or service disabled", currentIssue, { disabledFirewallProfiles: disabledProfiles, defenderRealtimeProtection: securitySettings.defenderRealtimeProtection, disabledServices }, now, "high"));
      securityIssue = currentIssue;
      const processNames = new Map(processes.map((entry) => [entry.pid, entry.name]));
      const outbound = new Map();
      for (const entry of connections) if (entry.state === "Established" && entry.remoteAddress && !isLocal(entry.remoteAddress)) {
        outbound.set(entry.pid, (outbound.get(entry.pid) ?? 0) + 1);
      }
      for (const [pid, count] of outbound) if (count >= threshold) {
        const remoteAddresses = [...new Set(connections.filter((entry) => entry.pid === pid && entry.state === "Established" && entry.remoteAddress && !isLocal(entry.remoteAddress)).map((entry) => entry.remoteAddress))].sort();
        const event = makeEvent(
          "outbound_connection_volume", "High outbound connection count",
          `Process ${processNames.get(pid) ?? "unknown"} (PID ${pid}) had ${count} established non-local TCP connections; configured threshold is ${threshold}.`,
          { pid, processName: processNames.get(pid) ?? "unknown", observedCount: count, threshold, remoteAddresses }, now, "medium"
        );
        if (remoteAddresses.length === 1) event.remoteAddress = remoteAddresses[0];
        events.push(event);
      }
      try { onState({ listeningPorts: [...listeningPorts], startupEntries: [...startupBaseline.values()], securityIssue }); } catch { /* A baseline write failure must not stop observation. */ }
      return events;
    },
    reportSendFailure(now = new Date().toISOString()) {
      outageFailures++;
      if (outageFailures < 3 || outageReported) return [];
      outageReported = true;
      return [makeEvent("repeated_agent_failures", "Repeated agent report failures", `The agent failed to deliver reports ${outageFailures} consecutive times.`, { consecutiveFailures: outageFailures }, now, "low")];
    },
    reportSendSuccess() { outageFailures = 0; outageReported = false; }
  };
}

export function makeEvent(rule, title, reason, evidence, timestamp = new Date().toISOString(), severity = "low") {
  return { eventId: randomUUID(), rule, title, reason, evidence, timestamp, severity, category: "endpoint-detection" };
}
function isLocal(ip) { return ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.") || ip.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd"); }
