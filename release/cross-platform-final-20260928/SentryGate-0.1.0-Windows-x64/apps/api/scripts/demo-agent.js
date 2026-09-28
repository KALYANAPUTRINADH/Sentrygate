import crypto from "node:crypto";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { recordAudit } from "../src/audit.js";

const config = loadConfig();
const db = openDatabase(config.dbPath);
try {
  let device = db.prepare("SELECT device_id FROM device_agents WHERE is_demo=1 LIMIT 1").get();
  if (!device) {
    const deviceId = crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO device_agents (device_id,name,hostname,os_version,agent_version,credential_hash,enrolled_at,last_heartbeat,health_status,is_demo)
      VALUES (?,?,?,?,?,?,?,?,?,1)`).run(deviceId, "Simulated Windows test device", "SG-TEST-WIN01", "Windows 11 (simulated)", "0.3.0-demo", crypto.randomBytes(32).toString("hex"), now, now, "healthy");
    device = { device_id: deviceId };
  }
  let assetId = db.prepare("SELECT asset_id FROM device_agents WHERE device_id=?").get(device.device_id).asset_id;
  if (!assetId) {
    assetId = Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,description,created_at) VALUES('Simulated Windows test device','computer','demo','healthy','SG-TEST-WIN01','Synthetic host-security inventory',?)").run(new Date().toISOString()).lastInsertRowid);
    db.prepare("UPDATE device_agents SET asset_id=? WHERE device_id=?").run(assetId, device.device_id);
  }
  const now = new Date().toISOString(), processPath = "C:\\Program Files\\SentryGate Demo\\sample-worker.exe";
  const evidence = { endpoint: "0.0.0.0:9443", pid: 4120, processName: "sample-worker.exe", simulated: true };
  db.prepare(`INSERT INTO device_snapshots(device_id,captured_at,processes_json,connections_json,applications_json,services_json,startup_entries_json,security_settings_json)
    VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET captured_at=excluded.captured_at,processes_json=excluded.processes_json,connections_json=excluded.connections_json,applications_json=excluded.applications_json,services_json=excluded.services_json,startup_entries_json=excluded.startup_entries_json,security_settings_json=excluded.security_settings_json`)
    .run(device.device_id, now, JSON.stringify([{ pid: 4120, parentPid: 900, name: "sample-worker.exe", executablePath: processPath, startedAt: now }]), JSON.stringify([{ pid: 4120, protocol: "TCP", state: "Listen", localAddress: "0.0.0.0", localPort: 9443, remoteAddress: "0.0.0.0", remotePort: 0, timestamp: now }]), JSON.stringify([{ name: "SentryGate Demo Worker", version: "1.0.0", publisher: "Local simulation", installLocation: "C:\\Program Files\\SentryGate Demo" }]), JSON.stringify([{ name: "DemoSvc", displayName: "Demo Service", state: "Running", startMode: "Auto", processId: 4120 }, { name: "WinDefend", displayName: "Microsoft Defender Antivirus Service", state: "Stopped", startMode: "Disabled", processId: 0 }]), JSON.stringify([{ name: "DemoWorker", executablePath: processPath, source: "Simulated Run key" }]), JSON.stringify({ firewallProfiles: [{ name: "Domain", enabled: true }, { name: "Public", enabled: true }], defenderRealtimeProtection: false, collectionNotes: ["Synthetic demonstration state; no Windows APIs were queried."] }));
  const demoEvents = [
    ["new_listening_port", "New listening TCP port (simulated)", "A TCP listener appeared at 0.0.0.0:9443 for process sample-worker.exe (PID 4120).", evidence, "medium"],
    ["new_startup_entry", "New startup entry (simulated)", "A startup entry appeared since the previous sample: DemoWorker.", { name: "DemoWorker", executablePath: processPath, simulated: true }, "medium"],
    ["security_protection_disabled", "Windows protection setting disabled (simulated)", "Microsoft Defender real-time protection is disabled; security service WinDefend reports Stopped/Disabled.", { defenderRealtimeProtection: false, disabledServices: [{ name: "WinDefend", state: "Stopped", startMode: "Disabled" }], simulated: true }, "high"]
  ];
  for (const [rule, title, reason, itemEvidence, severity] of demoEvents) {
    const eventId = `demo-${rule}-${device.device_id}`;
    const inserted = db.prepare(`INSERT OR IGNORE INTO events(asset_id,source,category,action,reason,evidence,process_details,severity,detection_rule,device_id,source_event_id,created_at)
      VALUES(?,'windows-agent','endpoint-detection','observed',?,?,?,?,?,?,?,?)`).run(assetId, reason, JSON.stringify(itemEvidence), "PID 4120 · sample-worker.exe", severity, rule, device.device_id, eventId, now);
    if (inserted.changes) {
      const event = Number(inserted.lastInsertRowid);
      db.prepare(`INSERT INTO alerts(asset_id,title,severity,status,evidence,observed_facts,estimate,event_id,device_id,created_at)
        VALUES(?,?,?,'open',?,?,?,?,?,?)`).run(assetId, title, severity, reason, JSON.stringify(itemEvidence), "Synthetic test event; no real process, service, firewall setting, or network traffic was affected.", event, device.device_id, now);
    }
  }
  recordAudit(db, "demo-command", "device.demo_seeded", `device:${device.device_id}`, "Created synthetic host-security inventory and alerts; no Windows APIs or firewall operations were used.");
  console.log(`Simulated device ready: ${device.device_id}`);
  console.log("Sign in and open Devices to inspect simulated listeners, process ownership, installed app/service/startup inventories, checkup warnings, and alerts.");
} finally { db.close(); }
