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
    db.prepare("INSERT INTO device_snapshots (device_id,captured_at,processes_json,connections_json) VALUES (?,?,?,?)")
      .run(deviceId, now, JSON.stringify([{ pid: 4120, parentPid: 900, name: "sample-worker.exe", startedAt: now }]), JSON.stringify([{ pid: 4120, protocol: "TCP", state: "Listen", localAddress: "0.0.0.0", localPort: 9443, remoteAddress: "0.0.0.0", remotePort: 0, timestamp: now }]));
    const eventId = crypto.randomUUID();
    const evidence = { endpoint: "0.0.0.0:9443", pid: 4120, processName: "sample-worker.exe", simulated: true };
    const event = Number(db.prepare(`INSERT INTO events (source,category,action,reason,evidence,process_details,severity,detection_rule,device_id,source_event_id,created_at)
      VALUES ('windows-agent','endpoint-detection','observed',?,?,?,?,?,?,?,?)`).run("A TCP listener appeared at 0.0.0.0:9443 since the previous sample.", JSON.stringify(evidence), "PID 4120 · sample-worker.exe", "medium", "new_listening_port", deviceId, eventId, now).lastInsertRowid);
    db.prepare(`INSERT INTO alerts (title,severity,status,evidence,observed_facts,estimate,event_id,device_id,created_at)
      VALUES (?,?, 'open', ?, ?, ?, ?, ?, ?)`).run("New listening TCP port (simulated)", "medium", "Simulated test event: a new listener was observed at 0.0.0.0:9443 (PID 4120).", JSON.stringify(evidence), "Synthetic dashboard demonstration; no process or network traffic was affected.", event, deviceId, now);
    recordAudit(db, "demo-command", "device.demo_seeded", `device:${deviceId}`, "Created a clearly labeled simulated device and test alert.");
    device = { device_id: deviceId };
  }
  console.log(`Simulated device ready: ${device.device_id}`);
  console.log("Sign in to the dashboard and open Devices or Overview to inspect the simulated alert.");
} finally { db.close(); }
