import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { migrate } from "../src/db.js";
import { generatePilotReport, rollbackWebsitePilot, validatePilotOptions, validatePilotSimulationConfig } from "../src/pilot.js";

function database(){const db=new DatabaseSync(":memory:");migrate(db);return db;}

test("pilot option validation requires a positive asset and bounded report window",()=>{
  assert.deepEqual(validatePilotOptions({assetId:"4",days:14}),{assetId:4,days:14});
  assert.throws(()=>validatePilotOptions({assetId:0}),/asset ID/);
  assert.throws(()=>validatePilotOptions({assetId:1,days:91}),/1 to 90/);
});

test("pilot simulation configuration permits only bounded observe-mode loopback targets",()=>{
  const asset={type:"website",upstream_url:"http://127.0.0.1:4320"},rule={enabled:1,mode:"observe",rateLimitCount:3};
  assert.equal(validatePilotSimulationConfig({asset,rule,gatewayUrl:"http://localhost:4310"}).gateway.hostname,"localhost");
  assert.throws(()=>validatePilotSimulationConfig({asset,rule:{...rule,mode:"block"},gatewayUrl:"http://127.0.0.1:4310"}),/observe mode/);
  assert.throws(()=>validatePilotSimulationConfig({asset:{...asset,upstream_url:"https://production.example"},rule,gatewayUrl:"http://127.0.0.1:4310"}),/upstream must be loopback/);
  assert.throws(()=>validatePilotSimulationConfig({asset,rule:{...rule,rateLimitCount:6},gatewayUrl:"http://127.0.0.1:4310"}),/5 or fewer/);
});

test("pilot rollback restores website upstream, observe mode, and only queues SentryGate-owned rules",()=>{
  const db=database();
  try{
    const now=new Date().toISOString();
    const website=Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,description,upstream_url,created_at) VALUES('Pilot','website','owner','healthy','pilot.test','','http://127.0.0.1:4320',?)").run(now).lastInsertRowid);
    const computer=Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,description,created_at) VALUES('Test device','computer','owner','healthy','PC-1','',?)").run(now).lastInsertRowid);
    const otherComputer=Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,description,created_at) VALUES('Other device','computer','owner','healthy','PC-2','',?)").run(now).lastInsertRowid);
    db.prepare("INSERT INTO gateway_rules(asset_id,enabled,mode,updated_at) VALUES(?,1,'block',?)").run(website,now);
    db.prepare("INSERT INTO device_agents(device_id,name,hostname,os_version,agent_version,credential_hash,enrolled_at,asset_id) VALUES(?,'Agent','PC-1','Windows','1','hash',?,?)").run(randomUUID(),now,computer);
    db.prepare("INSERT INTO device_agents(device_id,name,hostname,os_version,agent_version,credential_hash,enrolled_at,asset_id) VALUES(?,'Other','PC-2','Windows','1','hash',?,?)").run(randomUUID(),now,otherComputer);
    const device=db.prepare("SELECT device_id FROM device_agents WHERE name='Agent'").get().device_id;
    const otherDevice=db.prepare("SELECT device_id FROM device_agents WHERE name='Other'").get().device_id;
    const insertRule=db.prepare(`INSERT INTO firewall_rules(id,device_id,remote_cidr,protocol,local_port,reason,evidence,expires_at,status,idempotency_key,preview_hash,created_by,created_at,updated_at)
      VALUES(?,?,?,'TCP',443,'test','test',?,'active',?,'hash','owner',?,?)`);
    insertRule.run("sg-owned",device,"192.0.2.3",new Date(Date.now()+3600000).toISOString(),"sg-key",now,now);
    insertRule.run("other-device",otherDevice,"192.0.2.4",new Date(Date.now()+3600000).toISOString(),"other-key",now,now);
    const result=rollbackWebsitePilot(db,{assetId:website,previousUpstream:"http://127.0.0.1:4320",deviceId:device});
    assert.equal(result.mode,"observe");
    assert.equal(result.queuedFirewallRemovals,1);
    assert.equal(db.prepare("SELECT mode FROM gateway_rules WHERE asset_id=?").get(website).mode,"observe");
    assert.equal(db.prepare("SELECT status FROM firewall_rules WHERE id='sg-owned'").get().status,"removing");
    assert.equal(db.prepare("SELECT status FROM firewall_rules WHERE id='other-device'").get().status,"active");
    assert.equal(db.prepare("SELECT action FROM audit_log WHERE action='pilot.rollback'").get().action,"pilot.rollback");
    assert.throws(()=>rollbackWebsitePilot(db,{assetId:website,previousUpstream:"https://user:password@example.test"}),/embedded credentials/);
  }finally{db.close();}
});

test("pilot report includes measurements, alerts, reviewed false positives, incidents and recommendation",()=>{
  const db=database();
  try{
    const now=new Date().toISOString(),asset=Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,description,created_at) VALUES('Pilot','website','owner','healthy','pilot.test','',?)").run(now).lastInsertRowid);
    const event=Number(db.prepare(`INSERT INTO events(asset_id,source,category,action,reason,evidence,severity,detection_rule,false_positive,reviewed_by,reviewed_at,created_at)
      VALUES(?,'website-gateway','http-request','observed','Sensitive path','GET /.env','medium','sensitive_path',1,'analyst',? ,?)`).run(asset,now,now).lastInsertRowid);
    db.prepare("INSERT INTO alerts(asset_id,event_id,title,severity,status,evidence,observed_facts,created_at) VALUES(?,?,'Sensitive path','medium','open','GET /.env','Matched sensitive_path',?)").run(asset,event,now);
    const incidentId=randomUUID();
    db.prepare(`INSERT INTO incidents(id,correlation_key,asset_id,observed_ip,detection_rule,severity,status,first_seen,last_seen,event_count,created_at,updated_at)
      VALUES(?, ?, ?, '127.0.0.1','sensitive_path','medium','open',?,?,1,?,?)`).run(incidentId,`site:${asset}:127.0.0.1:sensitive_path`,asset,now,now,now,now);
    db.prepare("INSERT INTO gateway_request_metrics(asset_id,event_id,observed_at,duration_ms,upstream_error) VALUES(?,?,?,12.3,0),(?,?,?,30.2,0)").run(asset,event,now,asset,event,now);
    const report=generatePilotReport(db,{assetId:asset,days:7});
    assert.equal(report.measurements.requests,2);
    assert.equal(report.measurements.alerts,1);
    assert.equal(report.measurements.falsePositives,1);
    assert.equal(report.measurements.gatewayLatencyMs.p95,30.2);
    assert.equal(report.falsePositiveReviews[0].reviewedBy,"analyst");
    assert.equal(report.incidents[0].id,incidentId);
    assert.equal(report.recommendation,"adjust");
    assert.match(report.limitations.join(" "),/not establish production readiness/);
  }finally{db.close();}
});
