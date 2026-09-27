import fs from "node:fs";
import { recordAudit } from "./audit.js";
import { logOperational } from "./logger.js";

export function databaseBytes(dbPath) {
  return [dbPath,`${dbPath}-wal`,`${dbPath}-shm`].reduce((total,file)=>{try{return total+fs.statSync(file).size;}catch{return total;}},0);
}

export function sweepOperationalState(db, config, now = new Date()) {
  const stamp=now.toISOString();
  const settings=db.prepare("SELECT raw_event_days,report_days FROM incident_settings WHERE id=1").get();
  const cutoff=new Date(now.getTime()-settings.raw_event_days*86_400_000).toISOString();
  const reportCutoff=new Date(now.getTime()-settings.report_days*86_400_000).toISOString();
  const removedEvents=db.prepare("DELETE FROM events WHERE created_at<?").run(cutoff).changes;
  const removedGatewayMetrics=db.prepare("DELETE FROM gateway_request_metrics WHERE observed_at<?").run(cutoff).changes;
  const removedReports=db.prepare("DELETE FROM incident_reports WHERE expires_at<=? OR created_at<?").run(stamp,reportCutoff).changes;
  const removedAudit=db.prepare("DELETE FROM audit_log WHERE created_at<?").run(cutoff).changes;
  db.prepare("DELETE FROM revoked_sessions WHERE expires_at<?").run(now.getTime());
  if(removedEvents||removedGatewayMetrics||removedReports||removedAudit){
    try{db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");}
    catch(error){logOperational("error","storage.compaction_failed",{code:error.code??error.name??"Error"});}
  }
  const staleDevices=db.prepare(`SELECT device_id,asset_id,name,last_heartbeat,collection_interval_seconds FROM device_agents
    WHERE revoked_at IS NULL AND is_demo=0 AND last_heartbeat IS NOT NULL AND datetime(last_heartbeat)<datetime(?,'-' || (collection_interval_seconds*3) || ' seconds')`).all(stamp);
  for(const device of staleDevices){
    const exists=db.prepare("SELECT id FROM alerts WHERE device_id=? AND title='Windows agent stopped reporting' AND status='open'").get(device.device_id);
    if(!exists){db.prepare(`INSERT INTO alerts(asset_id,title,severity,status,evidence,observed_facts,estimate,device_id,created_at) VALUES(?,?,'medium','open',?,?,?,?,?)`)
      .run(device.asset_id,"Windows agent stopped reporting",`No authenticated heartbeat received after ${device.last_heartbeat}; expected interval ${device.collection_interval_seconds} seconds.`,"The API last received an authenticated report at the timestamp shown.","Device availability may be affected; this does not identify a cause or user.",device.device_id,stamp);
      recordAudit(db,"system","health.agent_stale",`device:${device.device_id}`,"Opened an alert after the enrolled agent missed three reporting intervals.");}
  }
  db.prepare(`UPDATE alerts SET status='closed' WHERE title='Windows agent stopped reporting' AND status='open'
    AND device_id IN (SELECT device_id FROM device_agents WHERE revoked_at IS NULL AND last_heartbeat IS NOT NULL
      AND datetime(last_heartbeat)>=datetime(?,'-' || (collection_interval_seconds*3) || ' seconds'))`).run(stamp);
  const staleGateways=db.prepare(`SELECT g.asset_id,g.last_heartbeat,a.name FROM website_gateway_status g JOIN assets a ON a.id=g.asset_id
    WHERE a.removed_at IS NULL AND datetime(g.last_heartbeat)<datetime(?,'-90 seconds')`).all(stamp);
  for(const site of staleGateways){
    const exists=db.prepare("SELECT id FROM alerts WHERE asset_id=? AND title='Website gateway stopped reporting' AND status='open'").get(site.asset_id);
    if(!exists){db.prepare(`INSERT INTO alerts(asset_id,title,severity,status,evidence,observed_facts,estimate,created_at) VALUES(?,?,'high','open',?,?,?,?)`)
      .run(site.asset_id,"Website gateway stopped reporting",`Gateway heartbeat last observed at ${site.last_heartbeat}.`,"The local gateway status heartbeat is older than 90 seconds.","The gateway process may be stopped or unable to write local status.",stamp);
      recordAudit(db,"system","health.gateway_stale",`asset:${site.asset_id}`,"Opened an alert after the website gateway heartbeat expired.");}
  }
  db.prepare(`UPDATE alerts SET status='closed' WHERE title='Website gateway stopped reporting' AND status='open'
    AND asset_id IN (SELECT asset_id FROM website_gateway_status WHERE datetime(last_heartbeat)>=datetime(?,'-90 seconds'))`).run(stamp);
  const bytes=databaseBytes(config.dbPath);
  if(removedEvents||removedGatewayMetrics||removedReports||removedAudit) logOperational("info","retention.completed",{removedEvents,removedGatewayMetrics,removedReports,removedAudit,dbBytes:bytes});
  return {removedEvents,removedGatewayMetrics,removedReports,removedAudit,dbBytes:bytes,limitBytes:config.maxDbBytes};
}
