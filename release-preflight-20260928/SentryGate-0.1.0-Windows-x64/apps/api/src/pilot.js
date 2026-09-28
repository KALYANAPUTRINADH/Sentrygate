import { recordAudit } from "./audit.js";

export function validatePilotOptions(options={}){
  const assetId=Number(options.assetId);
  if(!Number.isSafeInteger(assetId)||assetId<1)throw new Error("A positive website asset ID is required");
  if(options.days!==undefined&&(!Number.isInteger(Number(options.days))||Number(options.days)<1||Number(options.days)>90))throw new Error("Pilot report days must be from 1 to 90");
  return {assetId,days:Number(options.days??7)};
}

export function validatePilotSimulationConfig({asset,rule,gatewayUrl}){
  if(!asset||asset.type!=="website"||asset.removed_at)throw new Error("Simulation requires an active website asset");
  if(!rule||!rule.enabled||rule.mode!=="observe")throw new Error("Simulation requires enabled observe mode");
  if(!Number.isInteger(rule.rateLimitCount)||rule.rateLimitCount<1||rule.rateLimitCount>5)throw new Error("For the bounded local burst set rate limit to 5 or fewer");
  const local=url=>["127.0.0.1","::1","localhost"].includes(url.hostname.replace(/^\[|\]$/g,""));
  let upstream,gateway;
  try{upstream=new URL(asset.upstream_url);gateway=new URL(gatewayUrl);}catch{throw new Error("Simulation requires valid upstream and gateway URLs");}
  if(!local(upstream))throw new Error("Refusing simulation: website upstream must be loopback");
  if(!local(gateway))throw new Error("Refusing simulation: gateway URL must be loopback");
  if(!["http:","https:"].includes(upstream.protocol)||!["http:","https:"].includes(gateway.protocol))throw new Error("Simulation URLs must use HTTP or HTTPS");
  return {upstream,gateway};
}

export function pilotMetrics(db,{assetId=null,days=7,now=new Date()}={}){
  if(!Number.isInteger(days)||days<1||days>90)throw new Error("Pilot metrics window must be from 1 to 90 days");
  const since=new Date(now.getTime()-days*86_400_000).toISOString();
  const scope=assetId===null?"":" AND asset_id=?";
  const args=assetId===null?[since]:[since,assetId];
  const base=db.prepare(`SELECT COUNT(*) AS requests, SUM(upstream_error) AS upstreamErrors FROM gateway_request_metrics WHERE observed_at>=?${scope}`).get(...args);
  const latencies=db.prepare(`SELECT duration_ms AS durationMs FROM gateway_request_metrics WHERE observed_at>=?${scope} ORDER BY observed_at DESC LIMIT 10000`).all(...args).map(row=>row.durationMs).sort((a,b)=>a-b);
  const eventArgs=assetId===null?[since]:[since,assetId];
  const eventScope=assetId===null?"":" AND asset_id=?";
  const eventCount=db.prepare(`SELECT COUNT(*) AS count FROM events WHERE source='website-gateway' AND created_at>=?${eventScope}`).get(...eventArgs).count;
  const detections=db.prepare(`SELECT COUNT(*) AS count FROM events WHERE source='website-gateway' AND created_at>=? AND detection_rule NOT IN ('none','allowlist')${eventScope}`).get(since,...(assetId===null?[]:[assetId])).count;
  const falsePositives=db.prepare(`SELECT COUNT(*) AS count FROM events WHERE source='website-gateway' AND created_at>=? AND false_positive=1${eventScope}`).get(...eventArgs).count;
  const alertArgs=assetId===null?[since]:[since,assetId];
  const alertScope=assetId===null?"":" AND asset_id=?";
  const alerts=db.prepare(`SELECT COUNT(*) AS count FROM alerts WHERE created_at>=?${alertScope}`).get(...alertArgs).count;
  const device=db.prepare(`SELECT device_id AS deviceId,name,agent_version AS version,last_heartbeat AS lastHeartbeat,health_status AS healthStatus,health_detail AS healthDetail,collection_interval_seconds AS heartbeatIntervalSeconds FROM device_agents WHERE revoked_at IS NULL AND is_demo=0${assetId===null?"":" AND asset_id=(SELECT id FROM assets WHERE id=?)"} ORDER BY last_heartbeat DESC LIMIT 1`).get(...(assetId===null?[]:[assetId]))??null;
  const websitePolicies=db.prepare(`SELECT a.id,a.name,a.upstream_url AS upstreamUrl,g.enabled,g.mode,g.failure_mode AS failureMode,g.rate_limit_count AS rateLimitCount,g.window_seconds AS windowSeconds,gw.last_heartbeat AS lastHeartbeat,gw.health_status AS healthStatus FROM assets a LEFT JOIN gateway_rules g ON g.asset_id=a.id LEFT JOIN website_gateway_status gw ON gw.asset_id=a.id WHERE a.type='website' AND a.removed_at IS NULL${assetId===null?"":" AND a.id=?"} ORDER BY a.name`).all(...(assetId===null?[]:[assetId]));
  const upstreamErrors=Number(base.upstreamErrors??0),requests=base.requests;
  const fpRate=detections?falsePositives/detections:0,upstreamErrorRate=requests?upstreamErrors/requests:0;
  let recommendation="continue";
  let recommendationReason="No marked false positives or material upstream errors were observed in the selected sample.";
  if(!requests){recommendation="adjust";recommendationReason="Insufficient gateway measurements; complete the local and staging simulation before deciding.";}
  else if(upstreamErrorRate>=0.02){recommendation="rollback";recommendationReason="At least 2% of measured gateway requests returned a server-side error; restore the prior routing before proceeding.";}
  else if(fpRate>=0.25){recommendation="adjust";recommendationReason="At least 25% of reviewed detections were marked false positive; adjust rules and repeat observe-mode validation.";}
  else if(!device||device.healthStatus!=="healthy"||!device.lastHeartbeat){recommendation="adjust";recommendationReason="No healthy enrolled Windows agent with a reported heartbeat is available; complete the endpoint pilot checks before proceeding.";}
  const metrics={windowDays:days,since,requests,eventRecords:eventCount,alerts,falsePositives,detections,falsePositiveRate:fpRate,upstreamErrors,upstreamErrorRate,
    gatewayLatencyMs:{sampleCount:latencies.length,p50:percentile(latencies,.50),p95:percentile(latencies,.95),p99:percentile(latencies,.99)},agent:device?{...device,healthy:device.healthStatus==="healthy"&&Boolean(device.lastHeartbeat)&&now.getTime()-Date.parse(device.lastHeartbeat)<=device.heartbeatIntervalSeconds*3000}:null};
  return {metrics,recommendation,recommendationReason,websitePolicies};
}

export function generatePilotReport(db,options={}){
  const {assetId,days}=options.assetId===undefined?{assetId:null,days:options.days??7}:validatePilotOptions(options);
  const result=pilotMetrics(db,{assetId,days});
  const events=db.prepare(`SELECT e.id,e.created_at AS timestamp,e.detection_rule AS rule,e.severity,e.action,e.false_positive AS falsePositive,e.reviewed_by AS reviewedBy,e.reviewed_at AS reviewedAt,e.reason,e.evidence,a.name AS asset FROM events e LEFT JOIN assets a ON a.id=e.asset_id WHERE e.source='website-gateway' AND e.created_at>=?${assetId===null?"":" AND e.asset_id=?"} ORDER BY e.created_at DESC LIMIT 2000`).all(...(assetId===null?[result.metrics.since]:[result.metrics.since,assetId]));
  const incidents=db.prepare(`SELECT i.id,i.severity,i.status,i.first_seen AS firstSeen,i.last_seen AS lastSeen,i.event_count AS eventCount,i.detection_rule AS rule,i.observed_ip AS observedIp,a.name AS asset FROM incidents i LEFT JOIN assets a ON a.id=i.asset_id WHERE i.created_at>=?${assetId===null?"":" AND i.asset_id=?"} ORDER BY i.created_at DESC LIMIT 500`).all(...(assetId===null?[result.metrics.since]:[result.metrics.since,assetId]));
  return {product:"SentryGate",reportType:"controlled-pilot",generatedAt:new Date().toISOString(),scope:{assetId,days:result.metrics.windowDays},measurements:result.metrics,incidents,falsePositiveReviews:events.filter(e=>e.falsePositive),recommendation:result.recommendation,recommendationReason:result.recommendationReason,
    limitations:["Gateway request duration ends when the response finishes and includes upload time, upstream wait, and response streaming; it is not isolated gateway CPU/queue latency.","Gateway latency and request totals cover only requests measured after Milestone 9 was installed.","False positives are administrator-reviewed labels, not an automated ground-truth classification.","This report does not establish production readiness or identify a person from network metadata."]};
}

export function rollbackWebsitePilot(db,{assetId,previousUpstream,deviceId=null,actor="pilot-rollback"}={}){
  const id=Number(assetId);
  if(!Number.isSafeInteger(id)||id<1)throw new Error("A positive website asset ID is required");
  let upstream;
  try{upstream=new URL(previousUpstream);}catch{throw new Error("A valid previous upstream URL is required");}
  if(!["http:","https:"].includes(upstream.protocol)||upstream.username||upstream.password||upstream.hash)throw new Error("Previous upstream must be HTTP(S), without embedded credentials or fragments");
  const asset=db.prepare("SELECT id,type,upstream_url FROM assets WHERE id=? AND removed_at IS NULL").get(id);
  if(!asset||asset.type!=="website")throw new Error("Active website asset not found");
  const now=new Date().toISOString();
  db.exec("BEGIN");
  try{
    db.prepare("UPDATE assets SET upstream_url=? WHERE id=?").run(previousUpstream,id);
    db.prepare("UPDATE gateway_rules SET enabled=1,mode='observe',updated_at=? WHERE asset_id=?").run(now,id);
    const removedGatewayBlocks=db.prepare("DELETE FROM gateway_ip_blocks WHERE asset_id=?").run(id).changes;
    db.prepare("UPDATE proposed_actions SET status='rolled_back',updated_at=?,failure='' WHERE target_type='website' AND target_id=? AND status IN ('active','approved','proposed')").run(now,String(id));
    const linked=deviceId?db.prepare("SELECT d.device_id FROM device_agents d JOIN assets a ON a.id=d.asset_id WHERE d.device_id=? AND d.revoked_at IS NULL AND a.type='computer' AND a.removed_at IS NULL").get(deviceId):db.prepare("SELECT d.device_id FROM device_agents d WHERE d.asset_id=? AND d.revoked_at IS NULL").get(id);
    if(deviceId&&!linked)throw new Error("Device ID must identify an active enrolled SentryGate agent on a computer asset");
    const queuedFirewallRemovals=linked?db.prepare("UPDATE firewall_rules SET status='removing',updated_at=? WHERE device_id=? AND status IN ('active','approved','failed','expired')").run(now,linked.device_id).changes:0;
    recordAudit(db,actor,"pilot.rollback",`asset:${id}`,`Restored configured upstream to ${upstream.origin}; set website rules to observe; removed ${removedGatewayBlocks} SentryGate gateway block(s); queued ${queuedFirewallRemovals} SentryGate-owned device rule removal(s)${linked?` for device ${linked.device_id}`:""}. No unrelated rules were accessed.`);
    db.exec("COMMIT");
    return {assetId:id,previousUpstream:asset.upstream_url,restoredUpstream:previousUpstream,mode:"observe",removedGatewayBlocks,queuedFirewallRemovals,agentConfirmationRequired:queuedFirewallRemovals>0};
  }catch(error){db.exec("ROLLBACK");throw error;}
}

function percentile(values,p){if(!values.length)return null;return Number(values[Math.max(0,Math.ceil(values.length*p)-1)].toFixed(2));}
