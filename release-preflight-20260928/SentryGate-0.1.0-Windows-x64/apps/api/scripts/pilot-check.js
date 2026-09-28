import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";

const args=readArgs(process.argv.slice(2)),assetId=Number(args["asset-id"]),deviceId=args["device-id"];
if(!Number.isSafeInteger(assetId)||assetId<1)throw new Error("Pass --asset-id for the approved staging website.");
if(!deviceId||!/^[0-9a-f-]{36}$/i.test(deviceId))throw new Error("Pass --device-id for the enrolled Windows test computer.");
if(!args.backup)throw new Error("Pass --backup with a recent verified SQLite backup path.");
const config=loadConfig(),db=openDatabase(path.resolve(args.db??config.dbPath)),results=[];
const check=(name,ok,detail)=>{results.push({name,ok:Boolean(ok),detail});console.log(`${ok?"PASS":"FAIL"} ${name}: ${detail}`);};
try{
  const asset=db.prepare("SELECT id,name,upstream_url FROM assets WHERE id=? AND type='website' AND removed_at IS NULL").get(assetId);
  check("website asset",Boolean(asset),asset?`${asset.name} registered and active`:`asset ${assetId} not found`);
  if(!asset)process.exitCode=1;
  let rule=null,upstream=null;
  if(asset){rule=db.prepare("SELECT enabled,mode,failure_mode AS failureMode FROM gateway_rules WHERE asset_id=?").get(assetId);try{upstream=new URL(asset.upstream_url);}catch{}}
  check("observe-only detection",Boolean(rule&&rule.enabled&&rule.mode==="observe"),rule?`enabled=${Boolean(rule.enabled)}, mode=${rule.mode}`:"website gateway policy missing");
  check("firewall preview posture",true,"pilot tooling never approves rules; automatic action policies remain suggestion-only");
  check("upstream URL",Boolean(upstream),asset?.upstream_url||"invalid or empty");
  if(upstream){const probe=await fetch(upstream.href,{method:"HEAD",signal:AbortSignal.timeout(5000)});check("upstream TLS/connectivity",probe.status<500,`${upstream.origin} responded HTTP ${probe.status}; TLS validation was enabled`);}
  const apiHealth=await fetch(new URL("/api/health",config.apiBaseUrl),{signal:AbortSignal.timeout(4000)});
  const health=await apiHealth.json().catch(()=>({}));check("API and database health",apiHealth.ok&&health.ok&&health.database==="ready",`HTTP ${apiHealth.status}; database=${health.database??"unknown"}; transport=${health.transport??"unknown"}`);
  const gatewayBase=process.env.SENTRYGATE_PILOT_GATEWAY_URL??`${config.tlsCertPath?"https":"http"}://127.0.0.1:${config.gatewayPort}`;
  const gatewayUrl=new URL(`/site/${assetId}/`,gatewayBase);
  const loopback=host=>["127.0.0.1","::1","localhost"].includes(host.replace(/^\[|\]$/g,""));
  const transportOk=([config.apiBaseUrl,upstream?.href,gatewayUrl.origin].filter(Boolean).every(raw=>{const u=new URL(raw);return loopback(u.hostname)||u.protocol==="https:";}));
  check("remote TLS policy",transportOk,"remote API, gateway, and upstream URLs must use HTTPS; loopback HTTP is allowed only for local development");
  const gatewayResponse=await fetch(gatewayUrl,{method:"HEAD",signal:AbortSignal.timeout(5000)});
  check("gateway connectivity and certificate",gatewayResponse.status<500,`${gatewayUrl.origin} returned HTTP ${gatewayResponse.status}; client certificate verification enabled`);
  check("TLS certificate files",!config.tlsCertPath||fs.existsSync(config.tlsCertPath)&&fs.existsSync(config.tlsKeyPath),config.tlsCertPath?`configured certificate/key present at ${config.tlsCertPath}`:"loopback development only; remote pilot requires configured TLS files");
  const device=db.prepare("SELECT name,agent_version,last_heartbeat,health_status,health_detail,collection_interval_seconds,revoked_at,is_demo FROM device_agents WHERE device_id=?").get(deviceId);
  check("agent enrollment",Boolean(device&&!device.revoked_at&&!device.is_demo),device?`${device.name} ${device.agent_version}; heartbeat ${device.last_heartbeat??"not yet received"}`:"device ID not found, revoked, or demo-only");
  if(device&&!device.is_demo&&!device.revoked_at){const age=device.last_heartbeat?Date.now()-Date.parse(device.last_heartbeat):Infinity,limit=(device.collection_interval_seconds*3+10)*1000;check("agent heartbeat",age<limit&&device.health_status==="healthy",device.last_heartbeat?`${Math.round(age/1000)} seconds ago; health=${device.health_status}; detail=${device.health_detail||"none"}`:"no authenticated heartbeat yet");}
  const firewallCount=db.prepare("SELECT COUNT(*) AS count FROM firewall_rules WHERE device_id=? AND status IN ('approved','active')").get(deviceId).count;
  check("firewall preview-only posture",firewallCount===0,`${firewallCount} approved/active SentryGate rule(s) on selected device; no rules are applied by this preflight`);
  const backup=path.resolve(args.backup);let backupOk=false,backupDetail="file unavailable or integrity check failed";
  try{const fileDb=new DatabaseSync(backup,{readOnly:true});const integrity=fileDb.prepare("PRAGMA integrity_check").get();backupOk=integrity?.integrity_check==="ok";backupDetail=`integrity_check=${integrity?.integrity_check??"unknown"}; size=${fs.statSync(backup).size} bytes`;fileDb.close();}catch(error){backupDetail=error.message.slice(0,180);}
  check("database backup",backupOk,backupDetail);
  const fsInfo=fs.statfsSync(path.dirname(path.resolve(config.dbPath))),available=fsInfo.bavail*fsInfo.bsize;
  check("available disk space",available>=2*1024**3,`${(available/1024**3).toFixed(2)} GiB available on database volume; pilot gate requires 2 GiB`);
  if(results.some(row=>!row.ok))process.exitCode=1;
  console.log(`Pilot preflight: ${results.filter(x=>x.ok).length}/${results.length} checks passed.`);
}finally{db.close();}

function readArgs(values){const result={};for(let i=0;i<values.length;i++){if(!values[i].startsWith("--"))throw new Error(`Unexpected argument ${values[i]}`);result[values[i].slice(2)]=values[++i];}return result;}
