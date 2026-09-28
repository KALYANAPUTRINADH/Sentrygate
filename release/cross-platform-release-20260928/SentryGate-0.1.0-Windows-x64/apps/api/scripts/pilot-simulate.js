import path from "node:path";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { validatePilotSimulationConfig } from "../src/pilot.js";

const args=readArgs(process.argv.slice(2)),assetId=Number(args["asset-id"]);
if(!Number.isSafeInteger(assetId)||assetId<1)throw new Error("Pass --asset-id for the local test website.");
const config=loadConfig(),db=openDatabase(path.resolve(args.db??config.dbPath));
try{
  const asset=db.prepare("SELECT id,name,type,removed_at,upstream_url FROM assets WHERE id=? AND type='website' AND removed_at IS NULL").get(assetId);
  if(!asset)throw new Error("Active website asset not found.");
  const rule=db.prepare("SELECT enabled,mode,rate_limit_count AS rateLimitCount FROM gateway_rules WHERE asset_id=?").get(assetId);
  const gatewayBase=process.env.SENTRYGATE_PILOT_GATEWAY_URL??`http://127.0.0.1:${config.gatewayPort}`;
  const {gateway}=validatePilotSimulationConfig({asset,rule,gatewayUrl:gatewayBase});
  const base=`${gateway.origin}/site/${assetId}`;
  const results=[];
  results.push(await probe("normal visitor",`${base}/?pilot=normal`));
  results.push(await probe("sensitive-path probe",`${base}/.env?pilot=probe`));
  for(let i=0;i<rule.rateLimitCount+2;i++)results.push(await probe(`bounded rate sample ${i+1}`,`${base}/?pilot=rate-${i+1}`));
  const detected=db.prepare("SELECT COUNT(*) AS count FROM events WHERE asset_id=? AND source='website-gateway' AND created_at>=? AND detection_rule IN ('sensitive_path','rate_limit')").get(assetId,new Date(Date.now()-60_000).toISOString()).count;
  if(results.some(x=>x.status>=500))throw new Error("At least one local simulation request returned a server-side error.");
  console.log(JSON.stringify({asset:asset.name,mode:"observe",gateway:gateway.origin,requests:results.length,normal:results[0].status,sensitivePath:results[1].status,rateSampleStatuses:results.slice(2).map(x=>x.status),detectionsObserved:detected,firewallChanges:0},null,2));
}finally{db.close();}

async function probe(label,url){const response=await fetch(url,{signal:AbortSignal.timeout(5000)});await response.arrayBuffer();console.log(`${label}: HTTP ${response.status}`);return {label,status:response.status};}
function readArgs(values){const result={};for(let i=0;i<values.length;i++){if(!values[i].startsWith("--"))throw new Error(`Unexpected argument ${values[i]}`);result[values[i].slice(2)]=values[++i];}return result;}
