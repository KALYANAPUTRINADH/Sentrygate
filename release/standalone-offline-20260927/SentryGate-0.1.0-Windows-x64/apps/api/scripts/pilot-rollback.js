import path from "node:path";
import { openDatabase } from "../src/db.js";
import { loadConfig } from "../src/config.js";
import { rollbackWebsitePilot } from "../src/pilot.js";

const args=readArgs(process.argv.slice(2));
if(args.confirm!=="true")throw new Error("Rollback changes routing settings. Pass --confirm true after reviewing the previous upstream.");
const db=openDatabase(path.resolve(args.db??loadConfig().dbPath));
try{
  const result=rollbackWebsitePilot(db,{assetId:Number(args["asset-id"]),previousUpstream:args["previous-upstream"],deviceId:args["device-id"]??null});
  console.log(JSON.stringify({...result,nextSteps:["In the SentryGate server terminal, press Ctrl+C (API and gateway share the process).","If device rules were queued, keep the Windows agent online until it reports removal; verify actual state in Firewall and review the audit log.","Restore any external DNS, load balancer, or reverse-proxy routing manually to the recorded prior target. This command never edits DNS or unrelated firewall rules."]},null,2));
}finally{db.close();}

function readArgs(values){const result={};for(let i=0;i<values.length;i++){if(!values[i].startsWith("--"))throw new Error(`Unexpected argument ${values[i]}`);result[values[i].slice(2)]=values[++i];}return result;}
