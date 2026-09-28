import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { openDatabase } from "../src/db.js";
import { loadConfig } from "../src/config.js";
import { generatePilotReport, validatePilotOptions } from "../src/pilot.js";

const args=readArgs(process.argv.slice(2));
const options=validatePilotOptions({...(args["asset-id"]?{assetId:Number(args["asset-id"])}:{}),days:Number(args.days??7)});
const dbPath=path.resolve(args.db??loadConfig().dbPath),db=openDatabase(dbPath);
try{
  const report=generatePilotReport(db,options),output=path.resolve(args.out??"sentrygate-pilot-report.json");
  fs.writeFileSync(output,JSON.stringify(report,null,2),{encoding:"utf8",flag:"w"});
  console.log(JSON.stringify({report:output,recommendation:report.recommendation,requests:report.measurements.requests,alerts:report.measurements.alerts,falsePositives:report.measurements.falsePositives,upstreamErrors:report.measurements.upstreamErrors}));
}finally{db.close();}

function readArgs(values){const result={};for(let i=0;i<values.length;i++){if(!values[i].startsWith("--"))throw new Error(`Unexpected argument ${values[i]}`);result[values[i].slice(2)]=values[++i];}return result;}
