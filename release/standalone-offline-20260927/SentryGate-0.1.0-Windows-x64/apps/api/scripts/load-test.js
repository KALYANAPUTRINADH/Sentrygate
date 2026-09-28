import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createServer } from "../src/app.js";
import { openDatabase } from "../src/db.js";
import { createGatewayServer } from "../src/gateway.js";

const root=fs.mkdtempSync(path.join(os.tmpdir(),"sentrygate-load-")),dbPath=path.join(root,"load.db");
const db=openDatabase(dbPath),secret=`load-test-${randomUUID()}-do-not-use-in-production`;
const config={dbPath,maxDbBytes:512*1024*1024,sessionSecret:secret,cookieSecure:false,apiBaseUrl:"",port:0,gatewayPort:0,host:"127.0.0.1",gatewayHost:"127.0.0.1",webRoot:path.resolve("apps/web"),eventIngestTimeoutMs:2000};
let api,gateway,upstream;
function listen(server){return new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",()=>resolve(server.address().port));});}
function close(server){return server?new Promise(resolve=>server.close(()=>resolve())):Promise.resolve();}
function percentile(samples,p){return samples.toSorted((a,b)=>a-b)[Math.min(samples.length-1,Math.ceil(samples.length*p)-1)]??0;}
async function runBatch(baseUrl,count,concurrency){
  const samples=[],errors=[];let next=0;
  const workers=Array.from({length:concurrency},async()=>{while(next<count){const index=next++,start=performance.now();try{const response=await fetch(`${baseUrl}/site/${assetId}/health?i=${index}`);await response.arrayBuffer();if(response.status!==200)errors.push(response.status);}catch(error){errors.push(error.code??error.name);}samples.push(performance.now()-start);}});
  const start=performance.now();await Promise.all(workers);const elapsed=performance.now()-start;
  return {requests:count,concurrency,elapsedMs:+elapsed.toFixed(1),throughputPerSecond:+(count/(elapsed/1000)).toFixed(1),latencyMs:{p50:+percentile(samples,.5).toFixed(2),p95:+percentile(samples,.95).toFixed(2),p99:+percentile(samples,.99).toFixed(2)},errors:errors.length};
}
let assetId;
try{
  upstream=http.createServer((req,res)=>{req.resume();res.writeHead(200,{"Content-Length":"2"});res.end("ok");});
  const upstreamPort=await listen(upstream),created=db.prepare("INSERT INTO assets(name,type,owner,status,address,description,upstream_url,created_at) VALUES('Load site','website','load-test','healthy','localhost','','',?)").run(new Date().toISOString());
  assetId=Number(created.lastInsertRowid);db.prepare("UPDATE assets SET upstream_url=? WHERE id=?").run(`http://127.0.0.1:${upstreamPort}`,assetId);
  db.prepare("INSERT INTO gateway_rules(asset_id,updated_at) VALUES(?,?)").run(assetId,new Date().toISOString());
  api=createServer(db,config);const apiPort=await listen(api);config.apiBaseUrl=`http://127.0.0.1:${apiPort}`;
  gateway=createGatewayServer(db,config);const gatewayPort=await listen(gateway),baseUrl=`http://127.0.0.1:${gatewayPort}`;
  const baseline=db.prepare("SELECT COUNT(*) AS n FROM events WHERE asset_id=?").get(assetId).n;
  const normal=await runBatch(baseUrl,120,12),burst=await runBatch(baseUrl,500,60);
  const expected=normal.requests+burst.requests,stored=db.prepare("SELECT COUNT(*) AS n FROM events WHERE asset_id=?").get(assetId).n-baseline;
  const dashboard=[];for(let i=0;i<30;i++){const before=performance.now();const response=await fetch(`http://127.0.0.1:${apiPort}/api/health`);await response.arrayBuffer();dashboard.push(performance.now()-before);}
  console.log(JSON.stringify({scope:"isolated loopback-only SQLite/API/gateway; synthetic traffic",normal,burst,eventDelivery:{expected,stored,lost:expected-stored},dashboardHealthLatencyMs:{p50:+percentile(dashboard,.5).toFixed(2),p95:+percentile(dashboard,.95).toFixed(2),p99:+percentile(dashboard,.99).toFixed(2)},dbBytes:fs.statSync(dbPath).size},null,2));
  if(normal.errors||burst.errors||stored!==expected)process.exitCode=1;
}finally{await Promise.all([close(gateway),close(api),close(upstream)]);db.close();fs.rmSync(root,{recursive:true,force:true});}
