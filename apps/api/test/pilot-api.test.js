import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createServer } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";

test("pilot metrics and report require administrator access; false-positive review is validated and audited",async()=>{
  const config=loadConfig({dbPath:path.join(os.tmpdir(),`sentrygate-pilot-api-${randomUUID()}.db`),sessionSecret:"test-secret-for-sentrygate-suite-32",port:0,webRoot:path.resolve("apps/web")});
  const db=openDatabase(config.dbPath),server=createServer(db,config);
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  const base=`http://127.0.0.1:${server.address().port}`;
  const call=async(url,options={})=>{const response=await fetch(`${base}${url}`,{headers:{"Content-Type":"application/json",...(options.headers??{})},...options});return {response,body:await response.json().catch(()=>null),cookie:response.headers.get("set-cookie")?.split(";")[0]};};
  try{
    assert.equal((await call("/api/pilot/metrics")).response.status,401);
    const setup=await call("/api/setup",{method:"POST",body:JSON.stringify({email:"pilot@example.com",password:"long enough pilot password"})}),headers={Cookie:setup.cookie};
    const asset=Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,description,created_at) VALUES('Pilot','website','pilot@example.com','healthy','local.test','',?)").run(new Date().toISOString()).lastInsertRowid);
    const now=new Date().toISOString();
    const event=Number(db.prepare(`INSERT INTO events(asset_id,source,category,action,reason,evidence,severity,detection_rule,source_event_id,created_at)
      VALUES(?,'website-gateway','http-request','observed','Sensitive path','GET /.env','medium','sensitive_path',?,?)`).run(asset,randomUUID(),now).lastInsertRowid);
    db.prepare("INSERT INTO gateway_request_metrics(asset_id,event_id,observed_at,duration_ms,upstream_error) VALUES(?,?,?,8.5,0)").run(asset,event,now);
    const metrics=await call("/api/pilot/metrics?days=7",{headers});
    assert.equal(metrics.response.status,200);
    assert.equal(metrics.body.metrics.requests,1);
    assert.equal(metrics.body.metrics.gatewayLatencyMs.p50,8.5);
    assert.equal((await call(`/api/events/${event}/false-positive`,{method:"POST",headers,body:JSON.stringify({falsePositive:"yes"})})).response.status,400);
    const reviewed=await call(`/api/events/${event}/false-positive`,{method:"POST",headers,body:JSON.stringify({falsePositive:true})});
    assert.equal(reviewed.response.status,200);
    assert.equal(db.prepare("SELECT false_positive FROM events WHERE id=?").get(event).false_positive,1);
    assert.equal(db.prepare("SELECT action FROM audit_log WHERE target=?").get(`event:${event}`).action,"pilot.false_positive_marked");
    const report=await call(`/api/pilot/report?assetId=${asset}&days=7`,{headers});
    assert.equal(report.response.status,200);
    assert.equal(report.body.falsePositiveReviews.length,1);
    assert.match(report.response.headers.get("content-disposition"),/sentrygate-pilot-/);
    assert.equal((await call("/api/pilot/metrics?days=100",{headers})).response.status,400);
  }finally{
    await new Promise(resolve=>server.close(resolve));db.close();
    for(const suffix of ["","-wal","-shm"])try{await import("node:fs").then(fs=>fs.unlinkSync(config.dbPath+suffix));}catch{}
  }
});
