import assert from "node:assert/strict";
import crypto from "node:crypto";
import { openDatabase } from "../src/db.js";
import { correlateEvent } from "../src/incidents.js";
import { evaluateIncidentPolicies } from "../src/actions.js";

const db = openDatabase(":memory:");
try {
  const now = Date.now(), stamp = new Date(now).toISOString();
  const assetId = Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,created_at) VALUES('Synthetic policy website','website','demo','healthy','demo.invalid',?)").run(stamp).lastInsertRowid);
  let incidentId = "";
  for (let index = 0; index < 3; index++) {
    const timestamp = new Date(now - 5_000 + index * 1000).toISOString();
    const id = Number(db.prepare(`INSERT INTO events(asset_id,source,category,action,reason,evidence,observed_source_ip,severity,detection_rule,created_at)
      VALUES(?,'demo','website','observed','Synthetic sensitive-path evidence','Demo only; no request sent','198.51.100.44','high','sensitive_path',?)`).run(assetId, timestamp).lastInsertRowid);
    incidentId = correlateEvent(db, id) ?? incidentId;
  }
  if (!incidentId) throw new Error(`Synthetic incident was not correlated; stored events=${db.prepare("SELECT COUNT(*) AS count FROM events").get().count}`);
  const addPolicy = (mode) => db.prepare(`INSERT INTO action_policies(id,name,enabled,mode,asset_id,detection_rule,minimum_severity,minimum_event_count,window_minutes,target_type,target_id,protocol,local_port,duration_minutes,created_by,created_at,updated_at)
    VALUES(?,?,1,?,?,'sensitive_path','high',3,10,'website',?,'TCP',443,5,'demo',?,?)`).run(crypto.randomUUID(), `Local ${mode} demo`, mode, assetId, String(assetId), stamp, stamp);
  addPolicy("observe");
  assert.deepEqual(evaluateIncidentPolicies(db, incidentId, now), []);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM proposed_actions").get().count, 0);
  console.log("OBSERVE: 3 synthetic matching events recorded; no response action proposed.");
  addPolicy("recommend");
  const actions = evaluateIncidentPolicies(db, incidentId, now);
  assert.equal(actions.length, 1);
  assert.equal(db.prepare("SELECT status FROM proposed_actions WHERE id=?").get(actions[0]).status, "proposed");
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM firewall_rules").get().count, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM gateway_ip_blocks").get().count, 0);
  console.log(`RECOMMEND: action ${actions[0]} is proposed for administrator review; no firewall or gateway block applied.`);
  console.log("ENFORCE: disabled in this demonstration and remains disabled by default in every install/upgrade.");
} finally { db.close(); }
