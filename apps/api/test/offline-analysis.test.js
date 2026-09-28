import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { openDatabase } from "../src/db.js";
import { analyzeNextBatch, applyAnalysisFeedback } from "../src/offline-analysis.js";

function fixture() {
  const dbPath = path.join(os.tmpdir(), `sentrygate-analysis-${randomUUID()}.db`);
  const db = openDatabase(dbPath);
  const asset = Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,created_at) VALUES('Local test','website','test','healthy','http://local.test',?)").run(new Date().toISOString()).lastInsertRowid);
  db.prepare("UPDATE local_analysis_settings SET enabled=1,request_rate_threshold=30,sensitive_threshold=3,connection_threshold=50 WHERE id=1").run();
  return { db, dbPath, asset };
}
function event(db, asset, { source="website-gateway", category="http-request", rule="none", ip="192.0.2.8", at, evidence="{}", deviceId=null, path: requestPath="/", reason="request observed" } = {}) {
  return db.prepare(`INSERT INTO events(asset_id,source,category,action,reason,evidence,observed_source_ip,request_path,detection_rule,severity,device_id,created_at)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(asset, source, category, "observed", reason, evidence, ip, requestPath, rule, "medium", deviceId, at).lastInsertRowid;
}
function cleanup({ db, dbPath }) { db.close(); for (const suffix of ["", "-wal", "-shm"]) try { os.rmSync(dbPath + suffix); } catch {} }

test("normal traffic is not a finding and analysis disabled leaves cursor unchanged", () => {
  const f = fixture();
  try {
    const now = Date.now();
    for (let i = 0; i < 12; i++) event(f.db, f.asset, { at: new Date(now - i * 500).toISOString() });
    f.db.prepare("UPDATE local_analysis_settings SET enabled=0 WHERE id=1").run();
    assert.equal(analyzeNextBatch(f.db).processed, 0);
    assert.equal(f.db.prepare("SELECT cursor_event_id FROM local_analysis_state WHERE id=1").get().cursor_event_id, 0);
    f.db.prepare("UPDATE local_analysis_settings SET enabled=1 WHERE id=1").run();
    assert.equal(analyzeNextBatch(f.db).findings, 0);
    assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM local_analysis_findings").get().n, 0);
  } finally { cleanup(f); }
});

test("detects repeated sensitive paths and above-baseline request burst once across restart", () => {
  const f = fixture();
  try {
    const now = Date.now();
    for (const hours of [3, 2, 1]) for (let n = 0; n < 2; n++) event(f.db, f.asset, { at: new Date(now - hours * 3_600_000 + n * 1000).toISOString() });
    for (let n = 0; n < 35; n++) event(f.db, f.asset, { at: new Date(now + n).toISOString(), path: "/login" });
    const sensitiveTime = new Date(now + 100).toISOString();
    for (let n = 0; n < 3; n++) event(f.db, f.asset, { at: sensitiveTime, rule: "sensitive_path", path: "/.env" });
    const first = analyzeNextBatch(f.db, { batchSize: 12 });
    assert.equal(first.processed, 12);
    while (analyzeNextBatch(f.db, { batchSize: 12 }).processed) {}
    const count = f.db.prepare("SELECT COUNT(*) AS n FROM local_analysis_findings").get().n;
    assert.ok(count >= 2);
    assert.ok(f.db.prepare("SELECT 1 FROM local_analysis_findings WHERE category='sensitive_path'").get());
    assert.ok(f.db.prepare("SELECT 1 FROM local_analysis_findings WHERE category='request_rate'").get());
    assert.ok(JSON.parse(f.db.prepare("SELECT evidence_json FROM local_analysis_findings WHERE category='sensitive_path'").get().evidence_json).length >= 3);
    assert.equal(analyzeNextBatch(f.db).findings, 0);
    assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM local_analysis_findings").get().n, count);
  } finally { cleanup(f); }
});

test("detects unusual connection metadata and resumes after reopening database", () => {
  const f = fixture();
  try {
    const deviceId = randomUUID(), now = Date.now();
    f.db.prepare("INSERT INTO device_agents(device_id,name,hostname,os_version,agent_version,credential_hash,enrolled_at) VALUES(?,?,?,?,?,?,?)").run(deviceId, "test", "local", "Windows", "test", "not-a-secret", new Date().toISOString());
    for (const hours of [5, 4, 3]) event(f.db, f.asset, { source: "windows-agent", category: "outbound_connection_volume", rule: "outbound_connection_volume", deviceId, at: new Date(now - hours * 3_600_000).toISOString(), evidence: JSON.stringify({ processName: "sample.exe", observedCount: 10 }) });
    event(f.db, f.asset, { source: "windows-agent", category: "outbound_connection_volume", rule: "outbound_connection_volume", deviceId, at: new Date(now).toISOString(), evidence: JSON.stringify({ processName: "sample.exe", observedCount: 75, threshold: 40, remoteAddresses: ["203.0.113.10"] }) });
    f.db.prepare("UPDATE local_analysis_settings SET batch_size=2 WHERE id=1").run();
    assert.equal(analyzeNextBatch(f.db).processed, 2);
    f.db.close();
    const reopened = openDatabase(f.dbPath);
    assert.equal(analyzeNextBatch(reopened).processed, 2);
    assert.equal(reopened.prepare("SELECT COUNT(*) AS n FROM local_analysis_findings WHERE category='connection_pattern'").get().n, 1);
    reopened.close();
    f.db = { close() {} };
  } finally { cleanup(f); }
});

test("feedback tunes effective threshold only after enough reviewed findings", () => {
  const f = fixture();
  try {
    const insert = f.db.prepare(`INSERT INTO local_analysis_findings(id,finding_key,category,title,reason,severity,confidence,window_start,window_end,baseline_json,evidence_json,created_at)
      VALUES(?,?,'request_rate','Test','Evidence','medium',60,?,?, '{}','[]',?)`);
    for (let i = 0; i < 3; i++) insert.run(randomUUID(), `f${i}`, new Date().toISOString(), new Date().toISOString(), new Date().toISOString());
    for (const id of f.db.prepare("SELECT id FROM local_analysis_findings").all()) f.db.prepare("UPDATE local_analysis_findings SET feedback='false_positive' WHERE id=?").run(id.id);
    assert.equal(applyAnalysisFeedback(f.db, "request_rate").multiplier, 1.25);
  } finally { cleanup(f); }
});
