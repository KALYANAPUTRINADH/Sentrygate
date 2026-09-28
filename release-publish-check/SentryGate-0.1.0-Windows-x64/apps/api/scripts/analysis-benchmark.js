import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { openDatabase } from "../src/db.js";
import { databaseBytes } from "../src/operations.js";
import { analyzeNextBatch } from "../src/offline-analysis.js";

const requested = Number(process.argv[2] ?? 5000);
if (!Number.isInteger(requested) || requested < 100 || requested > 100_000) throw new Error("Sample size must be 100 to 100000 events");
const dbPath = path.join(os.tmpdir(), `sentrygate-analysis-benchmark-${process.pid}.db`);
const db = openDatabase(dbPath);
const now = Date.now();
const assetId = Number(db.prepare("INSERT INTO assets(name,type,owner,status,address,created_at) VALUES('Benchmark site','website','local benchmark','healthy','http://127.0.0.1',?)").run(new Date(now).toISOString()).lastInsertRowid);
db.prepare("UPDATE local_analysis_settings SET enabled=1,batch_size=100,request_rate_threshold=30 WHERE id=1").run();
const insert = db.prepare(`INSERT INTO events(asset_id,source,category,action,reason,evidence,observed_source_ip,method,request_path,detection_rule,severity,created_at)
  VALUES(?,'website-gateway','http-request','observed','synthetic benchmark event','{}',?,'GET','/benchmark',?, 'info',?)`);
db.exec("BEGIN");
try {
  for (let i = 0; i < requested - 46; i++) {
    const timestamp = new Date(now - (requested - i) * 25_000).toISOString();
    insert.run(assetId, `192.0.2.${1 + (i % 240)}`, "none", timestamp);
  }
  const endpoint = "198.51.100.20";
  for (const hoursAgo of [4, 3, 2]) insert.run(assetId, endpoint, "none", new Date(now - hoursAgo * 3_600_000).toISOString());
  for (let i = 0; i < 40; i++) insert.run(assetId, endpoint, "none", new Date(now + i).toISOString());
  for (let i = 0; i < 3; i++) insert.run(assetId, endpoint, "sensitive_path", new Date(now + 50 + i).toISOString());
  db.exec("COMMIT");
} catch (error) { db.exec("ROLLBACK"); throw error; }

const initialBytes = databaseBytes(dbPath);
const initialRss = process.memoryUsage().rss;
const cpuStart = process.cpuUsage();
let peakRss = initialRss, processed = 0, detected = 0;
const batchLatencies = [];
const totalStart = performance.now();
while (true) {
  const started = performance.now();
  const result = analyzeNextBatch(db, { batchSize: 100 });
  batchLatencies.push(performance.now() - started);
  peakRss = Math.max(peakRss, process.memoryUsage().rss);
  processed += result.processed;
  detected += result.findings;
  if (!result.processed) break;
}
const elapsedMs = performance.now() - totalStart;
const cpu = process.cpuUsage(cpuStart);
const sorted = batchLatencies.slice(0, -1).sort((a, b) => a - b);
const p95 = sorted.length ? sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)] : 0;
const findings = db.prepare("SELECT category,title,confidence FROM local_analysis_findings ORDER BY created_at").all();
const report = {
  sample: "synthetic local website events with baseline windows, one request burst, and repeated sensitive-path probes",
  requestedEvents: requested, processedEvents: processed, findings: findings.length, categories: findings.map((finding) => finding.category),
  elapsedMs: Number(elapsedMs.toFixed(2)), eventsPerSecond: Number((processed / (elapsedMs / 1000)).toFixed(1)),
  averageDetectionLatencyMsPerEvent: Number((elapsedMs / Math.max(processed, 1)).toFixed(4)), batchLatencyP95Ms: Number(p95.toFixed(3)),
  cpuMs: Number(((cpu.user + cpu.system) / 1000).toFixed(2)), rssStartBytes: initialRss, rssPeakBytes: peakRss,
  rssIncreaseBytes: Math.max(0, peakRss - initialRss), databaseBytesBefore: initialBytes, databaseBytesAfter: databaseBytes(dbPath),
  limitations: ["Single local Windows/Node run; not a capacity guarantee", "Synthetic event mix; no gateway or agent traffic generated", "CPU and RSS include process runtime overhead"]
};
console.log(JSON.stringify(report, null, 2));
db.close();
for (const suffix of ["", "-wal", "-shm"]) try { fs.unlinkSync(dbPath + suffix); } catch {}
