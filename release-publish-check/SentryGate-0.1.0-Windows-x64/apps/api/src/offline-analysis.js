import crypto from "node:crypto";

const SEVERITY = { info: "low", low: "low", medium: "medium", high: "high", critical: "high" };

export const DEFAULT_ANALYSIS_SETTINGS = Object.freeze({
  enabled: true, batchSize: 100, pollIntervalMs: 1000, findingRetainedDays: 90,
  sensitiveThreshold: 3, sensitiveWindowMinutes: 10, requestRateThreshold: 30,
  requestWindowSeconds: 60, baselineDays: 7, rateSigma: 3, connectionThreshold: 50
});

export function readAnalysisSettings(db) {
  const row = db.prepare("SELECT * FROM local_analysis_settings WHERE id=1").get();
  const feedback = Object.fromEntries(db.prepare("SELECT category,threshold_multiplier AS multiplier,useful_count AS usefulCount,false_positive_count AS falsePositiveCount FROM local_analysis_feedback").all().map((item) => [item.category, item]));
  return {
    enabled: Boolean(row.enabled), batchSize: row.batch_size, pollIntervalMs: row.poll_interval_ms,
    findingRetainedDays: row.finding_retained_days, sensitiveThreshold: row.sensitive_threshold,
    sensitiveWindowMinutes: row.sensitive_window_minutes, requestRateThreshold: row.request_rate_threshold,
    requestWindowSeconds: row.request_window_seconds, baselineDays: row.baseline_days,
    rateSigma: row.rate_sigma, connectionThreshold: row.connection_threshold, feedback
  };
}

export function analyzeNextBatch(db, { now = new Date(), batchSize } = {}) {
  const settings = readAnalysisSettings(db);
  if (!settings.enabled) return { enabled: false, processed: 0, findings: 0 };
  const state = db.prepare("SELECT cursor_event_id AS cursor FROM local_analysis_state WHERE id=1").get();
  const limit = Math.max(1, Math.min(500, batchSize ?? settings.batchSize));
  const events = db.prepare(`SELECT id,asset_id AS assetId,device_id AS deviceId,source,category,action,reason,evidence,
    observed_source_ip AS sourceIp,request_path AS path,method,detection_rule AS rule,severity,created_at AS createdAt
    FROM events WHERE id>? ORDER BY id LIMIT ?`).all(state.cursor, limit);
  const stamp = now.toISOString();
  let created = 0;
  db.exec("BEGIN");
  try {
    for (const event of events) {
      if (event.source === "website-gateway") created += analyzeWebsiteEvent(db, event, settings);
      if (event.source === "windows-agent") created += analyzeConnectionEvent(db, event, settings);
    }
    const cursor = events.at(-1)?.id ?? state.cursor;
    db.prepare("UPDATE local_analysis_state SET cursor_event_id=?,last_run_at=?,last_error='',processed_total=processed_total+? WHERE id=1").run(cursor, stamp, events.length);
    db.exec("COMMIT");
    return { enabled: true, processed: events.length, findings: created, cursor };
  } catch (error) {
    db.exec("ROLLBACK");
    db.prepare("UPDATE local_analysis_state SET last_run_at=?,last_error=? WHERE id=1").run(stamp, String(error.message).slice(0, 500));
    throw error;
  }
}

function analyzeWebsiteEvent(db, event, settings) {
  const sourceIp = event.sourceIp.trim();
  if (!sourceIp || !event.assetId) return 0;
  const feedback = settings.feedback;
  const time = Date.parse(event.createdAt);
  if (!Number.isFinite(time)) return 0;
  let findings = 0;

  if (event.rule === "sensitive_path" || event.category === "sensitive-path-probe") {
    const width = settings.sensitiveWindowMinutes * 60_000;
    const start = Math.floor(time / width) * width;
    const end = start + width;
    const events = db.prepare(`SELECT id,created_at AS createdAt,request_path AS path,method,reason,evidence,action,severity
      FROM events WHERE source='website-gateway' AND asset_id=? AND observed_source_ip=? AND detection_rule='sensitive_path'
      AND created_at>=? AND created_at<? ORDER BY created_at,id LIMIT 100`).all(event.assetId, sourceIp, new Date(start).toISOString(), new Date(end).toISOString());
    const threshold = tuned(settings.sensitiveThreshold, feedback.sensitive_path?.multiplier);
    if (events.length >= threshold) {
      findings += insertFinding(db, {
        key: `sensitive:${event.assetId}:${sourceIp}:${start}`, category: "sensitive_path", event,
        title: "Repeated sensitive-path requests", severity: events.length >= threshold * 2 ? "high" : "medium",
        confidence: Math.min(95, 55 + events.length * 5), start, end,
        reason: `${events.length} gateway events matched the sensitive-path rule in a ${settings.sensitiveWindowMinutes}-minute bucket; configured threshold is ${threshold}. This is a lead, not attribution or proof of intent.`,
        baseline: { type: "fixed_rule_threshold", threshold, observedCount: events.length, windowMinutes: settings.sensitiveWindowMinutes },
        evidence: events.map((item) => ({ eventId: item.id, timestamp: item.createdAt, method: item.method, path: item.path, reason: item.reason, action: item.action, severity: item.severity }))
      });
    }
  }

  const windowSeconds = settings.requestWindowSeconds;
  const width = windowSeconds * 1000;
  const start = Math.floor(time / width) * width;
  const end = start + width;
  const bucket = Math.floor(start / width);
  const latestInBucket = db.prepare(`SELECT MAX(id) AS id FROM events WHERE source='website-gateway' AND asset_id=?
    AND observed_source_ip=? AND created_at>=? AND created_at<?`).get(event.assetId, sourceIp, new Date(start).toISOString(), new Date(end).toISOString()).id;
  if (latestInBucket !== event.id) return findings;
  const threshold = tuned(settings.requestRateThreshold, feedback.request_rate?.multiplier);
  const current = db.prepare("SELECT COUNT(*) AS count FROM events WHERE source='website-gateway' AND asset_id=? AND observed_source_ip=? AND created_at>=? AND created_at<?")
    .get(event.assetId, sourceIp, new Date(start).toISOString(), new Date(end).toISOString()).count;
  if (current < threshold) return findings;
  const samples = db.prepare(`SELECT CAST(strftime('%s',created_at) AS INTEGER)/? AS bucket,COUNT(*) AS count
    FROM events WHERE source='website-gateway' AND asset_id=? AND observed_source_ip=? AND created_at>=? AND created_at<?
    GROUP BY bucket ORDER BY bucket LIMIT 2000`).all(width / 1000, event.assetId, sourceIp,
      new Date(start - settings.baselineDays * 86_400_000).toISOString(), new Date(start).toISOString());
  const counts = samples.map((sample) => Number(sample.count));
  const { mean, deviation } = stats(counts);
  const expected = Math.max(threshold, mean + settings.rateSigma * deviation);
  if (current >= threshold && current > expected && samples.length >= 3) {
    const evidence = db.prepare(`SELECT id,created_at AS createdAt,method,request_path AS path,response_status AS status,action,reason
      FROM events WHERE source='website-gateway' AND asset_id=? AND observed_source_ip=? AND created_at>=? AND created_at<? ORDER BY created_at,id LIMIT 100`)
      .all(event.assetId, sourceIp, new Date(start).toISOString(), new Date(end).toISOString());
    findings += insertFinding(db, {
      key: `rate:${event.assetId}:${sourceIp}:${bucket}`, category: "request_rate", event,
      title: "Request rate above local baseline", severity: current >= expected * 2 ? "high" : "medium",
      confidence: Math.min(95, 50 + Math.min(samples.length, 9) * 5), start, end,
      reason: `${current} requests from the gateway-observed endpoint in ${windowSeconds}s exceeded the configured floor ${threshold} and historical baseline (${mean.toFixed(1)} mean, ${deviation.toFixed(1)} standard deviation across ${samples.length} prior buckets).`,
      baseline: { type: "historical_minute_buckets", observedCount: current, threshold, meanPerWindow: round(mean), standardDeviation: round(deviation), sampleWindows: samples.length, windowSeconds, baselineDays: settings.baselineDays },
      evidence: evidence.map((item) => ({ eventId: item.id, timestamp: item.createdAt, method: item.method, path: item.path, responseStatus: item.status, action: item.action, reason: item.reason }))
    });
  }
  return findings;
}

function analyzeConnectionEvent(db, event, settings) {
  if (event.rule !== "outbound_connection_volume" || !event.deviceId) return 0;
  const evidence = parseJson(event.evidence);
  const count = Number(evidence?.observedCount);
  const processName = typeof evidence?.processName === "string" ? evidence.processName.slice(0, 200) : "unknown";
  if (!Number.isFinite(count) || count < 1) return 0;
  const cutoff = new Date(Date.parse(event.createdAt) - settings.baselineDays * 86_400_000).toISOString();
  const prior = db.prepare(`SELECT id,created_at AS createdAt,evidence FROM events WHERE source='windows-agent' AND device_id=?
    AND detection_rule='outbound_connection_volume' AND created_at<? ORDER BY created_at DESC LIMIT 500`).all(event.deviceId, cutoff);
  const counts = prior.flatMap((item) => {
    const payload = parseJson(item.evidence);
    return payload?.processName === processName && Number.isFinite(Number(payload.observedCount)) ? [Number(payload.observedCount)] : [];
  });
  const { mean, deviation } = stats(counts);
  const threshold = tuned(settings.connectionThreshold, settings.feedback.connection_pattern?.multiplier);
  const expected = Math.max(threshold, mean + 3 * deviation);
  if (count < threshold || (counts.length >= 3 && count <= expected)) return 0;
  const at = Date.parse(event.createdAt);
  return insertFinding(db, {
    key: `connection:${event.deviceId}:${processName}:${Math.floor(at / 3_600_000)}`,
    category: "connection_pattern", event, title: "Unusual outbound connection volume",
    severity: count >= threshold * 2 ? "high" : "medium", confidence: Math.min(90, 50 + counts.length * 5),
    start: at - 3_600_000, end: at,
    reason: `Observed event reports ${count} outbound connections for process ${processName}; threshold is ${threshold}${counts.length ? ` and historical mean is ${mean.toFixed(1)} across ${counts.length} samples` : "; no comparable local history is available"}.`,
    baseline: { type: counts.length >= 3 ? "process_event_history" : "configured_threshold_only", observedCount: count, threshold, meanPerEvent: round(mean), standardDeviation: round(deviation), sampleCount: counts.length, baselineDays: settings.baselineDays },
    evidence: [{ eventId: event.id, timestamp: event.createdAt, deviceId: event.deviceId, processName, pid: evidence.pid ?? null, observedCount: count, threshold: evidence.threshold ?? null, remoteAddresses: Array.isArray(evidence.remoteAddresses) ? evidence.remoteAddresses.slice(0, 25) : [] }]
  });
}

function insertFinding(db, item) {
  const id = crypto.randomUUID();
  const result = db.prepare(`INSERT OR IGNORE INTO local_analysis_findings
    (id,finding_key,category,asset_id,device_id,observed_endpoint,title,reason,severity,confidence,window_start,window_end,baseline_json,evidence_json,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, item.key, item.category, item.event.assetId, item.event.deviceId,
    item.event.sourceIp || "", item.title, item.reason, item.severity, item.confidence, new Date(item.start).toISOString(),
    new Date(item.end).toISOString(), JSON.stringify(item.baseline), JSON.stringify(item.evidence), new Date().toISOString());
  return result.changes;
}

function stats(values) {
  if (!values.length) return { mean: 0, deviation: 0 };
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + ((value - mean) ** 2), 0) / values.length;
  return { mean, deviation: Math.sqrt(variance) };
}
function tuned(value, multiplier = 1) { return Math.max(1, Math.round(value * multiplier)); }
function round(value) { return Math.round(value * 100) / 100; }
function parseJson(value) { try { return JSON.parse(value); } catch { return null; } }

export function applyAnalysisFeedback(db, category, now = new Date().toISOString()) {
  const counts = db.prepare("SELECT SUM(feedback='useful') AS useful,SUM(feedback='false_positive') AS falsePositive FROM local_analysis_findings WHERE category=?").get(category);
  const useful = counts.useful ?? 0, falsePositive = counts.falsePositive ?? 0, total = useful + falsePositive;
  const multiplier = total >= 3 && falsePositive / total >= 0.5 ? 1.25 : total >= 3 && useful / total >= 0.7 ? 0.9 : 1;
  db.prepare(`INSERT INTO local_analysis_feedback(category,threshold_multiplier,useful_count,false_positive_count,updated_at)
    VALUES(?,?,?,?,?) ON CONFLICT(category) DO UPDATE SET threshold_multiplier=excluded.threshold_multiplier,
    useful_count=excluded.useful_count,false_positive_count=excluded.false_positive_count,updated_at=excluded.updated_at`)
    .run(category, multiplier, useful, falsePositive, now);
  return { useful, falsePositive, total, multiplier };
}

export function findingForDashboard(row) {
  return { id: row.id, category: row.category, assetId: row.asset_id, deviceId: row.device_id,
    observedEndpoint: row.observed_endpoint, title: row.title, reason: row.reason, severity: row.severity,
    confidence: row.confidence, windowStart: row.window_start, windowEnd: row.window_end,
    baseline: parseJson(row.baseline_json), evidence: parseJson(row.evidence_json), feedback: row.feedback,
    reviewedBy: row.reviewed_by, reviewedAt: row.reviewed_at, createdAt: row.created_at };
}

export function pruneAnalysisFindings(db, now = new Date()) {
  const { finding_retained_days: days } = db.prepare("SELECT finding_retained_days FROM local_analysis_settings WHERE id=1").get();
  return db.prepare("DELETE FROM local_analysis_findings WHERE created_at<?").run(new Date(now.getTime() - days * 86_400_000).toISOString()).changes;
}
