import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createServer } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";

test("analysis endpoints require authentication, validate settings, and audit analyst feedback", async () => {
  const dbPath = path.join(os.tmpdir(), `sentrygate-analysis-api-${randomUUID()}.db`);
  const config = loadConfig({ dbPath, sessionSecret: "test-secret-for-sentrygate-suite-32", port: 0, webRoot: path.resolve("apps/web") });
  const db = openDatabase(dbPath), server = createServer(db, config);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (url, options = {}) => {
    const response = await fetch(`${base}${url}`, { headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }, ...options });
    return { response, body: await response.json().catch(() => null), cookie: response.headers.get("set-cookie")?.split(";")[0] };
  };
  try {
    assert.equal((await call("/api/analysis/settings")).response.status, 401);
    const setup = await call("/api/setup", { method: "POST", body: JSON.stringify({ email: "offline@example.com", password: "offline analysis password" }) });
    const headers = { Cookie: setup.cookie };
    const initial = await call("/api/analysis/settings", { headers });
    assert.equal(initial.body.settings.enabled, true);
    assert.equal((await call("/api/analysis/settings", { method: "PUT", headers, body: JSON.stringify({ enabled: true }) })).response.status, 400);
    const configBody = { ...initial.body.settings, enabled: true };
    delete configBody.feedback;
    assert.equal((await call("/api/analysis/settings", { method: "PUT", headers, body: JSON.stringify(configBody) })).response.status, 200);
    assert.equal((await call("/api/health")).response.status, 200, "API health stays available while the optional worker is not running");
    const findingId = randomUUID(), now = new Date().toISOString();
    db.prepare(`INSERT INTO local_analysis_findings(id,finding_key,category,title,reason,severity,confidence,window_start,window_end,baseline_json,evidence_json,created_at)
      VALUES(?,?,'sensitive_path','Test lead','Three matching observations','medium',70,?,?,?, ?,?)`)
      .run(findingId, `api:${findingId}`, now, now, JSON.stringify({ threshold: 3 }), JSON.stringify([{ eventId: 12 }]), now);
    assert.equal((await call("/api/analysis/findings", { headers })).body.length, 1);
    const reviewed = await call(`/api/analysis/findings/${findingId}/feedback`, { method: "POST", headers, body: JSON.stringify({ feedback: "false_positive" }) });
    assert.equal(reviewed.response.status, 200);
    assert.equal(reviewed.body.tuning.falsePositive, 1);
    assert.equal(db.prepare("SELECT action FROM audit_log WHERE target=?").get(`analysis-finding:${findingId}`).action, "analysis.feedback_recorded");
  } finally {
    await new Promise((resolve) => server.close(resolve)); db.close();
    for (const suffix of ["", "-wal", "-shm"]) try { os.rmSync(dbPath + suffix); } catch {}
  }
});
