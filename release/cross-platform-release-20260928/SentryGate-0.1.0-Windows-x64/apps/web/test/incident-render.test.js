import assert from "node:assert/strict";
import test from "node:test";
import { renderIncidentEvidence } from "../assets/incident-render.js";

test("incident evidence escapes malicious request paths and user agents in dashboard markup", () => {
  const html = renderIncidentEvidence({
    timestamp: "2026-09-27T10:00:00.000Z", source: "website-gateway", detectionRule: "sensitive_path", severity: "high",
    reason: "Observed request", evidence: "Gateway event evidence", action: "blocked", assetName: "Docs", deviceName: "—",
    path: `</dd><img src=x onerror="alert(1)">`, userAgent: `<svg onload='alert(2)'>`
  });
  assert.ok(!html.includes("<img src=x"));
  assert.ok(!html.includes("<svg onload="));
  assert.ok(html.includes("&lt;/dd&gt;&lt;img"));
  assert.ok(html.includes("&lt;svg onload=&#039;alert(2)&#039;&gt;"));
});
