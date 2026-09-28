import { loadConfig } from "../src/config.js";
import { openDatabase } from "../src/db.js";
import { recordAudit } from "../src/audit.js";

const mode = process.argv[2];
if (! ["enable", "disable", "status"].includes(mode)) {
  console.error("Usage: node apps/api/scripts/analysis-toggle.js <enable|disable|status>");
  process.exitCode = 2;
} else {
  const config = loadConfig();
  const db = openDatabase(config.dbPath);
  try {
    if (mode !== "status") {
      db.prepare("UPDATE local_analysis_settings SET enabled=?,updated_at=? WHERE id=1").run(mode === "enable" ? 1 : 0, new Date().toISOString());
      recordAudit(db, "local-console", `analysis.${mode}d`, "offline-analysis", `Offline analysis ${mode}d through the local command-line control; worker process state is unchanged.`);
      console.log(`Offline analysis ${mode}d. This does not start or stop the separate worker process.`);
    }
    const row = db.prepare("SELECT enabled,batch_size AS batchSize,poll_interval_ms AS pollIntervalMs,finding_retained_days AS findingRetainedDays FROM local_analysis_settings WHERE id=1").get();
    console.log(JSON.stringify({ ...row, enabled: Boolean(row.enabled) }, null, 2));
  } finally { db.close(); }
}
