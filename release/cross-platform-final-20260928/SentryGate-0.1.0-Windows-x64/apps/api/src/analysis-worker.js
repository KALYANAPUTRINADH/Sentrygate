import { openDatabase } from "./db.js";
import { logOperational } from "./logger.js";
import { analyzeNextBatch, pruneAnalysisFindings, readAnalysisSettings } from "./offline-analysis.js";

export async function runAnalysisWorker({ dbPath, signal = { aborted: false }, onCycle = () => {}, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }) {
  const db = openDatabase(dbPath);
  let lastPrune = 0;
  logOperational("info", "analysis.worker_started", { processId: process.pid });
  try {
    while (!signal.aborted) {
      try {
        const settings = readAnalysisSettings(db);
        if (settings.enabled) {
          const result = analyzeNextBatch(db);
          onCycle(result);
          if (Date.now() - lastPrune > 60_000) {
            const removed = pruneAnalysisFindings(db);
            if (removed) logOperational("info", "analysis.retention_completed", { removedFindings: removed });
            lastPrune = Date.now();
          }
        }
        await sleep(settings.pollIntervalMs);
      } catch (error) {
        db.prepare("UPDATE local_analysis_state SET last_run_at=?,last_error=? WHERE id=1").run(new Date().toISOString(), String(error.message).slice(0, 500));
        logOperational("error", "analysis.cycle_failed", { code: error.code ?? error.name ?? "Error" });
        await sleep(1000);
      }
    }
  } finally {
    db.close();
    logOperational("info", "analysis.worker_stopped", {});
  }
}
