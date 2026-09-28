import { loadConfig } from "../src/config.js";
import { runAnalysisWorker } from "../src/analysis-worker.js";

const config = loadConfig();
const controller = new AbortController();
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => controller.abort());
await runAnalysisWorker({ dbPath: config.dbPath, signal: controller.signal });
