import fs from "node:fs";
import path from "node:path";

const required = [
  "apps/web/index.html",
  "apps/web/assets/app.js",
  "apps/web/assets/styles.css",
  "docs/threat-model.md",
  "docs/deployment.md",
  "docs/milestone-2.md",
  "apps/api/src/gateway.js",
  "apps/api/src/agent-credentials.js"
];

for (const file of required) {
  const fullPath = path.resolve(file);
  if (!fs.existsSync(fullPath)) {
    console.error(`Missing required asset: ${file}`);
    process.exit(1);
  }
}

console.log("SentryGate static assets verified.");
