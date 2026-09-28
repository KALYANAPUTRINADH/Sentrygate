import { loadConfig } from "../src/config.js";
import { openDatabase, seedDemoData } from "../src/db.js";

const config = loadConfig();
const db = openDatabase(config.dbPath);
try {
  seedDemoData(db);
  console.log("Demo data is ready. Start the dashboard with: npm run dev");
} finally {
  db.close();
}
