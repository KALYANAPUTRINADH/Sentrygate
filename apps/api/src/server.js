import { createServer } from "./app.js";
import { loadConfig } from "./config.js";
import { openDatabase } from "./db.js";
import { createGatewayServer } from "./gateway.js";
import { ensureAgentCredential } from "./agent-credentials.js";
import { expireFirewallRules } from "./firewall.js";
import { expireGatewayActions } from "./actions.js";

const config = loadConfig();
const db = openDatabase(config.dbPath);
ensureAgentCredential(db, config.sessionSecret);
const server = createServer(db, config);
const gateway = createGatewayServer(db, config);
const expirySweep = setInterval(() => {
  try { expireFirewallRules(db); expireGatewayActions(db); }
  catch (error) { console.error("SentryGate expiry sweep failed:", error.message); }
}, 15_000);
expirySweep.unref();

server.listen(config.port, config.host, () => {
  console.log(`SentryGate dashboard/API at http://${config.host}:${config.port}`);
});
gateway.listen(config.gatewayPort, config.gatewayHost, () => {
  console.log(`SentryGate website gateway at http://${config.gatewayHost}:${config.gatewayPort}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => {
  clearInterval(expirySweep);
  server.close(() => {
    gateway.close(() => {
    db.close();
    process.exit(0);
    });
  });
});
