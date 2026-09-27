import { createServer } from "./app.js";
import { loadConfig } from "./config.js";
import { openDatabase } from "./db.js";
import { createGatewayServer } from "./gateway.js";
import { ensureAgentCredential } from "./agent-credentials.js";
import { expireFirewallRules } from "./firewall.js";
import { expireGatewayActions } from "./actions.js";
import { logOperational } from "./logger.js";
import { sweepOperationalState } from "./operations.js";

const config = loadConfig();
const db = openDatabase(config.dbPath);
ensureAgentCredential(db, config.sessionSecret);
const server = createServer(db, config);
const gateway = createGatewayServer(db, config);
const expirySweep = setInterval(() => {
  try { expireFirewallRules(db); expireGatewayActions(db); sweepOperationalState(db,config); }
  catch (error) { logOperational("error","expiry_sweep.failed",{code:error.code??error.name??"Error"}); }
}, 15_000);
expirySweep.unref();
try { sweepOperationalState(db,config); } catch(error) { logOperational("error","operations.initial_sweep_failed",{code:error.code??error.name??"Error"}); }

server.listen(config.port, config.host, () => {
  logOperational("info","api.listening",{host:config.host,port:config.port,transport:config.tlsCertPath?"https":"http"});
});
gateway.listen(config.gatewayPort, config.gatewayHost, () => {
  logOperational("info","gateway.listening",{host:config.gatewayHost,port:config.gatewayPort,transport:config.tlsCertPath?"https":"http"});
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
