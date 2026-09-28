import path from "node:path";
import { loadConfig } from "../src/config.js";
import { restoreBackup } from "../src/storage.js";

const config=loadConfig(),sourceIndex=process.argv.indexOf("--source"),confirm=process.argv.includes("--confirm");
if(sourceIndex<0||!process.argv[sourceIndex+1])throw new Error("Usage: npm run db:restore -- --source <backup-file> --confirm");
if(!confirm)throw new Error("Restore is destructive to the active database. Stop the service, verify the backup, then add --confirm.");
console.log(JSON.stringify({ok:true,...restoreBackup(path.resolve(process.argv[sourceIndex+1]),config.dbPath,{confirm})}));
