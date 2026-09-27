import path from "node:path";
import { loadConfig } from "../src/config.js";
import { createBackup } from "../src/storage.js";

const config=loadConfig();
const outIndex=process.argv.indexOf("--out");
if(outIndex<0||!process.argv[outIndex+1])throw new Error("Usage: npm run db:backup -- --out <backup-file>");
const result=createBackup(config.dbPath,path.resolve(process.argv[outIndex+1]));
console.log(JSON.stringify({ok:true,...result}));
