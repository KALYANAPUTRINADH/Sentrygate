import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export function createBackup(sourcePath, outputPath) {
  const source=path.resolve(sourcePath),output=path.resolve(outputPath);
  if(source===output)throw new Error("Backup output must differ from the live database");
  if(fs.existsSync(output))throw new Error("Backup output already exists; choose a new filename");
  fs.mkdirSync(path.dirname(output),{recursive:true});
  const db=new DatabaseSync(source);
  try{db.exec("PRAGMA busy_timeout=5000");db.prepare(`VACUUM INTO '${output.replaceAll("'","''")}'`).run();}
  finally{db.close();}
  assertIntegrity(output);
  return {path:output,bytes:fs.statSync(output).size};
}

export function restoreBackup(sourcePath,targetPath,{confirm=false}={}) {
  if(!confirm)throw new Error("Restore requires explicit confirmation; stop SentryGate first");
  const source=path.resolve(sourcePath),target=path.resolve(targetPath),stage=`${target}.restore-staging`;
  if(source===target)throw new Error("Restore source and target must differ");
  if(!fs.existsSync(source))throw new Error("Backup source does not exist");
  if(fs.existsSync(stage))throw new Error("Restore staging file already exists; inspect it before retrying");
  if(fs.existsSync(`${target}-wal`)||fs.existsSync(`${target}-shm`))throw new Error("Database sidecar files exist; ensure SentryGate is stopped and checkpoint or preserve them first");
  assertIntegrity(source);
  fs.mkdirSync(path.dirname(target),{recursive:true});
  fs.copyFileSync(source,stage);
  assertIntegrity(stage);
  const previous=fs.existsSync(target)?`${target}.pre-restore-${new Date().toISOString().replaceAll(":","-")}`:null;
  if(previous)fs.renameSync(target,previous);
  try{fs.renameSync(stage,target);}catch(error){if(previous)fs.renameSync(previous,target);throw error;}
  return {path:target,previousBackup:previous};
}

function assertIntegrity(filePath) {
  const db=new DatabaseSync(filePath);
  try{const result=db.prepare("PRAGMA integrity_check").get();if(result.integrity_check!=="ok")throw new Error(`SQLite integrity check failed: ${result.integrity_check}`);}
  finally{db.close();}
}
