import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { createBackup, restoreBackup } from "../src/storage.js";

test("SQLite backup is consistent and restore requires confirmation while preserving the previous database",()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"sentrygate-backup-"));
  try{
    const live=path.join(dir,"live.db"),backup=path.join(dir,"backup.db"),target=path.join(dir,"restore.db");
    let db=new DatabaseSync(live);db.exec("CREATE TABLE evidence(value TEXT); INSERT INTO evidence VALUES ('snapshot')");db.close();
    assert.throws(()=>restoreBackup(backup,target),/confirmation/);
    assert.equal(createBackup(live,backup).bytes>0,true);
    db=new DatabaseSync(target);db.exec("CREATE TABLE evidence(value TEXT); INSERT INTO evidence VALUES ('current')");db.close();
    const restored=restoreBackup(backup,target,{confirm:true});
    db=new DatabaseSync(target);assert.equal(db.prepare("SELECT value FROM evidence").get().value,"snapshot");db.close();
    assert.ok(fs.existsSync(restored.previousBackup));
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
