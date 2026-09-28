import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export class EventSpool {
  constructor(dbPath, { protect = (value) => value, unprotect = (value) => value, maxBytes = 268_435_456, maxEvents = 100_000 } = {}) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.protect = protect;
    this.unprotect = unprotect;
    this.dbPath=dbPath;
    this.maxBytes=maxBytes;
    this.maxEvents=maxEvents;
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS outbox (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);");
  }
  enqueue(event) {
    if(this.db.prepare("SELECT 1 FROM outbox WHERE event_id=?").get(event.eventId))return true;
    if(this.count()>=this.maxEvents||this.storageBytes()>=this.maxBytes)return false;
    return this.db.prepare("INSERT OR IGNORE INTO outbox (event_id,payload,created_at) VALUES (?,?,?)").run(event.eventId, this.protect(JSON.stringify(event)), event.timestamp).changes===1;
  }
  list(limit = 200) { return this.db.prepare("SELECT event_id AS eventId,payload FROM outbox ORDER BY created_at LIMIT ?").all(limit).map((row) => JSON.parse(this.unprotect(row.payload))); }
  acknowledge(ids) { const remove = this.db.prepare("DELETE FROM outbox WHERE event_id=?"); let deleted=0;for (const id of ids) deleted+=remove.run(id).changes;this.compactIfNeeded(deleted);return deleted; }
  pruneBefore(cutoff) { const deleted=this.db.prepare("DELETE FROM outbox WHERE created_at < ?").run(cutoff).changes;this.compactIfNeeded(deleted);return deleted; }
  count() { return this.db.prepare("SELECT COUNT(*) AS count FROM outbox").get().count; }
  storageBytes() { if(this.dbPath===":memory:")return 0;return [this.dbPath,`${this.dbPath}-wal`,`${this.dbPath}-shm`].reduce((n,file)=>{try{return n+fs.statSync(file).size;}catch{return n;}},0); }
  compactIfNeeded(deleted) { if(deleted&&this.storageBytes()>=this.maxBytes*0.75)this.db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"); }
  close() { this.db.close(); }
}
