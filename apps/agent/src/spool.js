import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export class EventSpool {
  constructor(dbPath, { protect = (value) => value, unprotect = (value) => value } = {}) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.protect = protect;
    this.unprotect = unprotect;
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS outbox (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);");
  }
  enqueue(event) { this.db.prepare("INSERT OR IGNORE INTO outbox (event_id,payload,created_at) VALUES (?,?,?)").run(event.eventId, this.protect(JSON.stringify(event)), event.timestamp); }
  list(limit = 200) { return this.db.prepare("SELECT event_id AS eventId,payload FROM outbox ORDER BY created_at LIMIT ?").all(limit).map((row) => JSON.parse(this.unprotect(row.payload))); }
  acknowledge(ids) { const remove = this.db.prepare("DELETE FROM outbox WHERE event_id=?"); for (const id of ids) remove.run(id); }
  pruneBefore(cutoff) { return this.db.prepare("DELETE FROM outbox WHERE created_at < ?").run(cutoff).changes; }
  count() { return this.db.prepare("SELECT COUNT(*) AS count FROM outbox").get().count; }
  close() { this.db.close(); }
}
