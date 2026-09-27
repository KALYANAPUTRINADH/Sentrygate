export function recordAudit(db, actor, action, target, detail) {
  db.prepare("INSERT INTO audit_log (actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?)").run(
    actor,
    action,
    target,
    detail,
    new Date().toISOString()
  );
}
