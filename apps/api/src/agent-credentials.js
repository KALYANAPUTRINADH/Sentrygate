import crypto from "node:crypto";

function encryptionKey(secret) {
  return Buffer.from(crypto.hkdfSync("sha256", Buffer.from(secret), Buffer.from("sentrygate-agent-token"), Buffer.from("at-rest"), 32));
}

export function rotateAgentCredential(db, secret) {
  const token = crypto.randomBytes(32).toString("base64url");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(secret), iv);
  const ciphertext = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  db.prepare(`INSERT INTO agent_credentials (id, token_hash, token_ciphertext, token_iv, token_tag, updated_at)
    VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,
    token_ciphertext=excluded.token_ciphertext, token_iv=excluded.token_iv, token_tag=excluded.token_tag,
    updated_at=excluded.updated_at`)
    .run(hashToken(token), ciphertext.toString("base64url"), iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), new Date().toISOString());
  return token;
}

export function ensureAgentCredential(db, secret) {
  const row = db.prepare("SELECT token_ciphertext, token_iv, token_tag FROM agent_credentials WHERE id = 1").get();
  if (!row) return rotateAgentCredential(db, secret);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(secret), Buffer.from(row.token_iv, "base64url"));
    decipher.setAuthTag(Buffer.from(row.token_tag, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(row.token_ciphertext, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    return rotateAgentCredential(db, secret);
  }
}

export function verifyAgentCredential(db, token) {
  if (typeof token !== "string" || token.length < 32 || token.length > 256) return false;
  const row = db.prepare("SELECT token_hash FROM agent_credentials WHERE id = 1").get();
  if (!row) return false;
  const supplied = Buffer.from(hashToken(token), "hex");
  const expected = Buffer.from(row.token_hash, "hex");
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
