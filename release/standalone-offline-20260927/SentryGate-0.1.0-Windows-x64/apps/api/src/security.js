import crypto from "node:crypto";

const scryptOptions = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("base64url");
  const hash = crypto.scryptSync(password, salt, 64, scryptOptions).toString("base64url");
  return { salt, hash };
}

export function verifyPassword(password, salt, expectedHash) {
  const hash = crypto.scryptSync(password, salt, 64, scryptOptions);
  const expected = Buffer.from(expectedHash, "base64url");
  return expected.length === hash.length && crypto.timingSafeEqual(hash, expected);
}

export function signSession(admin, secret) {
  const payload = {
    sub: String(admin.id),
    email: admin.email,
    jti: crypto.randomUUID(),
    exp: Date.now() + 8 * 60 * 60 * 1000
  };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${signature}`;
}

export function verifySession(token, secret) {
  if (!token || !token.includes(".")) {
    return null;
  }
  const [body, signature] = token.split(".");
  const expected = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  let payload;
  try { payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")); }
  catch { return null; }
  if (!payload || typeof payload.sub !== "string" || typeof payload.jti !== "string" || !Number.isFinite(payload.exp) || payload.exp < Date.now()) {
    return null;
  }
  return payload;
}
