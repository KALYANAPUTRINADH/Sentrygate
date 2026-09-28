# Milestone 1 - Project and Dashboard

Milestone 1 establishes the monorepo, local API, local database, authenticated administrator access, and a security dashboard.

## Included

- npm workspace monorepo with no external runtime dependencies for Milestone 1.
- Static dashboard with separate Overview, Protected Assets, Alerts, Events, and Settings pages. Website-gateway controls are added in Milestone 2.
- Asset registration with name, type, address, and description validation.
- Event records include timestamp, asset, observed source IP, request/process details, reason, severity, and action; event queries support filters.
- Alert list and evidence detail view.
- Node HTTP API with local SQLite persistence through Node's built-in SQLite driver.
- Administrator setup with scrypt password hashing and per-password salts.
- Signed HttpOnly session cookies with a secret from `.env` (random process-local secret when omitted).
- Audit log entries for setup, login, logout, and domain changes.
- Retention cleanup endpoint and startup database migrations.

## Local Configuration

Environment variables:

- `SENTRYGATE_DB_PATH`: path to SQLite database.
- `SENTRYGATE_SESSION_SECRET`: session signing secret. If omitted, a random secret is generated for that server process; configure a stable secret for persistent sessions.
- `SENTRYGATE_PORT`: API port, default `4300`.

## Security Notes

- Passwords and tokens are never stored in plaintext.
- Demo data is opt-in through `npm run demo:data`; sample records are illustrative, not live detections.
- Cookie settings use `HttpOnly` and `SameSite=Lax`; set `Secure` behind HTTPS in deployment.
