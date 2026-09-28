# Local Storage and Privacy

## Data location and protection

SentryGate stores backend state in one local SQLite database: administrator and asset configuration, credential verifiers, events, alerts, incidents, audit rows, findings, report snapshots, agent inventory, and queued actions. Select its directory before starting the API with `SENTRYGATE_DATA_DIR` in the uncommitted `.env`; `SENTRYGATE_DB_PATH` remains an explicit database-file override. Relative values are resolved from the repository/service working directory. Changing the directory does not move an existing database: stop SentryGate, make and verify a local backup, copy/restore the DB into the new directory, update the setting, then restart and verify `/api/health` and expected dashboard records.

The Settings page and authenticated `/api/storage` endpoint show the database path, combined SQLite/WAL/SHM use, configured cap, volume free space, and warnings. Configure the cap with `SENTRYGATE_MAX_DB_BYTES`, warning threshold with `SENTRYGATE_STORAGE_WARNING_PERCENT` (50–99), and low-volume warning with `SENTRYGATE_MIN_FREE_DISK_BYTES` (zero disables that warning). The default is a 2 GiB DB cap, 80% warning, and 1 GiB free-space warning. Retention for raw events, reports, audit rows, and analysis findings is configured in the existing Settings pages and runs automatically; **Run cleanup** is available for immediate cleanup.

SQLite is not encrypted by SentryGate. On Windows, put the data directory and any backups on a BitLocker-encrypted volume, restrict NTFS ACLs to the service identity and approved administrators, and keep keys/recovery material outside the database and source tree. On macOS/Linux use full-volume encryption and restrictive filesystem permissions. Windows agent secrets/spools use DPAPI; macOS/Linux agent secrets/spools use AES-256-GCM with a per-installation key file readable only by the service account (0600 permissions). This protects against other unprivileged local accounts, not root/administrator access or offline disk theft without volume encryption. Passwords and credential verifiers in SQLite are salted/hashed; they are not recoverable plaintext tokens. Protect the `.env`, TLS private keys, and backups with the same ACL/encryption policy.

## Local backup and restore

Backups are explicit, local filesystem operations. SentryGate never uploads, synchronizes, or automatically copies a backup elsewhere. Choose a path on an encrypted local volume, and apply the same ACLs as the live DB.

```powershell
$backup = Join-Path $env:ProgramData "SentryGate\Backups\sentrygate-$(Get-Date -Format yyyyMMdd-HHmmss).db"
New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null
npm run db:backup -- --out $backup
# Verify the generated snapshot independently.
node -e "const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(process.argv[1],{readOnly:true});console.log(d.prepare('PRAGMA integrity_check').get());d.close()" $backup
```

Restore is destructive and requires stopping SentryGate. It integrity-checks the source and staging copy, preserves an existing target as `.pre-restore-*`, and never contacts a remote service:

```powershell
# Stop the foreground server with Ctrl+C or stop the Windows service.
npm run db:restore -- --source $backup --confirm
npm run dev
Invoke-RestMethod http://127.0.0.1:4300/api/health
```

The automated `apps/api/test/storage.test.js` restore test checks snapshot contents, integrity, explicit confirmation, and preservation of the prior database. Run it with `node --test apps/api/test/storage.test.js` before relying on a backup. A successful integrity check does not prove backup freshness or completeness; periodically perform a restore drill and confirm expected dashboard records.

## Storage failure behavior

If the database approaches its configured cap, health and Settings warn. At the cap, event/report ingestion that checks capacity returns HTTP 507; new evidence cannot be persisted, and SentryGate does not claim otherwise. The gateway records events in a bounded local SQLite outbox before delivery. A temporarily unreachable API does not prevent an event from being durably queued, so a block-mode detection remains enforced and retries resume when the API returns. If that local outbox is full or cannot be written, the website's configured telemetry-failure behavior applies: **fail open** forwards the request, while **fail closed** returns 503 for a detected request that cannot be recorded. Device agents buffer events in a bounded, OS-protected spool. If the host volume is completely full or the database itself is unavailable, the API/dashboard cannot reliably serve data; operators must free local space or restore service. SentryGate does not disable the platform firewall.

## Network connections and offline operation

| Component | Runtime connection | Destination and purpose |
| --- | --- | --- |
| Browser dashboard | HTTP(S) requests, same origin only | Configured SentryGate API host for login, pages, and reports; no CDN assets or third-party browser SDKs |
| API | Local filesystem/SQLite | Configured local data directory; no outbound analytics, crash upload, cloud database, object store, or AI API |
| Website gateway | HTTP(S) upstream and local API | Only the administrator-configured website upstream, plus the configured local SentryGate event API; upstream may be external because it is the website being protected |
| Local endpoint agent | DNS and HTTPS (HTTP only for loopback development) | Resolves configured SentryGate API first and sends only when all resolved addresses are loopback/private/link-local; public or unresolved results are treated as offline. Standalone installs target loopback. DNS queries go to the endpoint's configured resolver |
| Optional analysis worker | Local SQLite | No network connection |
| Install/update | Operator-run package manager or local files | No runtime update check or silent download. Install-time dependency acquisition may use npm registry unless dependencies are already cached/offline-installed |

After dependencies and runtime are installed, dashboard/API, local gateway, local SQLite, and offline analysis work without internet access. A separately enrolled agent can communicate over a configured private network when the host is reachable. A protected website's upstream may itself require internet access; no gateway can serve an unreachable upstream unless the application has its own cache/fallback. The agent cannot report while its configured private backend is unreachable; it buffers within its configured local retention/capacity. A hostname requires the configured DNS resolver to be available, unless an IP address is configured.

The current packaged deployment starts the website gateway alongside the API and shares its local SQLite database. Therefore the outbox handles a temporary API delivery outage only while the gateway process and its host remain running. It does **not** yet provide a separately installable gateway on another computer with its own provisioned asset configuration and credential. If the SentryGate computer itself is offline, this gateway cannot keep serving the site or later deliver buffered events. Independent remote-gateway deployment is a remaining limitation and must be completed before relying on that outage scenario.

There are no analytics SDKs, crash-report uploaders, cloud storage clients, external AI integrations, or background update checks in runtime dependencies/code. To check the dependency tree for unexpected SDK changes during review, run `npm ls --all` and inspect package manifests/lockfiles before installing a candidate.

## Administrator-controlled updates

There is no automatic updater. An update is optional and administrator controlled: obtain a release/package from the organization's approved source using a separate review process, verify its published checksum/signature out of band, transfer it to the SentryGate host, inspect scripts and dependency changes, create and verify a local DB backup, run the full tests offline where possible, and apply in a maintenance window with the documented rollback plan. Do not run an unverified package or silently permit an update process to fetch/install code. Current releases do not provide a SentryGate-signed update manifest, so authenticity verification must be supplied by the release/distribution process; this is a limitation, not an automatic security guarantee.
