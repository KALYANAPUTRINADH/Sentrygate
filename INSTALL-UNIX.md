# SentryGate macOS and Linux Installation

This is the source/bundle procedure for macOS and Linux. Build the package on its target OS: Node binaries are platform-specific. SentryGate is standalone, local-only, and forces dashboard/API listeners to `127.0.0.1`. The dashboard/backend runs in the current user's service manager; the endpoint agent is installed separately after local enrollment. No network service, account, domain, cloud API, or internet connection is used after package transfer.

## Platform status

| Platform | Collection | Boot service | Firewall integration | Verification here |
|---|---|---|---|---|
| Windows | Existing CIM/PowerShell process, TCP, service, and security metadata | Windows service (`SentryGateAgent`) | Windows Defender Firewall through the separately installed SentryGate helper | Windows host tests and packaged API smoke only; no elevated service lifecycle test in this change |
| Linux | `ps`, `ss`, `systemctl`, firewall status metadata | systemd user service with linger for dashboard; system service for agent | nftables, only in the isolated `inet sentrygate` table; root agent service required | Mocked parser/adapter tests only; not run on a Linux host |
| macOS | `ps`, `lsof`, `launchctl`, Application Firewall status | LaunchDaemon for backend running as the installing user, plus root LaunchDaemon for agent (both start at boot) | No rule writes. Application Firewall status is observed; inbound IP rules remain preview-only because safely attaching a PF anchor requires editing shared system PF configuration | Mocked parser tests only; not run on macOS |

Windows behavior is documented separately in [INSTALL-WINDOWS.md](INSTALL-WINDOWS.md). macOS/Linux collection is metadata-only: no file contents, process command arguments, keystrokes, passwords, browser history, or encrypted traffic are collected. Native OS behavior, permissions, firewall state, and actual service startup must be tested on that OS before use. Linux runs the agent as root to collect system-wide metadata and use nftables; this broad privilege is a significant residual risk. macOS agent also runs as root for system-wide metadata, but does not change its firewall.

## Build a transferable package on each OS

Install Node.js 24+ on a development machine running the target OS. Run from the repository root:

```sh
sh scripts/package-platform.sh "$HOME/sentrygate-package"
```

Copy the generated `$HOME/sentrygate-package.tar.gz` to the target computer by USB. It includes the Node executable from the build machine; use a compatible architecture and OS release. Extract it and install:

```sh
mkdir -p "$HOME/SentryGateBundle"
tar -xzf /path/to/sentrygate-package.tar.gz -C "$HOME/SentryGateBundle"
cd "$HOME/SentryGateBundle"
sh scripts/install-sentrygate-linux.sh
```

For macOS use the matching `SentryGate-darwin-*.tar.gz` filename, extract it the same way, then run `sh scripts/install-sentrygate-macos.sh`. The installers copy application code under `/opt/sentrygate`, create the OS-specific backend service, and start it. Linux enables user-service lingering through `loginctl`; this requires administrator consent. macOS uses a boot-time LaunchDaemon running as the installing user. Create the first administrator at `http://127.0.0.1:4300`, then use **Devices → Enroll this computer** and copy the one-time device ID and credential.

Install the OS agent service only after local enrollment:

```sh
sudo env SENTRYGATE_AGENT_DATA=/var/lib/sentrygate-agent \
  /opt/sentrygate/runtime/sentrygate-node \
  /opt/sentrygate/apps/agent/scripts/configure-agent-unix.mjs \
  '<local-device-guid>' http://127.0.0.1:4300
sudo sh /opt/sentrygate/scripts/install-agent-service-unix.sh '<local-device-guid>'
```

The configuration prompt asks for the ID suffix and reads the credential without echo. The credential is AES-256-GCM encrypted under a per-installation 0600 key in `/var/lib/sentrygate-agent`; protect this directory with local disk encryption and administrator-only access. The Linux system agent runs as root so nftables and system-wide metadata collection work. Enforcement remains disabled until an owner explicitly changes local policy in the dashboard. macOS inbound IP firewall enforcement is not available; approvals for such rules fail closed and report an unsupported adapter.

## Service commands

Linux dashboard/backend:

```sh
systemctl --user status sentrygate.service
systemctl --user start sentrygate.service
systemctl --user stop sentrygate.service
systemctl --user restart sentrygate.service
```

Linux endpoint agent:

```sh
sudo systemctl status sentrygate-agent.service
sudo systemctl start sentrygate-agent.service
sudo systemctl stop sentrygate-agent.service
sudo systemctl restart sentrygate-agent.service
```

macOS dashboard/backend (system LaunchDaemon runs the backend as the installing user):

```sh
sudo launchctl print system/local.sentrygate.dashboard
sudo launchctl kickstart -k system/local.sentrygate.dashboard
sudo launchctl bootout system/local.sentrygate.dashboard
sudo launchctl bootstrap system /Library/LaunchDaemons/local.sentrygate.dashboard.plist
```

macOS endpoint agent:

```sh
sudo launchctl print system/local.sentrygate.agent
sudo launchctl kickstart -k system/local.sentrygate.agent
sudo launchctl bootout system/local.sentrygate.agent
sudo launchctl bootstrap system /Library/LaunchDaemons/local.sentrygate.agent.plist
```

All systems health-check the local backend with:

```sh
curl --fail http://127.0.0.1:4300/api/health
```

Expected JSON includes `"ok":true`, `"standalone":true`, and `"remoteAccessEnabled":false`. Open `http://127.0.0.1:4300` in a local browser. Local service logs are in the OS journal on Linux (`journalctl --user -u sentrygate` and `sudo journalctl -u sentrygate-agent`) and under the SentryGate Runtime/Agent data directories on macOS.

## Backup, update, uninstall

Run backup locally; the database remains on this computer:

```sh
sh /opt/sentrygate/scripts/backup-sentrygate-unix.sh "$HOME/SentryGate-backup-$(date +%Y%m%d-%H%M%S).db"
```

Update offline: transfer and extract a package built for this same OS/architecture, inspect its checksum through your approved channel, then stop, back up, and replace application files while preserving the local data directories:

```sh
sh /path/to/new-bundle/scripts/update-sentrygate-unix.sh /path/to/new-bundle
```

Rollback is manual: stop both services, move `/opt/sentrygate.old-<timestamp>` back to `/opt/sentrygate`, restart the services, and restore a database backup only if the new version migrated it incompatibly. Keep the previous binary bundle until health and login checks pass.

Uninstall removes services and asks before removing code/data. Linux removal only deletes the isolated `inet sentrygate` nftables table if every rule in it has a SentryGate ownership comment; it refuses otherwise.

```sh
sh /opt/sentrygate/scripts/uninstall-sentrygate-unix.sh
```

Verify services are absent. Type `DELETE DATA` only when you intentionally want the local database, reports, credentials, keys, and buffered agent events erased. Back up first if those records matter.

## Development tests

```sh
npm test
npm run typecheck
npm run build
```

The platform collector and nftables adapter tests use mocked OS output/commands. Those checks do **not** establish that launchd, systemd, `ss`, `lsof`, `nft`, OS permission behavior, or service recovery works on macOS/Linux. Complete installation, reboot, recovery, offline operation, backup/restore, rollback, and uninstall tests on clean machines of each target OS before deploying.
