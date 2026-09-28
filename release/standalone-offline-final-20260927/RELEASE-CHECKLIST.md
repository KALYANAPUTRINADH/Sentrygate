# SentryGate Windows Release Checklist

Release artifact: `SentryGate-0.1.0-Windows-x64.zip`
SHA-256: `67999d3215a2c5cfe8f4b8160b2ea00beb872b52d2a25c0f6690d8dc4ad7570a`

## Automated checks
- PASS: automated test suite (ℹ tests 81).
- PASS: JavaScript syntax/typecheck and static asset build checks.
- PASS: package-local static asset verification executed during packaging.
- PASS: extracted-package smoke (bundled Node runtime, SQLite, localhost API/dashboard, and first-admin setup).
- PASS: packaged Node.js runtime included; installer contains no default administrator password.
- PASS: detections default to Observe and firewall policy remains preview-only/disabled.
- FAIL: none in automated checks for this release build.
- NOT RUN: clean-VM service install, reboot, crash recovery, upgrade, rollback, firewall ownership cleanup, and uninstall. Requires a disposable Windows VM and elevated interactive session.

## Unresolved risks
- The backend/dashboard starts per-user at install and after that user's next logon; the enrolled agent service starts automatically with Windows and buffers reports while the dashboard host is unavailable.
- This release is a PowerShell/ZIP installer, not a signed MSI. Verify the downloaded archive SHA-256 and code-signing policy before distribution.
- No clean-machine Windows lifecycle verification is claimed by this build.
