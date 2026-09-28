# SentryGate Windows Release Checklist

Release artifact: `SentryGate-0.1.0-Windows-x64.zip`
SHA-256: `84fdeaaaebe5e6a63a713101bdb9bbe215bc4f960cf0aac07ecb28409bbf7fa8`

## Automated checks
- PASS: automated test suite (ℹ tests 89).
- PASS: JavaScript syntax/typecheck and static asset build checks.
- PASS: package-local static asset verification executed during packaging.
- PASS: extracted-package smoke (bundled Node runtime, SQLite, localhost API/dashboard, and first-admin setup).
- PASS: packaged Node.js runtime included; installer contains no default administrator password.
- PASS: detections default to Observe and firewall policy remains preview-only/disabled.
- FAIL: none in automated checks for this release build.
- NOT RUN: clean-VM service install, reboot, crash recovery, upgrade, rollback, firewall ownership cleanup, and uninstall. Requires a disposable Windows VM and elevated interactive session.
- BLOCKED: GitHub publication requires the exact candidate to pass clean-VM qualification, the protected `windows-clean-vm-qualified` approval, and repository variable `SENTRYGATE_CLEAN_WINDOWS_VM_VERIFIED=true`.

## Unresolved risks
- The backend/dashboard starts per-user at install and after that user's next logon; the enrolled agent service starts automatically with Windows and buffers reports while the dashboard host is unavailable.
- This release is a PowerShell/ZIP installer, not a signed MSI. Verify the downloaded archive SHA-256 and code-signing policy before distribution.
- No clean-machine Windows lifecycle verification is claimed by this build.
- Required service: `SentryGateAgent` (Automatic); optional `SentryGateFirewallHelper` is not installed by default. The dashboard uses the current user's `SentryGate Dashboard` logon task, not a Windows service.
