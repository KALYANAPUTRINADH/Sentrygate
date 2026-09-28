import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../../..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");

test("Windows installer keeps secrets interactive, dashboard loopback-local, and policy defaults safe", () => {
  const install = read("scripts/Install-SentryGate.ps1");
  const agentInstall = read("apps/agent/scripts/install-agent.ps1");
  const agentPackager = read("scripts/package-agent.ps1");
  const agentRollback = read("apps/agent/scripts/rollback-agent.ps1");
  const agentConfigure = read("apps/agent/scripts/configure-agent.ps1");
  const localStart = read("scripts/start-sentrygate.ps1");
  assert.match(install, /127\.0\.0\.1:4300/);
  assert.match(install, /setupRequired/);
  assert.match(install, /Type INSTALL/);
  assert.match(install, /-LocalOnly/);
  assert.match(install, /Locally enroll this computer/);
  assert.match(localStart, /SENTRYGATE_STANDALONE='true'/);
  assert.match(localStart, /SENTRYGATE_HOST='127\.0\.0\.1'/);
  assert.match(agentInstall, /-StartupType Automatic/);
  assert.match(agentInstall, /restart\/5000\/restart\/15000\/restart\/60000/);
  assert.match(agentInstall, /SpoolMaxBytes\s*=\s*268435456/);
  assert.match(agentPackager, /No device identity, credential, configuration, local database, or event spool is included/);
  assert.match(agentPackager, /Get-FileHash[\s\S]*SHA256/);
  assert.match(agentRollback, /Agent\.rollback-/);
  assert.match(agentRollback, /DPAPI credentials, device identity, and buffered local event data/);
  assert.match(agentConfigure, /Read-Host 'Paste the one-time device credential' -AsSecureString/);
  assert.doesNotMatch(install, /password\s*=\s*['"]/i);
  assert.match(read("apps/api/src/db.js"), /mode TEXT NOT NULL DEFAULT 'observe'/);
  assert.match(read("apps/api/src/db.js"), /enforcement_enabled INTEGER NOT NULL DEFAULT 0/);
});

test("Windows lifecycle scripts preserve data, require deletion consent, and limit uninstall to owned paths", () => {
  const upgrade = read("scripts/Upgrade-SentryGate.ps1");
  const rollback = read("scripts/Rollback-SentryGate.ps1");
  const uninstall = read("scripts/Uninstall-SentryGate.ps1");
  const agentUpgrade = read("apps/agent/scripts/upgrade-agent.ps1");
  assert.match(upgrade, /backup-sentrygate\.ps1/);
  assert.match(upgrade, /rollback-\$stamp/);
  assert.match(upgrade, /start-sentrygate\.ps1/);
  assert.match(rollback, /PreviousInstallDirectory/);
  assert.match(uninstall, /Type DELETE DATA/);
  assert.match(uninstall, /\.sentrygate-install/);
  assert.match(uninstall, /\.sentrygate-data/);
  assert.match(uninstall, /uninstall-agent\.ps1/);
  assert.match(agentUpgrade, /WaitForStatus\('Running'/);
  assert.match(agentUpgrade, /DPAPI data and buffered events were preserved/);
  assert.match(agentUpgrade, /\$stagedService/);
  assert.match(read("docs/multi-computer-deployment.md"), /Do not port-forward SentryGate's TCP API port/);
  assert.match(read("docs/multi-computer-deployment.md"), /Agent\.rollback-/);
  assert.match(read("INSTALL-WINDOWS.md"), /no domain, VPN, central server/i);
});

test("release packager includes a private Node runtime and does not copy .env or local database files", () => {
  const packager = read("scripts/package-local.ps1");
  assert.match(packager, /runtime\\node\.exe/);
  assert.match(packager, /INSTALL-WINDOWS\.md/);
  assert.match(packager, /Install-SentryGate\.ps1/);
  assert.match(packager, /RELEASE-NOTES\.md/);
  assert.doesNotMatch(packager, /\.env(?:\.example)?/);
  assert.doesNotMatch(packager, /Copy-Item[^\r\n]*\.db/);
  assert.match(read("scripts/build-release.ps1"), /Get-FileHash[^\r\n]*SHA256/);
});

test("GitHub release bootstrap verifies named assets and service health before reporting success", () => {
  const bootstrap = read("Install-SentryGate.ps1");
  const workflow = read(".github/workflows/windows-release.yml");
  assert.match(bootstrap, /api\.github\.com\/repos/);
  assert.match(bootstrap, /SentryGate-\$releaseVersion-Windows-x64\.zip/);
  assert.match(bootstrap, /\$checksumName = "\$archiveName\.sha256"/);
  assert.match(bootstrap, /Get-FileHash[^\r\n]*SHA256/);
  assert.match(bootstrap, /missing required installer asset/);
  assert.match(bootstrap, /missing required checksum asset/);
  assert.match(bootstrap, /Get-Service -Name 'SentryGateAgent'/);
  assert.match(bootstrap, /StartMode -ne 'Auto'/);
  assert.match(bootstrap, /health-sentrygate\.ps1/);
  assert.match(bootstrap, /Name -like '\.env\*'/);
  assert.match(bootstrap, /Filter '\*\.db'/);
  assert.match(workflow, /npm test/);
  assert.match(workflow, /npm install --ignore-scripts/);
  assert.doesNotMatch(workflow, /npm ci|cache: npm/);
  assert.match(workflow, /build-release\.ps1/);
  assert.match(workflow, /windows-clean-vm-qualified/);
  assert.match(workflow, /SENTRYGATE_CLEAN_WINDOWS_VM_VERIFIED/);
  assert.match(workflow, /gh release (create|upload)/);
  assert.match(workflow, /RELEASE-NOTES\.md/);
  const notes = read("RELEASE-NOTES.md");
  assert.match(notes, /Windows 11 x64/);
  assert.match(notes, /Uninstall/);
  assert.match(notes, /Limitations/);
  assert.match(notes, /SentryGateAgent/);
});

test("local startup does not accept an unrelated listener as its own backend", () => {
  const start = read("scripts/start-sentrygate.ps1");
  assert.match(start, /Win32_Process -Filter "ProcessId=\$existingPid"/);
  assert.match(start, /CommandLine -like "\*\$apiEntry\*"/);
  assert.match(start, /Get-Process -Id \$api\.Id/);
});
