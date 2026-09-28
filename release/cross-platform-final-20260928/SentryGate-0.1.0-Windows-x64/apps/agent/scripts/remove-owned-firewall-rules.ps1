$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission is required to remove SentryGate firewall rules.' }
$owned = @(Get-NetFirewallRule -Group 'SentryGate' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^SentryGate-(App-)?[0-9a-f-]{36}$' -and $_.Description -like 'SentryGate managed rule:*' })
foreach ($rule in $owned) { Remove-NetFirewallRule -Name $rule.Name -Group 'SentryGate' -ErrorAction Stop }
Write-Output "Removed $($owned.Count) SentryGate-owned firewall rules. Unrelated firewall rules were not changed."
