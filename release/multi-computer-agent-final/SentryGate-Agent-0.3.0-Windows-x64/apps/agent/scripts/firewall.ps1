$ErrorActionPreference = 'Stop'
$inputJson = [Console]::In.ReadToEnd()
$request = $inputJson | ConvertFrom-Json
$results = [System.Collections.Generic.List[object]]::new()
$owned = @(Get-NetFirewallRule -Group 'SentryGate' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^SentryGate-(App-)?[0-9a-f-]{36}$' -and $_.Description -like 'SentryGate managed rule:*' })
if ($request.action -eq 'pruneExpired') {
  foreach ($existing in $owned) {
    if ($existing.Description -match 'expires=([^; ]+)') {
      try {
        if ([DateTimeOffset]::Parse($Matches[1]).ToUniversalTime() -le [DateTimeOffset]::UtcNow) {
          Remove-NetFirewallRule -Name $existing.Name -Group 'SentryGate' -ErrorAction Stop
          if (@(Get-NetFirewallRule -Name $existing.Name -Group 'SentryGate' -ErrorAction SilentlyContinue).Count -gt 0) { throw 'Expired SentryGate-owned rule remains after removal.' }
          $results.Add(@{ id=($existing.Name -replace '^SentryGate-(App-)?',''); status='removed'; detail='Expired SentryGate-owned rule removed by local helper timer.'; actualState=$null })
        }
      } catch { $results.Add(@{ id=($existing.Name -replace '^SentryGate-(App-)?',''); status='failed'; detail=$_.Exception.Message; actualState=$null }) }
    }
  }
  ConvertTo-Json -InputObject @{ results=@($results) } -Depth 8 -Compress
  exit 0
}
foreach ($rule in $request.rules) {
  $state = $null
  try {
    if ($rule.name -notmatch '^SentryGate-(App-)?[0-9a-f-]{36}$' -or $rule.group -ne 'SentryGate') { throw 'Ownership marker is invalid.' }
    $found = @($owned | Where-Object Name -eq $rule.name)
    $byName = @(Get-NetFirewallRule -Name $rule.name -ErrorAction SilentlyContinue)
    $descriptionMarker = "SentryGate managed rule: $($rule.id)"
    $byDescription = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Description -like "$descriptionMarker*" })
    $candidates = @($byName + $byDescription | Sort-Object Name -Unique)
    if ($candidates | Where-Object { $_.Name -ne $rule.name -or $_.Group -ne 'SentryGate' -or $_.Description -notlike "$descriptionMarker*" }) { throw 'SentryGate ownership markers changed; no firewall rule was modified.' }
    if ($rule.operation -eq 'remove' -or [DateTimeOffset]::Parse($rule.expiresAt) -le [DateTimeOffset]::UtcNow) {
      foreach ($existing in $found) { Remove-NetFirewallRule -Name $existing.Name -Group 'SentryGate' -ErrorAction Stop }
      $results.Add(@{ id=$rule.id; status='removed'; detail='Owned SentryGate rule absent after removal.'; actualState=$null })
      continue
    }
    if ($rule.operation -ne 'ensure') { throw 'Requested firewall operation failed validation.' }
    if ($found.Count -gt 1) { throw 'Multiple owned rules have the same identifier; no changes made.' }
    if ($found.Count -eq 0) {
      if ($rule.kind -eq 'application') {
        if (-not [IO.Path]::IsPathRooted([string]$rule.programPath) -or [IO.Path]::GetExtension([string]$rule.programPath) -ne '.exe' -or -not (Test-Path -LiteralPath $rule.programPath -PathType Leaf)) { throw 'Application executable path is invalid or unavailable.' }
        if ($rule.action -notin @('Allow','Block')) { throw 'Application policy action is invalid.' }
        New-NetFirewallRule -Name $rule.name -DisplayName $rule.name -Group 'SentryGate' -Description "SentryGate managed rule: $($rule.id); expires=$(([DateTimeOffset]::Parse($rule.expiresAt)).ToUniversalTime().ToString('o'))" -Direction Inbound -Action $rule.action -Enabled True -Profile Any -Program $rule.programPath -ErrorAction Stop | Out-Null
      } else {
        if ($rule.kind -ne 'inbound' -or $rule.protocol -notin @('TCP','UDP') -or [int]$rule.localPort -lt 1 -or [int]$rule.localPort -gt 65535) { throw 'Requested inbound rule failed validation.' }
        New-NetFirewallRule -Name $rule.name -DisplayName $rule.name -Group 'SentryGate' -Description "SentryGate managed rule: $($rule.id); expires=$(([DateTimeOffset]::Parse($rule.expiresAt)).ToUniversalTime().ToString('o'))" -Direction Inbound -Action Block -Enabled True -Profile Any -RemoteAddress $rule.remoteAddress -Protocol $rule.protocol -LocalPort $rule.localPort -ErrorAction Stop | Out-Null
      }
    }
    $actual = Get-NetFirewallRule -Name $rule.name -Group 'SentryGate' -ErrorAction Stop | Select-Object -First 1
    $state = @{ name=$actual.Name; group=$actual.Group; description=$actual.Description; direction=$actual.Direction.ToString(); action=$actual.Action.ToString(); enabled=$actual.Enabled.ToString() }
    if ($rule.kind -eq 'application') {
      $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $actual
      $state.program = [string]$app.Program
      if ($state.action -ne [string]$rule.action -or $state.enabled -ne 'True' -or $state.program -ine [string]$rule.programPath -or $state.direction -ne 'Inbound') { throw 'Observed application rule differs from the approved inbound-only preview; no unrelated rule was changed.' }
    } else {
      $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $actual
      $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $actual
      $state.remoteAddress = @($addr.RemoteAddress); $state.protocol = $port.Protocol.ToString(); $state.localPort = @($port.LocalPort)
      if ($state.direction -ne 'Inbound' -or $state.action -ne 'Block' -or $state.enabled -ne 'True' -or
          (@($state.remoteAddress | ForEach-Object { $_.ToString() }) -notcontains [string]$rule.remoteAddress) -or
          $state.protocol -ne [string]$rule.protocol -or (@($state.localPort | ForEach-Object { $_.ToString() }) -notcontains [string]$rule.localPort)) { throw 'Observed Windows rule differs from the approved preview; no unrelated rule was changed.' }
    }
    $results.Add(@{ id=$rule.id; status='active'; detail='Windows reports the owned inbound rule active.'; actualState=$state })
  } catch {
    $results.Add(@{ id=$rule.id; status='failed'; detail=$_.Exception.Message; actualState=$state })
  }
}
ConvertTo-Json -InputObject @{ results=@($results) } -Depth 8 -Compress
