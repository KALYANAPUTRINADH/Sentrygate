$ErrorActionPreference = 'Stop'
$inputJson = [Console]::In.ReadToEnd()
$request = $inputJson | ConvertFrom-Json
$results = [System.Collections.Generic.List[object]]::new()
$desired = @($request.rules | Where-Object { $_.operation -eq 'ensure' -and $_.status -in @('approved','active','failed') -and [DateTimeOffset]::Parse($_.expiresAt) -gt [DateTimeOffset]::UtcNow })
$owned = @(Get-NetFirewallRule -Group 'SentryGate' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^SentryGate-[0-9a-f-]{36}$' -and $_.Description -like 'SentryGate managed rule:*' })
foreach ($rule in $request.rules) {
  $state = $null
  try {
    if ($rule.name -notmatch '^SentryGate-[0-9a-f-]{36}$' -or $rule.group -ne 'SentryGate') { throw 'Ownership marker is invalid.' }
    $found = @($owned | Where-Object Name -eq $rule.name)
    if ($rule.operation -eq 'remove' -or [DateTimeOffset]::Parse($rule.expiresAt) -le [DateTimeOffset]::UtcNow) {
      foreach ($existing in $found) { Remove-NetFirewallRule -Name $existing.Name -Group 'SentryGate' -ErrorAction Stop }
      $results.Add(@{ id=$rule.id; status='removed'; detail='Owned SentryGate rule absent after removal.'; actualState=$null })
      continue
    }
    if ($rule.operation -ne 'ensure' -or $rule.protocol -notin @('TCP','UDP') -or [int]$rule.localPort -lt 1 -or [int]$rule.localPort -gt 65535) { throw 'Requested firewall rule failed validation.' }
    if ($found.Count -gt 1) { throw 'Multiple owned rules have the same identifier; no changes made.' }
    if ($found.Count -eq 0) {
      New-NetFirewallRule -Name $rule.name -DisplayName $rule.name -Group 'SentryGate' -Description "SentryGate managed rule: $($rule.id)" -Direction Inbound -Action Block -Enabled True -Profile Any -RemoteAddress $rule.remoteAddress -Protocol $rule.protocol -LocalPort $rule.localPort -ErrorAction Stop | Out-Null
    }
    $actual = Get-NetFirewallRule -Name $rule.name -Group 'SentryGate' -ErrorAction Stop | Select-Object -First 1
    $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $actual
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $actual
    $state = @{ name=$actual.Name; group=$actual.Group; description=$actual.Description; direction=$actual.Direction.ToString(); action=$actual.Action.ToString(); enabled=$actual.Enabled.ToString(); remoteAddress=@($addr.RemoteAddress); protocol=$port.Protocol.ToString(); localPort=@($port.LocalPort) }
    if ($state.direction -ne 'Inbound' -or $state.action -ne 'Block' -or $state.enabled -ne 'True' -or
        (@($state.remoteAddress | ForEach-Object { $_.ToString() }) -notcontains [string]$rule.remoteAddress) -or
        $state.protocol -ne [string]$rule.protocol -or (@($state.localPort | ForEach-Object { $_.ToString() }) -notcontains [string]$rule.localPort)) {
      throw 'Observed Windows rule differs from the approved preview; no unrelated rule was changed.'
    }
    $results.Add(@{ id=$rule.id; status='active'; detail='Windows reports the owned inbound rule active.'; actualState=$state })
  } catch {
    $results.Add(@{ id=$rule.id; status='failed'; detail=$_.Exception.Message; actualState=$state })
  }
}
ConvertTo-Json -InputObject @{ results=@($results) } -Depth 8 -Compress
