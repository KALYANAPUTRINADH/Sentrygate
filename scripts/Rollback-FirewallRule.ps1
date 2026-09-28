param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-fA-F-]{36}$')]
  [string]$RuleId,
  [string]$BaseUrl = 'http://127.0.0.1:4300'
)

$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -notmatch '^https?://(127\.0\.0\.1|localhost)(:\d+)?$') {
  throw 'Rollback is restricted to the local loopback SentryGate dashboard.'
}

$credential = Get-Credential -Message 'Enter the local SentryGate administrator credentials'
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$loginBody = @{ email = $credential.UserName; password = $credential.GetNetworkCredential().Password } | ConvertTo-Json -Compress
try {
  Invoke-RestMethod -Uri "$BaseUrl/api/login" -Method Post -WebSession $session -ContentType 'application/json' -Body $loginBody | Out-Null
  $loginBody = $null
  $result = Invoke-RestMethod -Uri "$BaseUrl/api/firewall/rules/$RuleId/rollback" -Method Post -WebSession $session -ContentType 'application/json' -Body '{"confirmed":true}'
  $result | Select-Object id, status, deviceName, remoteCidr, protocol, localPort, expiresAt, rollbackAt, failure | Format-List
  Write-Host 'Removal is queued for the enrolled agent. Verify the final operating-system removal in Firewall history.'
} finally {
  $loginBody = $null
  $credential = $null
  $session = $null
}
