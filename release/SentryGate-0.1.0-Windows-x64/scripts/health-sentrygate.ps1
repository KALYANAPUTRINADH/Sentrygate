param([string]$BaseUrl = 'http://127.0.0.1:4300',[string]$DeviceId,[switch]$SkipAgent)
$ErrorActionPreference='Stop'
$uri=[uri]$BaseUrl
if ($uri.Host -notin @('127.0.0.1','::1','localhost') -or $uri.Scheme -ne 'http') { throw 'Installer health checks are limited to the default local HTTP listener.' }
$base=$BaseUrl.TrimEnd('/')
$dashboard=Invoke-WebRequest "$base/" -TimeoutSec 5 -UseBasicParsing
if ($dashboard.StatusCode -ne 200) { throw 'Dashboard did not return HTTP 200.' }
$health=Invoke-RestMethod "$base/api/health" -TimeoutSec 5
if (-not $health.ok -or $health.database -ne 'ready') { throw 'Backend or SQLite health check failed.' }
if ($health.remoteAccessEnabled) { throw 'Remote dashboard access is enabled; installer defaults require localhost-only access.' }
$serviceState='not checked'
$serviceStartMode='not checked'
$delivery='not checked'
if (-not $SkipAgent) {
  $service=Get-Service SentryGateAgent -ErrorAction Stop
  if ($service.Status -ne 'Running') { throw "Windows agent service is $($service.Status), expected Running." }
  $serviceConfig=Get-CimInstance Win32_Service -Filter "Name='SentryGateAgent'"
  if ($serviceConfig.StartMode -ne 'Auto') { throw "Windows agent service startup mode is $($serviceConfig.StartMode), expected Auto." }
  $serviceState=$service.Status.ToString()
  $serviceStartMode=$serviceConfig.StartMode
  if (-not $DeviceId) { throw 'Pass -DeviceId to verify authenticated event delivery.' }
  if ($DeviceId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'DeviceId must be a GUID.' }
  $admin=Get-Credential -Message 'Sign in locally to verify the enrolled device heartbeat'
  $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($admin.Password)
  try {
    $password=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    $session=[Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $body=@{email=$admin.UserName;password=$password}|ConvertTo-Json -Compress
    Invoke-RestMethod "$base/api/login" -Method Post -ContentType 'application/json' -Body $body -WebSession $session -TimeoutSec 10 | Out-Null
  } finally { $password=$null; [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $admin.Password.Dispose() }
  $deadline=(Get-Date).AddSeconds(100);$device=$null
  do {
    $devices=Invoke-RestMethod "$base/api/devices" -WebSession $session -TimeoutSec 10
    $device=@($devices)|Where-Object { $_.deviceId -eq $DeviceId }|Select-Object -First 1
    if ($device -and $device.lastHeartbeat) {
      $age=((Get-Date).ToUniversalTime()-( [DateTime]::Parse($device.lastHeartbeat).ToUniversalTime())).TotalSeconds
      if ($age -le 100) { $delivery="authenticated heartbeat received $([int]$age)s ago";break }
    }
    Start-Sleep -Seconds 5
  } while ((Get-Date) -lt $deadline)
  if ($delivery -eq 'not checked') { throw 'No recent authenticated agent heartbeat arrived within 100 seconds; check service, network, and enrolled device ID.' }
}
[pscustomobject]@{Dashboard='PASS (HTTP 200)';Backend='PASS (healthy)';Database=$health.database;AgentService=$serviceState;AgentStartMode=$serviceStartMode;AgentEventDelivery=$delivery;DataDirectory=$health.dataDirectory;RemoteAccessEnabled=$health.remoteAccessEnabled;StorageBytes=$health.storageBytes}
