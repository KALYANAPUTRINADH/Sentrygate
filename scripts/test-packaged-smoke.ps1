param([Parameter(Mandatory=$true)][string]$ArchivePath)
$ErrorActionPreference='Stop'
$tempRoot=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ('sentrygate-package-smoke-'+[guid]::NewGuid().ToString('N'))))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$proc=$null
$envNames=@('NODE_ENV','SENTRYGATE_STANDALONE','SENTRYGATE_DATA_DIR','SENTRYGATE_DB_PATH','SENTRYGATE_PORT','SENTRYGATE_GATEWAY_PORT','SENTRYGATE_SESSION_SECRET','SENTRYGATE_HOST','SENTRYGATE_GATEWAY_HOST','SENTRYGATE_REMOTE_ACCESS_ENABLED','SENTRYGATE_API_BASE_URL','SENTRYGATE_TLS_CERT','SENTRYGATE_TLS_KEY')
$saved=@{};foreach($name in $envNames){$item=Get-Item "Env:$name" -ErrorAction SilentlyContinue;$saved[$name]=if($item){$item.Value}else{$null}}
function Get-FreeLoopbackPort {
  $socket=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
  try { $socket.Start();$socket.LocalEndpoint.Port } finally { $socket.Stop() }
}
try {
  $bundle=Join-Path $tempRoot 'bundle';Expand-Archive -LiteralPath (Resolve-Path $ArchivePath).Path -DestinationPath $bundle
  $node=Join-Path $bundle 'runtime\node.exe'
  foreach($required in @($node,(Join-Path $bundle 'Install-SentryGate.ps1'),(Join-Path $bundle 'INSTALL-WINDOWS.md'),(Join-Path $bundle 'RELEASE-NOTES.md'),(Join-Path $bundle 'apps\api\src\db.js'),(Join-Path $bundle 'apps\web\index.html'),(Join-Path $bundle 'apps\agent\scripts\install-agent.ps1'))) { if(-not(Test-Path -LiteralPath $required)){throw "Packaged file missing: $required"} }
  if(Get-ChildItem $bundle -Recurse -File | Where-Object { $_.Name -like '.env*' }){throw 'Release archive must not contain .env files.'}
  if(Get-ChildItem $bundle -Recurse -File -Filter '*.db'){throw 'Release archive must not contain local databases.'}
  if(Get-ChildItem $bundle -Recurse -File | Where-Object { $_.Name -in @('credential.dpapi','config.json') }){throw 'Release archive must not contain device identity or agent credential configuration.'}
  Push-Location $bundle;try{& $node 'apps/api/scripts/verify-static-assets.js';if($LASTEXITCODE -ne 0){throw 'Packaged static-asset verification failed.'}}finally{Pop-Location}
  $data=Join-Path $tempRoot 'data';$runtime=Join-Path $tempRoot 'runtime';New-Item -ItemType Directory -Path $data,$runtime | Out-Null
  $port=Get-FreeLoopbackPort;$gatewayPort=Get-FreeLoopbackPort
  $env:NODE_ENV='test';$env:SENTRYGATE_STANDALONE='true';$env:SENTRYGATE_DATA_DIR=$data;$env:SENTRYGATE_DB_PATH=Join-Path $data 'sentrygate.db';$env:SENTRYGATE_PORT=[string]$port;$env:SENTRYGATE_GATEWAY_PORT=[string]$gatewayPort;$env:SENTRYGATE_SESSION_SECRET=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48));$env:SENTRYGATE_HOST='0.0.0.0';$env:SENTRYGATE_GATEWAY_HOST='0.0.0.0';$env:SENTRYGATE_REMOTE_ACCESS_ENABLED='true';$env:SENTRYGATE_API_BASE_URL='https://203.0.113.9:443';$env:SENTRYGATE_TLS_CERT='ignored.crt';$env:SENTRYGATE_TLS_KEY='ignored.key'
  $proc=Start-Process -FilePath $node -ArgumentList @('apps/api/src/server.js') -WorkingDirectory $bundle -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtime 'api.log') -RedirectStandardError (Join-Path $runtime 'api-error.log')
  $base="http://127.0.0.1:$port";$ready=$false
  for($i=0;$i -lt 50;$i++){Start-Sleep -Milliseconds 400;try{$health=Invoke-RestMethod "$base/api/health" -TimeoutSec 2;if($health.ok){$ready=$true;break}}catch{}}
  if(-not $ready){throw 'Packaged backend/SQLite did not become healthy.'}
  $page=Invoke-WebRequest "$base/" -UseBasicParsing -TimeoutSec 5
  if($page.StatusCode -ne 200){throw 'Packaged dashboard did not return HTTP 200.'}
  $fresh=Invoke-RestMethod "$base/api/session" -TimeoutSec 5
  if(-not $fresh.setupRequired){throw 'Fresh package did not request owner setup.'}
  $password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))+'!aA'
  $created=Invoke-RestMethod "$base/api/setup" -Method Post -ContentType 'application/json' -Body (@{email='release-smoke@example.invalid';password=$password}|ConvertTo-Json) -TimeoutSec 5
  $after=Invoke-RestMethod "$base/api/session" -TimeoutSec 5
  if($after.setupRequired -or $created.email -ne 'release-smoke@example.invalid'){throw 'Packaged first-administrator setup did not complete.'}
  if(-not $health.standalone -or $health.remoteAccessEnabled -or $health.transport -ne 'loopback-http-development'){throw 'Packaged backend did not force standalone localhost-only mode.'}
  if(-not(Test-Path (Join-Path $data 'sentrygate.db'))){throw 'Packaged SQLite database was not created in the selected local data directory.'}
  Write-Output "PASS: extracted package, bundled runtime, migrations, forced-loopback standalone API despite hostile environment overrides, SQLite, first-admin setup; Node $((& $node --version).Trim())"
} finally {
  if($proc){Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue}
  foreach($name in $envNames){if($null -eq $saved[$name]){Remove-Item "Env:$name" -ErrorAction SilentlyContinue}else{Set-Item "Env:$name" $saved[$name]}}
  $resolved=[IO.Path]::GetFullPath($tempRoot);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  if($resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf).StartsWith('sentrygate-package-smoke-')){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
