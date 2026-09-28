param([string]$DataDirectory,[string]$RuntimeDirectory,[switch]$LocalOnly)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$node=if(Test-Path (Join-Path $root 'runtime\node.exe')){Join-Path $root 'runtime\node.exe'}else{(Get-Command node.exe -ErrorAction Stop).Source}
$version=[version]((& $node --version).TrimStart('v'))
if($version -lt [version]'24.0'){throw 'SentryGate requires Node.js 24 or later.'}
$envFile=Join-Path $root '.env'
if(Test-Path -LiteralPath $envFile){foreach($line in Get-Content -LiteralPath $envFile){if($line -match '^\s*(SENTRYGATE_[A-Za-z0-9_]+)\s*=\s*(.*)\s*$'){$key=$Matches[1];$value=$Matches[2].Trim('"',"'");if(-not (Test-Path "Env:$key")){Set-Item "Env:$key" $value}}}}
if($DataDirectory){$env:SENTRYGATE_DATA_DIR=[IO.Path]::GetFullPath($DataDirectory)}elseif(-not $env:SENTRYGATE_DATA_DIR){$env:SENTRYGATE_DATA_DIR=Join-Path $env:LOCALAPPDATA 'SentryGate\Data'}
if($DataDirectory -or -not $env:SENTRYGATE_DB_PATH){$env:SENTRYGATE_DB_PATH=Join-Path $env:SENTRYGATE_DATA_DIR 'sentrygate.db'}
$runtime=if($RuntimeDirectory){[IO.Path]::GetFullPath($RuntimeDirectory)}elseif($env:SENTRYGATE_RUNTIME_DIR){$env:SENTRYGATE_RUNTIME_DIR}else{Join-Path $env:LOCALAPPDATA 'SentryGate\Runtime'}
$env:SENTRYGATE_RUNTIME_DIR=$runtime;New-Item -ItemType Directory -Path $runtime -Force|Out-Null
if($LocalOnly){$env:NODE_ENV='development';$env:SENTRYGATE_STANDALONE='true';$env:SENTRYGATE_HOST='127.0.0.1';$env:SENTRYGATE_GATEWAY_HOST='127.0.0.1';$env:SENTRYGATE_PORT='4300';$env:SENTRYGATE_GATEWAY_PORT='4310';$env:SENTRYGATE_REMOTE_ACCESS_ENABLED='false';$env:SENTRYGATE_API_BASE_URL='http://127.0.0.1:4300';Remove-Item Env:SENTRYGATE_SESSION_SECRET -ErrorAction SilentlyContinue}
$runPort=$env:SENTRYGATE_PORT;if(-not $runPort){$runPort='4300'};$runHost=$env:SENTRYGATE_HOST;if(-not $runHost){$runHost='127.0.0.1'}
$runConfig=@{dataDirectory=$env:SENTRYGATE_DATA_DIR;databasePath=$env:SENTRYGATE_DB_PATH;apiPort=$runPort;apiHost=$runHost;tls=[bool]$env:SENTRYGATE_TLS_CERT}
[IO.File]::WriteAllText((Join-Path $runtime 'local-config.json'),($runConfig|ConvertTo-Json -Compress),[Text.Encoding]::UTF8)
$secretFile=Join-Path $runtime 'session-secret.dpapi'
if(-not $env:SENTRYGATE_SESSION_SECRET){
  if(Test-Path -LiteralPath $secretFile){$secure=Get-Content -LiteralPath $secretFile -Raw|ConvertTo-SecureString;$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure);try{$env:SENTRYGATE_SESSION_SECRET=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}}
  else{$env:SENTRYGATE_SESSION_SECRET=& $node -e "process.stdout.write(require('node:crypto').randomBytes(48).toString('base64url'))";$secure=ConvertTo-SecureString $env:SENTRYGATE_SESSION_SECRET -AsPlainText -Force;$protected=$secure|ConvertFrom-SecureString;[IO.File]::WriteAllText($secretFile,$protected,[Text.Encoding]::UTF8)}
}
$pidDir=Join-Path $runtime 'pids';New-Item -ItemType Directory -Path $pidDir -Force|Out-Null
$logDir=Join-Path $runtime 'logs';New-Item -ItemType Directory -Path $logDir -Force|Out-Null
$apiEntry=Join-Path $root 'apps\api\src\server.js';$workerEntry=Join-Path $root 'apps\api\scripts\analysis-worker.js'
$apiPidFile=Join-Path $pidDir 'api.pid';$workerPidFile=Join-Path $pidDir 'analysis.pid'
if(Test-Path $apiPidFile){
  $existingPid=0
  if([int]::TryParse((Get-Content -LiteralPath $apiPidFile -Raw),[ref]$existingPid)){
    $existing=Get-CimInstance Win32_Process -Filter "ProcessId=$existingPid" -ErrorAction SilentlyContinue
    if($existing -and $existing.CommandLine -like "*$apiEntry*"){
      $port=$env:SENTRYGATE_PORT;if(-not $port){$port='4300'};$scheme=if($env:SENTRYGATE_TLS_CERT){'https'}else{'http'}
      try{$health=Invoke-RestMethod "${scheme}://127.0.0.1:${port}/api/health" -TimeoutSec 2;if($health.ok){Write-Output 'SentryGate is already running.';return}}catch{}
    }
  }
  Remove-Item -LiteralPath $apiPidFile -Force -ErrorAction SilentlyContinue
}
$api=Start-Process -FilePath $node -ArgumentList @("`"$apiEntry`"") -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $logDir 'api.log') -RedirectStandardError (Join-Path $logDir 'api-error.log')
[IO.File]::WriteAllText($apiPidFile,[string]$api.Id)
$port=$env:SENTRYGATE_PORT;if(-not $port){$port='4300'};$scheme=if($env:SENTRYGATE_TLS_CERT){'https'}else{'http'};$healthUrl="${scheme}://127.0.0.1:$port/api/health"
$ready=$false;for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 500;if(-not(Get-Process -Id $api.Id -ErrorAction SilentlyContinue)){break};try{$health=Invoke-RestMethod $healthUrl -TimeoutSec 2;if($health.ok){$ready=$true;break}}catch{}}
if(-not $ready){try{Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue}catch{};throw "SentryGate API did not become healthy. Inspect $logDir\api-error.log"}
$worker=Start-Process -FilePath $node -ArgumentList @("`"$workerEntry`"") -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $logDir 'analysis.log') -RedirectStandardError (Join-Path $logDir 'analysis-error.log')
[IO.File]::WriteAllText($workerPidFile,[string]$worker.Id)
Write-Output "SentryGate API, website gateway, and local analysis worker started."
Write-Output "Dashboard: $($healthUrl -replace '/api/health','')"
Write-Output "Data: $env:SENTRYGATE_DATA_DIR"
