param([Parameter(Mandatory=$true)][string]$Source,[switch]$Confirm)
$ErrorActionPreference='Stop';if(-not $Confirm){throw 'Restore is destructive. Review the source backup, stop SentryGate, then pass -Confirm.'}
& (Join-Path $PSScriptRoot 'stop-sentrygate.ps1')
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path;Push-Location $root;$runtime=if($env:SENTRYGATE_RUNTIME_DIR){$env:SENTRYGATE_RUNTIME_DIR}else{Join-Path $env:LOCALAPPDATA 'SentryGate\Runtime'};$runConfigPath=Join-Path $runtime 'local-config.json';if(Test-Path $runConfigPath){$runConfig=Get-Content $runConfigPath -Raw|ConvertFrom-Json;$env:SENTRYGATE_DATA_DIR=$runConfig.dataDirectory;$env:SENTRYGATE_DB_PATH=$runConfig.databasePath};$node=if(Test-Path (Join-Path $root 'runtime\node.exe')){Join-Path $root 'runtime\node.exe'}else{(Get-Command node.exe -ErrorAction Stop).Source}
& $node (Join-Path $root 'apps\api\scripts\restore-db.js') '--source' ([IO.Path]::GetFullPath($Source)) '--confirm'
if($LASTEXITCODE -ne 0){Pop-Location;throw 'Local SentryGate restore failed; inspect the preserved database and restore output.'}
Pop-Location;& (Join-Path $PSScriptRoot 'start-sentrygate.ps1')
