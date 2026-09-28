param([Parameter(Mandatory=$true)][string]$OutputFile)
$ErrorActionPreference='Stop';$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path;Push-Location $root
$runtime=if($env:SENTRYGATE_RUNTIME_DIR){$env:SENTRYGATE_RUNTIME_DIR}else{Join-Path $env:LOCALAPPDATA 'SentryGate\Runtime'};$runConfigPath=Join-Path $runtime 'local-config.json';if(Test-Path $runConfigPath){$runConfig=Get-Content $runConfigPath -Raw|ConvertFrom-Json;$env:SENTRYGATE_DATA_DIR=$runConfig.dataDirectory;$env:SENTRYGATE_DB_PATH=$runConfig.databasePath}
$output=[IO.Path]::GetFullPath($OutputFile);if($output.StartsWith('\\')){throw 'Backups must be written to a local filesystem path.'}
$node=if(Test-Path (Join-Path $root 'runtime\node.exe')){Join-Path $root 'runtime\node.exe'}else{(Get-Command node.exe -ErrorAction Stop).Source}
& $node (Join-Path $root 'apps\api\scripts\backup-db.js') '--out' $output
if($LASTEXITCODE -ne 0){throw 'Local SentryGate backup failed.'}
Pop-Location
