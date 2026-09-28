$ErrorActionPreference='Stop'
$runtime=if($env:SENTRYGATE_RUNTIME_DIR){$env:SENTRYGATE_RUNTIME_DIR}else{Join-Path $env:LOCALAPPDATA 'SentryGate\Runtime'};$pidDir=Join-Path $runtime 'pids'
foreach($name in @('analysis','api')){$file=Join-Path $pidDir "$name.pid";if(-not(Test-Path $file)){continue};$id=0;if(-not[int]::TryParse((Get-Content -LiteralPath $file -Raw),[ref]$id)){Remove-Item -LiteralPath $file -Force;continue};$proc=Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue;$expected=if($name -eq 'api'){'apps\api\src\server.js'}else{'apps\api\scripts\analysis-worker.js'}
  if($proc -and $proc.CommandLine -like "*$expected*"){
    try{$node=if(Test-Path (Join-Path $PSScriptRoot '..\runtime\node.exe')){Join-Path $PSScriptRoot '..\runtime\node.exe'}else{(Get-Command node.exe -ErrorAction Stop).Source};& $node -e "process.kill($id,'SIGTERM')";Start-Sleep -Milliseconds 800}catch{}
    $still=Get-Process -Id $id -ErrorAction SilentlyContinue;if($still){Stop-Process -Id $id -Force}
  }
  Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
}
Write-Output 'SentryGate API/gateway and analysis worker stopped.'
