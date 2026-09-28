param([Parameter(Mandatory=$true)][ValidateSet('Start','Status','Restart','Stop')][string]$Action)
$ErrorActionPreference = 'Stop'
$name = 'SentryGateAgent'
$service = Get-Service -Name $name -ErrorAction Stop
switch ($Action) {
  'Start' { Start-Service -Name $name; (Get-Service -Name $name).WaitForStatus('Running',[TimeSpan]::FromSeconds(20)) }
  'Stop' { Stop-Service -Name $name; (Get-Service -Name $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20)) }
  'Restart' { Restart-Service -Name $name -Force; (Get-Service -Name $name).WaitForStatus('Running',[TimeSpan]::FromSeconds(30)) }
}
$service = Get-Service -Name $name
$startMode = (Get-CimInstance Win32_Service -Filter "Name='$name'").StartMode
[pscustomobject]@{ Name=$service.Name; Status=$service.Status.ToString(); StartMode=$startMode; LogPath="$env:ProgramData\SentryGate\Agent\logs\service.log" } | Format-List
if (Test-Path "$env:ProgramData\SentryGate\Agent\logs\service.log") { Get-Content "$env:ProgramData\SentryGate\Agent\logs\service.log" -Tail 20 }
