param([bool]$CollectProcesses = $true, [bool]$CollectConnections = $true)
$ErrorActionPreference = 'Stop'
$processes = @()
$connections = @()
$collectionErrors = @()
if ($CollectProcesses) {
  try {
    $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ pid = [int]$_.ProcessId; parentPid = [int]$_.ParentProcessId; name = [string]$_.Name; startedAt = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null } }
    })
  } catch { $collectionErrors += 'Process metadata query unavailable.' }
}
if ($CollectConnections) {
  try {
    $connections = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ pid = [int]$_.OwningProcess; state = [string]$_.State; localAddress = [string]$_.LocalAddress; localPort = [int]$_.LocalPort; remoteAddress = [string]$_.RemoteAddress; remotePort = [int]$_.RemotePort; timestamp = [DateTime]::UtcNow.ToString('o') }
    })
  } catch { $collectionErrors += 'TCP connection metadata query unavailable.' }
}
@{ processes = $processes; connections = $connections; collectionErrors = $collectionErrors } | ConvertTo-Json -Depth 5 -Compress
