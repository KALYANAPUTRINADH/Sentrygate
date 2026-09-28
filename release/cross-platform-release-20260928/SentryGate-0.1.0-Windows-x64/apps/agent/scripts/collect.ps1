param([bool]$CollectProcesses = $true, [bool]$CollectConnections = $true, [bool]$CollectApplications = $true, [bool]$CollectServices = $true, [bool]$CollectStartup = $true, [bool]$CollectSecurity = $true)
$ErrorActionPreference = 'Stop'
$processes = @()
$connections = @()
$applications = @()
$services = @()
$startupEntries = @()
$securitySettings = @{ firewallProfiles = @(); defenderRealtimeProtection = $null; collectionNotes = @() }
$collectionErrors = @()
if ($CollectProcesses) {
  try {
    $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ pid = [int]$_.ProcessId; parentPid = [int]$_.ParentProcessId; name = [string]$_.Name; executablePath = [string]$_.ExecutablePath; startedAt = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null } }
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
if ($CollectApplications) { try {
  $uninstallKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  $applications = @($uninstallKeys | ForEach-Object { Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue } |
    Where-Object { $_.DisplayName } | Select-Object -First 5000 | ForEach-Object {
      [pscustomobject]@{ name=[string]$_.DisplayName; version=[string]$_.DisplayVersion; publisher=[string]$_.Publisher; installLocation=[string]$_.InstallLocation; installDate=[string]$_.InstallDate }
    })
} catch { $collectionErrors += 'Installed application metadata query unavailable.' } }
if ($CollectServices) { try {
  $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ name=[string]$_.Name; displayName=[string]$_.DisplayName; state=[string]$_.State; startMode=[string]$_.StartMode; processId=[int]$_.ProcessId }
  })
} catch { $collectionErrors += 'Windows service metadata query unavailable.' } }
if ($CollectStartup) { try {
  $runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
  )
  foreach ($key in $runKeys) {
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($props) { foreach ($entry in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
      $raw = [string]$entry.Value
      $exe = if ($raw -match '^\s*"([^"]+\.exe)') { $Matches[1] } elseif ($raw -match '^\s*([^\s]+\.exe)') { $Matches[1] } else { '' }
      $startupEntries += [pscustomobject]@{ name=[string]$entry.Name; executablePath=$exe; source=$key }
    } }
  }
  foreach ($folder in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))) {
    if ($folder -and (Test-Path -LiteralPath $folder)) { Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
      $startupEntries += [pscustomobject]@{ name=$_.Name; executablePath=$_.FullName; source='Startup folder' }
    } }
  }
} catch { $collectionErrors += 'Startup entry metadata query unavailable.' } }
if ($CollectSecurity) { try {
  $securitySettings.firewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled | ForEach-Object {
    [pscustomobject]@{ name=[string]$_.Name; enabled=[bool]$_.Enabled }
  })
} catch { $securitySettings.collectionNotes += 'Windows Firewall profile status could not be queried.' }
try {
  $defender = Get-MpComputerStatus -ErrorAction Stop
  $securitySettings.defenderRealtimeProtection = [bool]$defender.RealTimeProtectionEnabled
} catch { $securitySettings.collectionNotes += 'Microsoft Defender real-time status unavailable or not applicable.' } }
@{ processes = $processes; connections = $connections; installedApplications=$applications; services=$services; startupEntries=$startupEntries; securitySettings=$securitySettings; collectionErrors = $collectionErrors } | ConvertTo-Json -Depth 5 -Compress
