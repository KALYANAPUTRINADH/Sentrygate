param([bool]$CollectProcesses = $true, [bool]$CollectConnections = $true, [bool]$CollectApplications = $true, [bool]$CollectServices = $true, [bool]$CollectStartup = $true, [bool]$CollectSecurity = $true)
$ErrorActionPreference = 'Stop'
$processes = @()
$connections = @()
$applications = @()
$services = @()
$startupEntries = @()
$securitySettings = @{ firewallProfiles = @(); defenderRealtimeProtection = $null; collectionNotes = @() }
$collectionErrors = @()
$stamp = [DateTime]::UtcNow.ToString('o')
function ConvertTo-Endpoint($value) {
  if ([string]$value -match '^\[(.+)\]:(\d+)$') { return @{ address=$Matches[1]; port=[int]$Matches[2] } }
  if ([string]$value -match '^(.+):(\d+)$') { return @{ address=$Matches[1]; port=[int]$Matches[2] } }
  return $null
}
if ($CollectProcesses) {
  try {
    $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ pid = [int]$_.ProcessId; parentPid = [int]$_.ParentProcessId; name = [string]$_.Name; executablePath = [string]$_.ExecutablePath; startedAt = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null } }
    })
  } catch {
    try {
      $processes = @(Get-Process -ErrorAction Stop | ForEach-Object {
        $exe = ''; $started = $null
        try { $exe = [string]$_.Path } catch { }
        try { $started = $_.StartTime.ToUniversalTime().ToString('o') } catch { }
        [pscustomobject]@{ pid=[int]$_.Id; parentPid=0; name=([string]$_.ProcessName + '.exe'); executablePath=$exe; startedAt=$started }
      })
      $securitySettings.collectionNotes += 'CIM process details were denied; process names and PIDs came from Get-Process, with parent PID or executable path omitted where unavailable.'
    } catch { $collectionErrors += 'Process metadata query unavailable.' }
  }
}
if ($CollectConnections) {
  try {
    $connections = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ pid = [int]$_.OwningProcess; state = [string]$_.State; localAddress = [string]$_.LocalAddress; localPort = [int]$_.LocalPort; remoteAddress = [string]$_.RemoteAddress; remotePort = [int]$_.RemotePort; timestamp = [DateTime]::UtcNow.ToString('o') }
    })
  } catch {
    try {
      $connections = @(netstat.exe -ano | ForEach-Object {
        $line = [string]$_
        if ($line -match '^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$') {
          $local = ConvertTo-Endpoint $Matches[1]; $remote = ConvertTo-Endpoint $Matches[2]
          if ($local) { [pscustomobject]@{ pid=[int]$Matches[4]; protocol='TCP'; state=$(if ($Matches[3] -eq 'LISTENING') {'Listen'} elseif ($Matches[3] -eq 'ESTABLISHED') {'Established'} else {$Matches[3]}); localAddress=$local.address; localPort=$local.port; remoteAddress=$(if ($remote) {$remote.address} else {''}); remotePort=$(if ($remote) {$remote.port} else {0}); timestamp=$stamp } }
        } elseif ($line -match '^\s*UDP\s+(\S+)\s+\S+\s+(\d+)\s*$') {
          $local = ConvertTo-Endpoint $Matches[1]
          if ($local) { [pscustomobject]@{ pid=[int]$Matches[2]; protocol='UDP'; state='Listen'; localAddress=$local.address; localPort=$local.port; remoteAddress=''; remotePort=0; timestamp=$stamp } }
        }
      })
      $securitySettings.collectionNotes += 'Get-NetTCPConnection was denied; TCP/UDP endpoints came from netstat. Per-connection process ownership may be incomplete for protected processes.'
    } catch { $collectionErrors += 'TCP connection metadata query unavailable.' }
  }
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
} catch {
  try {
    $services = @(Get-Service -ErrorAction Stop | ForEach-Object {
      $mode = 'Unknown'
      try { if ($_.StartType) { $mode = [string]$_.StartType } } catch { }
      [pscustomobject]@{ name=[string]$_.Name; displayName=[string]$_.DisplayName; state=[string]$_.Status; startMode=$mode; processId=0 }
    })
    $securitySettings.collectionNotes += 'CIM service metadata was denied; state and startup type came from Get-Service, with service PID omitted.'
  } catch { $collectionErrors += 'Windows service metadata query unavailable.' }
} }
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
} catch {
  try {
    $profile = ''
    foreach ($line in (netsh.exe advfirewall show allprofiles)) {
      if ([string]$line -match '^\s*(Domain|Private|Public) Profile Settings:') { $profile = $Matches[1]; continue }
      if ($profile -and [string]$line -match '^\s*State\s+(ON|OFF)\s*$') {
        $securitySettings.firewallProfiles += [pscustomobject]@{ name=$profile; enabled=($Matches[1] -eq 'ON') }
        $profile = ''
      }
    }
    if ($securitySettings.firewallProfiles.Count -gt 0) { $securitySettings.collectionNotes += 'Firewall profile status came from read-only netsh output because the NetSecurity cmdlet was denied.' }
    else { $securitySettings.collectionNotes += 'Windows Firewall profile status could not be parsed from netsh output.' }
  } catch { $securitySettings.collectionNotes += 'Windows Firewall profile status could not be queried.' }
}
try {
  $defender = Get-MpComputerStatus -ErrorAction Stop
  $securitySettings.defenderRealtimeProtection = [bool]$defender.RealTimeProtectionEnabled
} catch { $securitySettings.collectionNotes += 'Microsoft Defender real-time status unavailable to this agent identity; the value is unknown, not treated as disabled.' } }
@{ processes = $processes; connections = $connections; installedApplications=$applications; services=$services; startupEntries=$startupEntries; securitySettings=$securitySettings; collectionErrors = $collectionErrors } | ConvertTo-Json -Depth 5 -Compress
