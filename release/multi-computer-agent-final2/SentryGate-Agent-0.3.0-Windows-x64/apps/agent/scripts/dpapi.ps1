param([Parameter(Mandatory=$true)][ValidateSet('Protect','Unprotect')][string]$Action, [ValidateSet('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$inputText = [Console]::In.ReadToEnd()
if ($Action -eq 'Protect') {
  $bytes = [Text.Encoding]::UTF8.GetBytes($inputText)
  $protectionScope = [Security.Cryptography.DataProtectionScope]::$Scope
  $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, $protectionScope)
  [Console]::Out.Write([Convert]::ToBase64String($protected))
} else {
  $protected = [Convert]::FromBase64String($inputText.Trim())
  $protectionScope = [Security.Cryptography.DataProtectionScope]::$Scope
  $plain = [Security.Cryptography.ProtectedData]::Unprotect($protected, $null, $protectionScope)
  [Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain))
}
