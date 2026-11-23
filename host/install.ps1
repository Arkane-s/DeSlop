param([string]$ExtensionId)
if (-not $ExtensionId) { $ExtensionId = Read-Host 'Paste the extension ID (shown on chrome://extensions or edge://extensions)' }
$ExtensionId = $ExtensionId.Trim()
$dir = $PSScriptRoot
$manifest = @{
  name = 'com.defender.scan'
  description = 'Defender Quick Scan bridge'
  path = "$dir\host.bat"
  type = 'stdio'
  allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json
[IO.File]::WriteAllText("$dir\com.defender.scan.json", $manifest, (New-Object Text.UTF8Encoding($false)))
$roots = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts',
         'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts',
         'HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts'
foreach ($r in $roots) {
  $k = "$r\com.defender.scan"
  New-Item -Path $k -Force | Out-Null
  Set-ItemProperty -Path $k -Name '(default)' -Value "$dir\com.defender.scan.json"
}
Write-Host 'Done. Fully restart your browser, then open the extension.'
