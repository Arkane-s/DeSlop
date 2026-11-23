$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms

$stdin  = [Console]::OpenStandardInput()
$stdout = [Console]::OpenStandardOutput()
$script:mpCmd = $null
$activeDrops = @{}
$perFileLimit = 10000

function Read-Msg {
  $lenBuf = New-Object byte[] 4
  if ($stdin.Read($lenBuf, 0, 4) -lt 4) { return $null }
  $len = [BitConverter]::ToInt32($lenBuf, 0)
  $buf = New-Object byte[] $len
  $got = 0
  while ($got -lt $len) { $got += $stdin.Read($buf, $got, $len - $got) }
  [Text.Encoding]::UTF8.GetString($buf) | ConvertFrom-Json
}

function Send-Msg($obj) {
  $bytes = [Text.Encoding]::UTF8.GetBytes(($obj | ConvertTo-Json -Compress -Depth 5))
  $stdout.Write([BitConverter]::GetBytes([int]$bytes.Length), 0, 4)
  $stdout.Write($bytes, 0, $bytes.Length)
  $stdout.Flush()
}

function Send-Error([string]$text) {
  Send-Msg @{ ok = $false; error = $text }
}

function Send-Threat([string]$name) {
  Send-Msg @{ ok = $true; threat = $true; threats = @($name) }
}

function Send-Verdict($r, $extra = @{}) {
  if ($r.code -eq 0) { Send-Msg (@{ ok = $true; threat = $false } + $extra) }
  elseif ($r.code -eq 2) { Send-Msg (@{ ok = $true; threat = $true; threats = $r.names } + $extra) }
  else { Send-Error "Defender exited with code $($r.code)" }
}

function Get-MpCmd {
  $best = $null
  $bestV = [version]'0.0.0.0'
  foreach ($f in Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue) {
    $v = $null
    if ([version]::TryParse($f.Directory.Name.Split('-')[0], [ref]$v) -and $v -gt $bestV) { $best = $f.FullName; $bestV = $v }
  }
  if ($best) { return $best }
  "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
}

function Invoke-Scan([string]$path) {
  if (-not $script:mpCmd) { $script:mpCmd = Get-MpCmd }
  $text = & $script:mpCmd -Scan -ScanType 3 -File $path -DisableRemediation 2>&1 | Out-String
  $code = $LASTEXITCODE
  $names = @([regex]::Matches($text, '(?im)^\s*Threat\s*:\s*(.+?)\s*$') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
  @{ code = $code; names = $names }
}

function Get-FileSize([string]$path) {
  try { (Get-Item -LiteralPath $path -Force).Length } catch { $null }
}

function Get-SafeName([string]$name, [string]$fallback) {
  foreach ($c in [IO.Path]::GetInvalidFileNameChars()) { $name = $name.Replace([string]$c, '_') }
  if (-not $name -or $name -eq '.' -or $name -eq '..') { return $fallback }
  $name
}

function Lock-Folder([string]$dir) {
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($me, 'ExecuteFile', 'ObjectInherit', 'InheritOnly', 'Deny')
  $acl = Get-Acl -LiteralPath $dir
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $dir -AclObject $acl
}

function Remove-Drop([string]$dir) {
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  $activeDrops.Remove($dir)
}

function Save-Url([string]$url, [string]$dir, [long]$max) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $req = [Net.HttpWebRequest]::Create($url)
  $req.UserAgent = 'Mozilla/5.0'
  $req.Timeout = 30000
  $resp = $req.GetResponse()
  try {
    $name = $null
    $cd = $resp.Headers['Content-Disposition']
    if ($cd -match 'filename\*?=(?:UTF-8'''')?"?([^";]+)') { $name = [Uri]::UnescapeDataString($Matches[1]) }
    if (-not $name) { $name = [Uri]::UnescapeDataString($resp.ResponseUri.Segments[-1]).Trim('/') }
    $dest = Join-Path $dir (Get-SafeName $name 'download.bin')
    $in = $resp.GetResponseStream()
    $fs = [IO.File]::Create($dest)
    try {
      $buf = New-Object byte[] 81920
      $total = 0
      while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) {
        $total += $n
        if ($total -gt $max) { throw 'File is larger than the 1 GB limit' }
        $fs.Write($buf, 0, $n)
      }
    } finally { $fs.Dispose(); $in.Dispose() }
    return $dest
  } finally { $resp.Dispose() }
}

function Save-Clean([string]$file, [string]$name, [string]$url) {
  $dl = Join-Path (Join-Path $env:USERPROFILE 'Downloads') 'Scanned by Defender'
  if (-not (Test-Path -LiteralPath $dl)) { New-Item -ItemType Directory -Path $dl -Force | Out-Null }
  $target = Join-Path $dl $name
  $i = 1
  while (Test-Path -LiteralPath $target) {
    $target = Join-Path $dl ([IO.Path]::GetFileNameWithoutExtension($name) + " ($i)" + [IO.Path]::GetExtension($name))
    $i++
  }
  Move-Item -LiteralPath $file -Destination $target
  & icacls.exe $target /reset 2>&1 | Out-Null
  Set-Content -LiteralPath $target -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=$url"
  $target
}

function Select-Files {
  $d = New-Object Windows.Forms.OpenFileDialog
  $d.Multiselect = $true
  $d.Title = 'Choose files to scan with Defender'
  $owner = New-Object Windows.Forms.Form -Property @{ TopMost = $true }
  if ($d.ShowDialog($owner) -eq 'OK') { return @($d.FileNames) }
  @()
}

function Select-Folder {
  $d = New-Object Windows.Forms.FolderBrowserDialog
  $d.Description = 'Choose a folder'
  $d.ShowNewFolderButton = $false
  $owner = New-Object Windows.Forms.Form -Property @{ TopMost = $true }
  if ($d.ShowDialog($owner) -eq 'OK') { return $d.SelectedPath }
  ''
}

while ($msg = Read-Msg) {
  try {
    switch ($msg.action) {
      'status' {
        try {
          $s = Get-MpComputerStatus
          Send-Msg @{ ok = $true; antivirus = [bool]$s.AntivirusEnabled; realtime = [bool]$s.RealTimeProtectionEnabled;
                      signatures = $s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd') }
        }
        catch {
          $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
          if ($svc -and $svc.Status -eq 'Running' -and (Test-Path -LiteralPath (Get-MpCmd))) {
            Send-Msg @{ ok = $true; antivirus = $true; limited = $true }
          }
          else { throw }
        }
      }
      'pick' {
        Send-Msg @{ ok = $true; paths = @(Select-Files) }
      }
      'pickfolder' {
        Send-Msg @{ ok = $true; path = Select-Folder }
      }
      'scan' {
        $path = [string]$msg.path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Send-Error 'File not found'; continue }
        $size = Get-FileSize $path
        Send-Verdict (Invoke-Scan $path) @{ size = $size }
      }
      'scanfolder' {
        $path = [string]$msg.path
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { Send-Error 'Folder not found'; continue }
        $files = @(Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue)
        $total = $files.Count
        $bytes = [long](($files | Measure-Object -Property Length -Sum).Sum)
        if ($total -gt $perFileLimit) {
          Send-Msg @{ progress = $true; done = 0; total = $total; whole = $true }
          Send-Verdict (Invoke-Scan $path) @{ infected = 0; files = @(); scanned = $total; failed = 0; total = $total; bytes = $bytes }
        }
        else {
          $done = 0
          $failed = 0
          $names = @()
          $bad = @()
          Send-Msg @{ progress = $true; done = 0; total = $total }
          foreach ($f in $files) {
            $r = Invoke-Scan $f.FullName
            if ($r.code -eq 2) { $bad += $f.FullName; $names += $r.names }
            elseif ($r.code -ne 0) { $failed++ }
            $done++
            Send-Msg @{ progress = $true; done = $done; total = $total }
          }
          Send-Msg @{ ok = $true; threat = ($bad.Count -gt 0); threats = @($names | Select-Object -Unique); infected = $bad.Count; files = @($bad | Select-Object -First 20); scanned = $done; failed = $failed; total = $total; bytes = $bytes }
        }
      }
      'newfiles' {
        $path = [string]$msg.path
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { Send-Error 'Folder not found'; continue }
        $epoch = New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
        $since = $epoch.AddMilliseconds([double]$msg.since)
        $cutoff = (Get-Date).ToUniversalTime().AddSeconds(-5)
        $untilMs = [long](($cutoff - $epoch).TotalMilliseconds)
        $skip = '\.(crdownload|part|partial|tmp|download)$'
        $search = @{ LiteralPath = $path; File = $true; Force = $true; ErrorAction = 'SilentlyContinue' }
        if ($msg.recurse) { $search.Recurse = $true }
        $cands = @()
        foreach ($f in Get-ChildItem @search) {
          $t = $f.LastWriteTimeUtc
          if ($f.CreationTimeUtc -gt $t) { $t = $f.CreationTimeUtc }
          if ($t -le $since -or $t -gt $cutoff) { continue }
          if ($f.Name -match $skip) { continue }
          $cands += [pscustomobject]@{ path = $f.FullName; t = $t }
        }
        $cands = @($cands | Sort-Object t)
        if ($cands.Count -gt 200) {
          $cands = @($cands[0..199])
          $untilMs = [long](($cands[199].t - $epoch).TotalMilliseconds)
        }
        Send-Msg @{ ok = $true; files = @($cands | ForEach-Object { $_.path }); until = $untilMs }
      }
      'cancel' {
        $target = [string]$msg.path
        $killed = 0
        if ($target) {
          foreach ($proc in @(Get-CimInstance Win32_Process -Filter "Name = 'MpCmdRun.exe'" -ErrorAction SilentlyContinue)) {
            if ($proc.CommandLine -and $proc.CommandLine.IndexOf($target, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
              try { Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop; $killed++ } catch { }
            }
          }
        }
        Send-Msg @{ ok = $true; killed = $killed }
      }
      'reveal' {
        $target = [string]$msg.path
        if ($target -and (Test-Path -LiteralPath $target -PathType Leaf)) {
          Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"' + $target + '"')
        }
        elseif ($target -and (Test-Path -LiteralPath $target -PathType Container)) {
          Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $target + '"')
        }
        elseif ($target) {
          $parent = Split-Path -LiteralPath $target -Parent
          if ($parent -and (Test-Path -LiteralPath $parent -PathType Container)) {
            Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $parent + '"')
          }
        }
        Send-Msg @{ ok = $true }
      }
      'dropchunk' {
        $id = [string]$msg.id
        if ($id -notmatch '^[0-9a-fA-F-]{36}$') { Send-Error 'Bad upload id'; continue }

        $dir = Join-Path $env:TEMP ('DefenderQuickScan\drop-' + $id)
        $name = Get-SafeName ([IO.Path]::GetFileName([string]$msg.name)) 'dropped.bin'
        $file = Join-Path $dir $name
        $index = [int]$msg.index
        $keepDir = $false
        try {
          if ($index -eq 0) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try { Lock-Folder $dir } catch { }
            $activeDrops[$dir] = $true
          }
          if (-not $activeDrops.ContainsKey($dir)) {
            Send-Error 'Upload was not started'
          }
          elseif ($index -gt 0 -and -not (Test-Path -LiteralPath $file)) {
            Send-Threat 'Removed by real-time protection while the file was being added'
          }
          else {
            $wrote = $true
            try {
              $bytes = [Convert]::FromBase64String([string]$msg.data)
              $fs = [IO.File]::Open($file, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
              try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            } catch {
              if ($_.Exception.Message -match 'virus|unwanted') { $wrote = $false } else { throw }
            }
            if (-not $wrote) {
              Send-Threat 'Blocked by real-time protection while the file was being added'
            }
            elseif (-not $msg.last) {
              Send-Msg @{ ok = $true; more = $true }
              $keepDir = $true
            }
            elseif (-not (Test-Path -LiteralPath $file)) {
              Send-Threat 'Removed by real-time protection while the file was being added'
            }
            else {
              $size = Get-FileSize $file
              Send-Verdict (Invoke-Scan $file) @{ name = $name; size = $size }
            }
          }
        } finally {
          if (-not $keepDir) { Remove-Drop $dir }
        }
      }
      'scanurl' {
        $url = [string]$msg.url
        if ($url -notmatch '^https?://') { Send-Error 'Only http:// and https:// links are supported'; continue }

        $tmp = Join-Path $env:TEMP ('DefenderQuickScan\' + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $locked = $false
        try { Lock-Folder $tmp; $locked = $true } catch { }
        try {
          $file = Save-Url $url $tmp 1073741824
          if (-not (Test-Path -LiteralPath $file)) {
            Send-Threat 'Removed by real-time protection as it was downloaded'
            continue
          }
          $name = Split-Path $file -Leaf
          $size = Get-FileSize $file
          $r = Invoke-Scan $file
          $kept = $null
          if ($r.code -eq 0 -and $msg.keep) { $kept = Save-Clean $file $name $url }
          Send-Verdict $r @{ name = $name; size = $size; kept = $kept; locked = $locked }
        } finally {
          Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
      }
      default { Send-Error 'Unknown action' }
    }
  } catch {
    Send-Error $_.Exception.Message
  }
}

foreach ($d in @($activeDrops.Keys)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }