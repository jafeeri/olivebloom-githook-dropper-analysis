# Read-only host compromise assessment for the OliveBloom git-hook dropper. Changes nothing.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File hunt.ps1 [-Since "yyyy-MM-dd HH:mm"] > hunt_out.txt
# IOC strings are split ('wt'+'ech') so this script's own 4104 log entries never match them.
param([datetime]$Since = '2026-11-03 21:00')  # start of the exposure window
$ioc = ('wt'+'ech'), ('dt'+'ech'), ('aur'+'alyx'), ('66\.116\.'+'241'), ('olive'+'bloom'), ('timi'+'malik') -join '|'
function Sec($t) { "`n===== $t" }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
"Admin: $admin   Now: $(Get-Date)   Window: since $since"

Sec 'A1 Temp dirs: IOC names or new scripts/binaries since window'
foreach ($d in $env:TEMP, "$env:WINDIR\Temp") {
  Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue |
    ? { $_.Name -match $ioc -or ($_.LastWriteTime -gt $since -and $_.Extension -match '^\.(ps1|py|exe|dll|bat|cmd|vbs|js|hta|scr)$') } |
    Select FullName, Length, LastWriteTime | Format-Table -Auto | Out-String -Width 250
}

Sec 'A2 PowerShell/Operational since window: IOC hits'
$ps = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$since} -ErrorAction SilentlyContinue)
"total events: $($ps.Count)"
$ps | ? { $_.Message -match $ioc } | Select TimeCreated, Id, @{n='Msg';e={$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))}} | Format-List

Sec 'A3 Windows PowerShell 400: HostApplication with -File / Bypass / -enc since window'
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; Id=400; StartTime=$since} -ErrorAction SilentlyContinue |
  % { ($_.Message -split "`n" | ? { $_ -match 'HostApplication' }) -join '' } | ? { $_ -match "$ioc|Bypass|-File|-enc" } | Sort -Unique

Sec 'A4 Defender status + detections (last 3 days)'
try { Get-MpComputerStatus -ErrorAction Stop | Select AMServiceEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanEndTime | Format-List } catch { "MpComputerStatus: $($_.Exception.Message)" }
try { Get-MpThreatDetection -ErrorAction Stop | ? { $_.InitialDetectionTime -gt (Get-Date).AddDays(-3) } | Select InitialDetectionTime, ThreatID, Resources | Format-List } catch { "MpThreatDetection: $($_.Exception.Message)" }
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1006,1015,1116,1117,5001,5007; StartTime=$since} -ErrorAction SilentlyContinue | Select TimeCreated, Id, @{n='Msg';e={$_.Message.Substring(0,[Math]::Min(160,$_.Message.Length))}} | Format-Table -Auto -Wrap | Out-String -Width 250

Sec 'A5 Network: C2 IP in connections/DNS; external connections by process'
Get-NetTCPConnection -ErrorAction SilentlyContinue | ? RemoteAddress -match ('66\.116\.'+'241')
Get-DnsClientCache -ErrorAction SilentlyContinue | ? { $_.Data -match ('66\.116\.'+'241') }
"(blank above = no hits). Established external connections:"
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  ? { $_.RemoteAddress -notmatch '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80|0\.0\.0\.0)' } |
  Group-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path } | Sort Count -Desc |
  Select Count, Name, @{n='Remotes';e={($_.Group.RemoteAddress | Sort -Unique | Select -First 4) -join ', '}} | Format-Table -Auto -Wrap | Out-String -Width 250

Sec 'A6 Processes: IOC/encoded cmdlines, and anything running from user-writable dirs (with signature)'
$procs = Get-CimInstance Win32_Process
$procs | ? { $_.CommandLine -match "$ioc|-EncodedCommand|-enc |Bypass -File" } | Select ProcessId, ParentProcessId, Name, CommandLine | Format-List
$procs | ? { $_.ExecutablePath -match '\\AppData\\|\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\' } | Sort ExecutablePath -Unique |
  % { $s = Get-AuthenticodeSignature $_.ExecutablePath -ErrorAction SilentlyContinue
      [pscustomobject]@{Sig=$s.Status; Signer=($s.SignerCertificate.Subject -replace ',.*'); Path=$_.ExecutablePath} } | Sort Sig | Format-Table -Auto | Out-String -Width 250

Sec 'B1 Run / RunOnce / Policies Run / logon script'
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
  $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
  if ($p) { "-- $k"; $p.PSObject.Properties | ? { $_.Name -notmatch '^PS' } | % { "   {0} = {1}" -f $_.Name, $_.Value } }
}
"UserInitMprLogonScript = '$((Get-ItemProperty 'HKCU:\Environment' -ErrorAction SilentlyContinue).UserInitMprLogonScript)'"

Sec 'B2 Startup folders'
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force -ErrorAction SilentlyContinue | Select FullName, LastWriteTime | Format-Table -Auto

Sec 'B3 Scheduled tasks: new (3 days) or script/temp/appdata actions; Task Scheduler 106 registrations'
Get-ScheduledTask -ErrorAction SilentlyContinue | % {
  $a = ($_.Actions | % { "$($_.Execute) $($_.Arguments)" }) -join ' | '
  $d = $null; try { $d = [datetime]$_.Date } catch {}
  if (($d -and $d -gt (Get-Date).AddDays(-3)) -or $a -match "$ioc|powershell|wscript|cscript|mshta|\\Temp\\|AppData|python|curl") { [pscustomobject]@{Task="$($_.TaskPath)$($_.TaskName)"; Date=$d; Action=$a} }
} | Format-List
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106; StartTime=$since} -ErrorAction SilentlyContinue | Select TimeCreated, Message | Format-List

Sec 'B4 Services: user-writable paths/scripts; System 7045 installs since window'
Get-CimInstance Win32_Service | ? { $_.PathName -match '\\Users\\|\\Temp\\|AppData|powershell|\.ps1|python|curl' } | Select Name, State, StartMode, PathName | Format-List
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$since} -ErrorAction SilentlyContinue | Select TimeCreated, Message | Format-List

Sec 'B5 WMI subscriptions'
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select Name, Query | Format-List
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select Name, CommandLineTemplate | Format-List
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | Select Name, ScriptText | Format-List

Sec 'B6 IFEO, Winlogon, AppInit, LSA'
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | % { $v = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger; if ($v) { "IFEO $($_.PSChildName) Debugger = $v" } }
$w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue; "Winlogon Shell=$($w.Shell)  Userinit=$($w.Userinit)"
$ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue; "AppInit_DLLs='$($ai.AppInit_DLLs)' LoadAppInit=$($ai.LoadAppInit_DLLs)"
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue; "LSA Security Packages: $($lsa.'Security Packages' -join ',')  Auth: $($lsa.'Authentication Packages' -join ',')"

Sec 'B7 HKCU COM servers in user-writable paths'
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | % {
  foreach ($s in 'InprocServer32','LocalServer32') { $v = (Get-ItemProperty "$($_.PSPath)\$s" -ErrorAction SilentlyContinue).'(default)'; if ($v -match '\\Temp\\|\\Downloads\\|\\Public\\' -or ($v -and -not (Test-Path ($v -replace '"' -replace '\s+/.*$' -replace '\s+-.*$')))) { "$($_.PSChildName)\$s = $v" } }
}

Sec 'B8 PowerShell profiles'
foreach ($p in $PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost, "$HOME\Documents\PowerShell\profile.ps1", "$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1") { if (Test-Path $p) { "$p  (modified $((Get-Item $p).LastWriteTime))" } }

Sec 'B9 New exe/script/lnk in AppData/ProgramData/Public since window'
foreach ($d in $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, $env:PUBLIC) {
  Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue |
    ? { $_.CreationTime -gt $since -and $_.Extension -match '^\.(ps1|py|pyw|exe|dll|bat|cmd|vbs|js|jse|hta|scr|lnk|msi)$' -and $_.FullName -notmatch '\\Code Cache\\|\\Microsoft\\Windows\\Recent\\' } |
    Select FullName, Length, CreationTime | Format-Table -Auto | Out-String -Width 250
}

Sec 'B10 hosts file, proxy, browser extensions added since window, firewall rules for user-dir programs'
$h = Get-Item "$env:WINDIR\System32\drivers\etc\hosts"; "hosts modified $($h.LastWriteTime)"; Get-Content $h | ? { $_ -notmatch '^\s*(#|$)' }
$ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; "ProxyEnable=$($ie.ProxyEnable) ProxyServer='$($ie.ProxyServer)' AutoConfigURL='$($ie.AutoConfigURL)'"
foreach ($e in "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Extensions\*", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Extensions\*", "$env:APPDATA\Opera Software\*\Extensions\*", "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions\*") {
  Get-Item $e -ErrorAction SilentlyContinue | ? { $_.CreationTime -gt $since } | Select FullName, CreationTime
}
Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ? { $_.Program -match '\\Temp\\|\\Downloads\\|\\Users\\Public\\' } | Select Program

Sec 'C1 Downloads since window with Mark-of-the-Web source'
Get-ChildItem "$HOME\Downloads" -File -Force -ErrorAction SilentlyContinue | ? { $_.LastWriteTime -gt $since -or $_.CreationTime -gt $since } |
  % { $z = (Get-Content $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue) -match 'HostUrl|ReferrerUrl'; "$($_.Name)  $($_.CreationTime)  $($z -join ' ')" }

Sec 'C2 Recent .lnk since window'
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Force -ErrorAction SilentlyContinue | ? { $_.LastWriteTime -gt $since } |
  % { $t = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath; "$($_.LastWriteTime)  $($_.Name) -> $t" }

Sec 'C3 git global/system config'
git config --global --list 2>$null; git config --system --list 2>$null | ? { $_ -match 'hook|template|alias|sshcommand|credential' }

Sec 'C4 Recycle Bins'
Get-ChildItem 'A:\$Recycle.Bin','C:\$Recycle.Bin','S:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue | ? { $_.Name -match $ioc -or $_.Name -like '$I*' -and (Get-Content $_.FullName -Raw -Encoding Unicode -ErrorAction SilentlyContinue) -match $ioc } | Select FullName
"done $(Get-Date)"
