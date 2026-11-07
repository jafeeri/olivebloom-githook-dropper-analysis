# Elevated, read-only part of the host assessment: Prefetch + Security log. Changes nothing. Run as Administrator.
param([datetime]$Since = '2026-11-03 21:00')
$out = Join-Path $PSScriptRoot 'hunt_admin_out.txt'
& {
  "Now: $(Get-Date)  Admin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators'))"
  "`n===== P1 Prefetch: interpreters/downloaders run since window (LastWriteTime = last run)"
  Get-ChildItem "$env:WINDIR\Prefetch" -ErrorAction SilentlyContinue |
    ? { $_.Name -match '^(POWERSHELL|PWSH|CURL|SH\.EXE|BASH|PYTHON|GIT|WSCRIPT|CSCRIPT|MSHTA|RUNDLL32|REGSVR32|BITSADMIN|CERTUTIL)' -and $_.LastWriteTime -gt $since } |
    Sort LastWriteTime | Select Name, LastWriteTime | Format-Table -Auto | Out-String -Width 200
  "`n===== P2 Prefetch: any NEW program first seen since window"
  Get-ChildItem "$env:WINDIR\Prefetch" -Filter *.pf -ErrorAction SilentlyContinue | ? { $_.CreationTime -gt $since } | Sort CreationTime | Select Name, CreationTime | Format-Table -Auto | Out-String -Width 200
  "`n===== S1 Security 4688 process creation since window (if auditing on) matching curl/powershell -File"
  $e = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$since} -ErrorAction SilentlyContinue)
  "4688 events: $($e.Count)"
  $e | ? { $_.Message -match ('wt'+'ech|aur'+'alyx|66\.116\.'+'241|Bypass -File') } | Select TimeCreated, @{n='M';e={$_.Message.Substring(0,300)}} | Format-List
  "`n===== S2 Security 4698 scheduled task created / 4720 user created / 4732 group add since window"
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698,4720,4732; StartTime=$since} -ErrorAction SilentlyContinue | Select TimeCreated, Id, @{n='M';e={$_.Message.Substring(0,200)}} | Format-List
  "done $(Get-Date)"
} *> $out
