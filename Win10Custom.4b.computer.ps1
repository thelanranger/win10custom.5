#### Win10Custom.ps1 v .4b
#### Computer Configuration
#### Written by TheLANRanger
#### 
#### Goal is to script as many basic default changes to Windows 10 desktop as possible to save clicks!
#### Should be partnered with Win10Custom.4b.User.ps1
#### Contains RenVSS.bat for single click ease. This maybe eliminated later on. 

#### ========================
#### Self Elevate
#### ------------------------
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
#### ========================


#### ========================
#### Check if the script was started with Administrator privileges.
#### ------------------------
#Requires -RunAsAdministrator
#### ========================

#### ========================
#### Create a System restore point before we break a bunch of stuff.
#### ------------------------
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 0 /f
Enable-ComputerRestore -Drive "C:\"
Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint --% "%DATE%", 100, 1
#### ========================

#### ========================
#### Enable Registry Backup (Disabled post 10 1803)
#### ------------------------
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup /t REG_DWORD /d 00000001 /f
#### ========================

#### ========================
#### Enable Volume Shadow Copy for local Disks and create schedule tasks
#### NOTE: There must be a VSS-Task-Disk task for partition (drive letter) on your system! Modify accordingly!
#### ------------------------
cmd /c "sc config vss start= auto"
cmd /c "sc start vss"

Register-ScheduledTask -TaskName "VSS-Task-Daily" -Trigger (New-ScheduledTaskTrigger -At 10:00pm -Daily) -User "NT AUTHORITY\SYSTEM" -Action (New-ScheduledTaskAction -Execute "$env:windir\System32\wbem\WMIC.exe" -Argument "/Namespace:\\root\default Path SystemRestore Call CreateRestorePoint ""SystemRestore-%Date%"", 100, 7") -RunLevel Highest -Force
Register-ScheduledTask -TaskName "VSS-Task-Daily-C" -Trigger (New-ScheduledTaskTrigger -At 10:05pm -Daily) -User "NT AUTHORITY\SYSTEM" -Action (New-ScheduledTaskAction -Execute "$env:windir\System32\wbem\WMIC.exe" -Argument "shadowcopy call create Volume=""C:\""" ) -RunLevel Highest -Force
#### Register-ScheduledTask -TaskName "VSS-Task-Daily-D" -Trigger (New-ScheduledTaskTrigger -At 10:05pm -Daily) -User "NT AUTHORITY\SYSTEM" -Action (New-ScheduledTaskAction -Execute "$env:windir\System32\wbem\WMIC.exe" -Argument "shadowcopy call create Volume=""D:\""" ) -RunLevel Highest -Force

Start-ScheduledTask "VSS-Task-Daily"
Start-ScheduledTask "VSS-Task-Daily-C"
#### Start-ScheduledTask "VSS-Task-Daily-D"
#### ========================

#### ========================
#### RenVSSadmin (RenVSS1.3.ps1 Starts here)
#### See https://github.com/thelanranger/renvss
#### ------------------------

#### Format date for file rename
$date = Get-Date -format "yyyyMMdd"

if (Test-Path $env:windir\system32\vssadmin.exe)  {
  #### We need to give the Administrators ownership before we can change permissions on the file
  takeown /F $env:windir\system32\vssadmin.exe /A
  #### Give Administrators the Change permissions for the file
  icacls $env:windir\system32\vssadmin.exe /grant Administrators:F
  #### Rename vssadmin.exe to the filename in the RenFile variable
  ren $env:windir\system32\vssadmin.exe $env:windir\system32\vssadmin.exe-$date

  #### Check rename:
     if (Test-Path $env:windir\system32\vssadmin.exe-$date) {
      echo "system32\vssadmin.exe has been successfully renamed"
      echo "to $env:windir\system32\vssadmin.exe-$date."
     }
}

if (Test-Path $env:windir\SysWOW64\vssadmin.exe)  {
  #### We need to give the Administrators ownership before we can change permissions on the file
  takeown /F $env:windir\SysWOW64\vssadmin.exe /A
  #### Give Administrators the Change permissions for the file
  icacls $env:windir\SysWOW64\vssadmin.exe /grant Administrators:F
  #### Rename vssadmin.exe to the filename in the RenFile variable
  ren $env:windir\SysWOW64\vssadmin.exe $env:windir\SysWOW64\vssadmin.exe-$date

  #### Check rename:
     if (Test-Path $env:windir\SysWOW64\vssadmin.exe-$date) {
      echo "SysWOW64\vssadmin.exe has been successfully renamed "
      echo "to $env:windir\SysWOW64\vssadmin.exe-$date."
     } 
}
#### =======================



#### ========================
#### Customize Windows 10 begin
#### ------------------------

#### Change updates to Semi Annual Channel: 16 = Semi-Annual Channel (Targeted), 32 = Semi-Annual Channel, Absent or other = All
#### *Note: Based upon documentation and the internet, I suspect that starting at 10 you are on targeted and the higher the number the more frequent the updates.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v BranchReadinessLevel /t REG_DWORD /d 00000010 /f

#### Data Collection (This is enterprise level settings!):
#### Disable Feedback and Diagnostics: Creates 'AllowTelemetry'. 0 = Security (Enterprise and Education editions only), 1 = Basic, 2 = Enhanced, 3 = Full (Recommended)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 00000000 /f
#### Disable Connected User Experience and Telemetry Service:
cmd /c "sc stop diagtrack"
cmd /c "sc config diagtrack start= disabled"


#### Set Time Zone to EST
tzutil /s "Eastern Standard Time"
#### Set power settings to 'High Performance'
POWERCFG -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
POWERCFG -X -disk-timeout-ac 0
POWERCFG -X -disk-timeout-dc 0
POWERCFG -H OFF
#### ========================
