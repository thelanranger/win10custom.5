
#### Win10Custom.ps1 v .5b
#### Computer Configuration
#### Written by TheLANRanger
#### 
#### Goal is to script as many basic default changes to Windows 10 desktop as possible to save clicks!

#### ========================
#### Create a System restore point before we break a bunch of stuff.
#### ------------------------
function Create-SystemRestore
{
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 0 /f
	Enable-ComputerRestore -Drive "C:\"
	Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint --% "%DATE%", 100, 1
}
#### ========================

#### ========================
#### Enable Registry Backup (Disabled post 10 1803)
#### ------------------------
function Enable-RegBackup
{
	reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup /t REG_DWORD /d 00000001 /f
}
#### ========================

#### ========================
#### Enable Volume Shadow Copy for local Disks and create schedule tasks
#### NOTE: There must be a VSS-Task-Disk task for partition (drive letter) on your system! Modify accordingly!
#### *Add variables for disks*
#### ------------------------
function VSS-Create
{
	cmd /c "sc config vss start= auto"
	cmd /c "sc start vss"

	Register-ScheduledTask -TaskName "VSS-Task-Daily" -Trigger (New-ScheduledTaskTrigger -At 10:00pm -Daily) -User "NT AUTHORITY\SYSTEM" -Action (New-ScheduledTaskAction -Execute "$env:windir\System32\wbem\WMIC.exe" -Argument "/Namespace:\\root\default Path SystemRestore Call CreateRestorePoint ""SystemRestore-%Date%"", 100, 7") -RunLevel Highest -Force
	Register-ScheduledTask -TaskName "VSS-Task-Daily-C" -Trigger (New-ScheduledTaskTrigger -At 10:05pm -Daily) -User "NT AUTHORITY\SYSTEM" -Action (New-ScheduledTaskAction -Execute "$env:windir\System32\wbem\WMIC.exe" -Argument "shadowcopy call create Volume=""C:\""" ) -RunLevel Highest -Force
	#### Register-ScheduledTask -TaskName "VSS-Task-Daily-D" -Trigger (New-ScheduledTaskTrigger -At 10:05pm -Daily) -User "NT AUTHORITY\SYSTEM" -Action (New-ScheduledTaskAction -Execute "$env:windir\System32\wbem\WMIC.exe" -Argument "shadowcopy call create Volume=""D:\""" ) -RunLevel Highest -Force

	Start-ScheduledTask "VSS-Task-Daily"
	Start-ScheduledTask "VSS-Task-Daily-C"
	#### Start-ScheduledTask "VSS-Task-Daily-D"
}
#### ========================

#### ========================
#### RenVSSadmin (RenVSS1.3.ps1 Starts here)
#### Idea stolen from bleepingcomputer.com Converted to powershell for here and expanded.
#### ------------------------
function RenVSS
{
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
}
#### =======================

#### ========================
#### Customize Windows 10 begin
#### ------------------------
function Win10-Custom-LM
{
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
}
#### ========================

#### ========================
#### Customize Windows 10 begin
#### ------------------------
function Win10-Custom-CU
{
    #### Shrink Search box to button: 0 = Hidden, 1 = Show search or Cortana icon, 2 = Show search box
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 00000001 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCortanaButton /t REG_DWORD /d 00000000 /f
    #### Combine Taskbar Buttons: 0 = Always combine, hide labels, 1 = Combine when taskbar is full, 2 = Never combine
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarGlomLevel /t REG_DWORD /d 00000002 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v MMTaskbarGlomLevel /t REG_DWORD /d 00000002 /f
    #### Always show all icons in notification area: 0 = Show all, 1 = Show none
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /d 00000000 /f
    #### Display Full Path in Title Bar area: 0 = Off, 1 = On
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v FullPath /t REG_DWORD /d 00000001 /f
    #### Display Filename Extensions: 0 = Show, 1 = Off
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced " /v HideFileExt /t REG_DWORD /d 00000000 /f
    #### Expand Ribbon in Explorer: 0 = Open, 1 = Close
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v MinimizedStateTabletModeOff /t REG_DWORD /d 00000000 /f
    #### Expand Copy Window to Full: 0 = Closed, 1 = Open
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 00000001 /f
    #### "Get tips, tricks, and suggestions as you use Windows": 0 = Off, 1 = On
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 00000000 /f
    #### App Suggestions on Start: 0 = Off, 1 = On
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 00000000 /f
    #### Hide People button from Taskbar: 0 = Off, 1 = On
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v People /t REG_DWORD /d 00000000 /f

    #### Set Background Color to Black
    #### *NOTE: It is questionable that this works...
    reg add "HKCU\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f
}
#### ========================

#### ========================
#### Restart Explorer and Destop Window Manager to make everything take effect now.
#### ------------------------
function Restart-Explorer
{
    taskkill /f /im explorer.exe
    start explorer.exe
    taskkill /f /im dwm.exe
    start dwm.exe
}
#### ========================

#### ========================
#### Install uBlock Plugin
#### ------------------------
function Remove-ChromeuBlock
{
	Remove-ItemProperty -Force -Path "HKCU:\Software\Google\Chrome\PreferenceMACs\Default\extensions.settings\" -Name "cjpalhdlnbpafiamejdnhcphjbkeiagm"
	#### Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Google\Chrome\" -Name "ExtensionInstallForcelist"
	Remove-Item -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm*" -Recurse
}
function Install-ChromeuBlock
{

	New-Item -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm"
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm\" -Name "update_url" -Value "https://clients2.google.com/service/update2/crx"
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm\" -Name "uBlock-Forced" -Value "oblockorigin-chrome"
}
#### ========================



#### ========================
#### Self Elevate
#### ------------------------
function Self-Elevate
{
    #### ========================
    #### Code credit of Ben Armstrong’s Virtualization Blog
    #### https://blogs.msdn.microsoft.com/virtual_pc_guy/
    #### ========================
    # Get the ID and security principal of the current user account
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
    # Check to see if we are currently running "as Administrator"
    if ($myWindowsPrincipal.IsInRole($adminRole))
    {
    # We are running "as Administrator" - so change the title and background color to indicate this
    #### $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
    $Host.UI.RawUI.BackgroundColor = "DarkBlue"
    clear-host
    }
    else
    {
    # We are not running "as Administrator" - so relaunch as administrator
   
    # Create a new process object that starts PowerShell

    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   
    # Specify the current script path and name as a parameter
    ####$newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
   
    # Indicate that the process should be elevated
    $newProcess.Verb = "runas";
   
    # Start the new process
    [System.Diagnostics.Process]::Start($newProcess);
   
    # Exit from the current, unelevated, process
    exit
    }
    #### ========================
    #### Elevated on call
    #### ========================
}


#### ========================
#### Begin script
#### ========================

#### Elevate!
Self-Elevate
#### Make System Restore
Create-SystemRestore
Enable-RegBackup
VSS-Create
#### RenVSS
RenVSS
#### Customize!
Win10-Custom-LM
Win10-Custom-CU
##Remove-ChromeuBlock
Install-ChromeuBlock

Write-Host -NoNewLine "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
#### ========================