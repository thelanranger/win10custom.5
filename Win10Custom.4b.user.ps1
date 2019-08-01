#### Win10Custom.ps1 v .4b
#### User Configuration
#### Written by TheLANRanger
#### 
#### Goal is to script as many basic default changes to Windows 10 desktop as possible to save clicks!
#### Should be partnered with Win10Custom.4b.Computer.ps1


#### ========================
#### Customize Windows 10 begin
#### ------------------------
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

#### Set Background Color to Black  *NOTE: It is questionable that this works...
reg add "HKCU\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f

#### Set Time Zone to EST
tzutil /s "Eastern Standard Time"
#### Set power settings to 'High Performance'
POWERCFG -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
POWERCFG -X -disk-timeout-ac 0
POWERCFG -X -disk-timeout-dc 0
POWERCFG -H OFF
#### ========================


#### ========================
#### Restart Explorer and Destop Window Manager to make everything take effect now.
#### !Disabled currently!
#### ------------------------
#### taskkill /f /im explorer.exe
#### start explorer.exe
#### taskkill /f /im dwm.exe
#### start dwm.exe
#### ========================




#### ========================
#### ------------------------
#### ========================
