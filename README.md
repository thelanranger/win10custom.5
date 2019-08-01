# win10custom
Modifies and Customizes a Win10 Default install. The purpose of this is to save a bunch of clicks 
in customizing a base system install of Windows 10. 

* Attempts Self Elevate *improved in .5b see code for comments
* Create a System restore point before we break a bunch of stuff. 
* Enable Registry Backup (Disabled post 10 1803) 
* Enable Volume Shadow Copy for local Disks and create schedule tasks 
* NOTE: There must be a VSS-Task-Disk task for partition (drive letter) on your system! Modify accordingly!

* RenVSSadmin (RenVSS1.3.ps1 Starts here)
* See https://github.com/thelanranger/renvss

* Customize Windows 10 begin 
* Shrink Search box to button: 0 = Hidden, 1 = Show search or Cortana icon, 2 = Show search box 
* Combine Taskbar Buttons: 0 = Always combine, hide labels, 1 = Combine when taskbar is full, 2 = Never combine 
* Always show all icons in notification area: 0 = Show all, 1 = Show none 
* Display Full Path in Title Bar area: 0 = Off, 1 = On 
* Display Filename Extensions: 0 = Show, 1 = Off 
* Expand Ribbon in Explorer: 0 = Open, 1 = Close 
* Expand Copy Window to Full: 0 = Closed, 1 = Open 
* "Get tips, tricks, and suggestions as you use Windows": 0 = Off, 1 = On 
* App Suggestions on Start: 0 = Off, 1 = On 
* Change updates to Semi Annual Channel: 16 = Semi-Annual Channel (Targeted), 32 = Semi-Annual Channel, Absent or other = All 
* *Note: Based upon documentation and the internet, I suspect that starting at 10 you are on targeted and the higher the number the more frequent the updates. 
* Data Collection (This is enterprise level settings!): 
* Disable Feedback and Diagnostics: Creates 'AllowTelemetry'. 0 = Security (Enterprise and Education editions only), 1 = Basic, 2 = Enhanced, 3 = Full (Recommended) 
* Disable Connected User Experience and Telemetry Service: 
* Set Background Color to Black  *NOTE: It is questionable that this works... 
* Set Time Zone to EST 
* Set power settings to 'High Performance' 

* Remove uBlock Origin for Chrome *optional
* Install uBlock Origin for Chrome

* Restart Explorer and Destop Window Manager to make everything take effect now *Optional
