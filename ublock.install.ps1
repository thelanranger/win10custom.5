Remove-ItemProperty -Force -Path "HKCU:\Software\Google\Chrome\PreferenceMACs\Default\extensions.settings\" -Name "cjpalhdlnbpafiamejdnhcphjbkeiagm"
#### Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Google\Chrome\" -Name "ExtensionInstallForcelist"
Remove-Item -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm*" -Recurse

New-Item -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm" | out-null
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm\" -Name "update_url" -Value "https://clients2.google.com/service/update2/crx" | out-null
New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm\" -Name "uBlock-Forced" -Value "oblockorigin-chrome" | out-null