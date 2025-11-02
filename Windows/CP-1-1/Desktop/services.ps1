Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
Unblock-File -Path .\services.ps1
Set-ExecutionPolicy -ExecutionPolicy bypass
get-service | Format-Table -Autosize


#Disable bad services
$badServicesPath = '~\Downloads\cp\Windows\CP-1-1\Desktop\badservices.txt'
$badServices = Get-Content -Path $badServicesPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() }

$badServices | Stop-Service

Foreach ($Service in $badServices) {
		Set-Service -Name $Service -StartupType 'Disabled'
		Stop-Service -Name $Service -Force
	}

#Enable good services
Get-Content -Path ~\Downloads\cp\Windows\CP-1-1\Desktop\goodservices.txt | Start-Service

#Disable Game Bar features
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force

#Disable Logitech Gaming service
Stop-Service "LogiRegistryService"
Set-Service "LogiRegistryService" -StartupType Disabled

#Disable CCleaner Health Check
Stop-Process -Force -Force -Name  ccleaner.exe
Stop-Process -Force -Force -Name  ccleaner64.exe
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type "String" -Value 2 -Force

#Disable CCleaner Monitoring && more
Stop-Process -Force -Force -Name "IMAGENAME eq CCleaner*"
schtasks /Change /TN "CCleaner Update" /Disable
Get-ScheduledTask -TaskName "CCleaner Update" | Disable-ScheduledTask
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)HealthCheck" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickClean" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickCleanIpm" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type "DWORD" -Value 0 -Force

#Disable Dropbox Update service
Set-Service dbupdate -StartupType Disabled
Set-Service dbupdatem -StartupType Disabled
Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineCore" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineUA" | Disable-ScheduledTask
#schtasks /Change /TN "DropboxUpdateTaskMachineCore" /Disable
#schtasks /Change /TN "DropboxUpdateTaskMachineUA" /Disable
