Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
Unblock-File -Path .\clearall.ps1
Set-ExecutionPolicy -ExecutionPolicy bypass

#Delete "windows.old" folder
#Cmd.exe /c Cleanmgr /sageset:65535 
Cmd.exe /c Cleanmgr /sagerun:65535
Write-Verbose "Removing .tmp, .etl, .evtx, thumbcache*.db, *.log files not in use"
Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
#Delete "RetailDemo" content (if it exits)
Write-Verbose "Removing Retail Demo content (if it exists)"
Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue
#Delete not in-use anything in the C:\Windows\Temp folder
Write-Verbose "Removing all files not in use in $env:windir\TEMP"
Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
#Clear out Windows Error Reporting (WER) report archive folders
Write-Verbose "Cleaning up WER report archive"
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
#Delete not in-use anything in your $env:TEMP folder
Write-Verbose "Removing files not in use in $env:TEMP directory"
Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
#Clear out ALL visible Recycle Bins
Write-Verbose "Clearing out ALL Recycle Bins"
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
#Clear out BranchCache cache
Write-Verbose "Clearing BranchCache cache"
Clear-BCCache -Force -ErrorAction SilentlyContinue
#Clear volume backups (shadow copies)
vssadmin delete shadows /all /quiet
#Empty trash bin
Powershell -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10);$bin.items() | ForEach { Write-Host "Deleting $($_.Name) from Recycle Bin"; Remove-Item $_.Path -Recurse -Force}"
#Delete controversial default0 user
net user defaultuser0 /delete 2>nul
#Clear thumbnail cache
Remove-Item /f /s /q /a $env:LocalAppData\Microsoft\Windows\Explorer\*.db
#Clear Windows temp files
Remove-Item /f /q $env:localappdata\Temp\*
Remove-Item /s /q "$env:WINDIR\Temp"
Remove-Item /s /q "$env:TEMP"
#Clear main telemetry file
takeown /f "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r -Value y
icacls "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
Write-Output"" > "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
Write-Output Clear successful: "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
#Clear Distributed Transaction Coordinator logs
Remove-Item /f /q $env:SystemRoot\DtcInstall.log
#Clear Optional Component Manager and COM+ components logs
Remove-Item /f /q $env:SystemRoot\comsetup.log
#Clear Pending File Rename Operations logs
Remove-Item /f /q $env:SystemRoot\PFRO.log
#Clear Windows Deployment Upgrade Process Logs
Remove-Item /f /q $env:SystemRoot\setupact.log
Remove-Item /f /q $env:SystemRoot\setuperr.log
#Clear Windows Setup Logs
Remove-Item /f /q $env:SystemRoot\setupapi.log
Remove-Item /f /q $env:SystemRoot\Panther\*
Remove-Item /f /q $env:SystemRoot\inf\setupapi.app.log
Remove-Item /f /q $env:SystemRoot\inf\setupapi.dev.log
Remove-Item /f /q $env:SystemRoot\inf\setupapi.offline.log
#Clear Windows System Assessment Tool logs
Remove-Item /f /q $env:SystemRoot\Performance\WinSAT\winsat.log
#Clear Password change events
Remove-Item /f /q $env:SystemRoot\debug\PASSWD.LOG
#Clear user web cache database
Remove-Item /f /q $env:LocalAppData\Microsoft\Windows\WebCache\*.*
#Clear system temp folder when noone is logged in
Remove-Item /f /q $env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Temp\*.*
#Clear DISM (Deployment Image Servicing and Management) Logs
Remove-Item /f /q  $env:SystemRoot\Logs\CBS\CBS.log
Remove-Item /f /q  $env:SystemRoot\Logs\DISM\DISM.log
#Clear Server-initiated Healing Events Logs
Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
#Common Language Runtime Logs
Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0\UsageTraces\*"
Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0_32\UsageTraces\*"
#Network Setup Service Events Logs
Remove-Item /f /q "$env:SystemRoot\Logs\NetSetup\*"
#Disk Cleanup tool (Cleanmgr.exe) Logs
Remove-Item /f /q "$env:SystemRoot\System32\LogFiles\setupcln\*"
#Clear Windows update and SFC scan logs
Remove-Item /f /q $env:SystemRoot\Temp\CBS\*
#Clear Windows Update Medic Service logs
takeown /f $env:SystemRoot\Logs\waasmedic /r -Value y
icacls $env:SystemRoot\Logs\waasmedic /grant administrators:F /t
Remove-Item /s /q $env:SystemRoot\Logs\waasmedic
#Clear Cryptographic Services Traces
Remove-Item /f /q $env:SystemRoot\System32\catroot2\dberr.txt
Remove-Item /f /q $env:SystemRoot\System32\catroot2.log
Remove-Item /f /q $env:SystemRoot\System32\catroot2.jrs
Remove-Item /f /q $env:SystemRoot\System32\catroot2.edb
Remove-Item /f /q $env:SystemRoot\System32\catroot2.chk
#Windows Update Events Logs
Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
#Windows Update Logs
Remove-Item /f /q "$env:SystemRoot\Traces\WindowsUpdate\*"
#Clear Internet Explorer traces
Remove-Item /f /q "$env:LocalAppData\Microsoft\Windows\INetCache\IE\*"
reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLsTime" /va /f
Remove-Item /s /q "$env:LocalAppData\Microsoft\Internet Explorer"
Remove-Item /s /q "$env:APPDATA\Microsoft\Windows\Cookies"
Remove-Item /s /q "$env:USERPROFILE\Cookies"
Remove-Item /s /q "$env:USERPROFILE\Local Settings\Traces"
Remove-Item /s /q "$env:LocalAppData\Temporary Internet Files"
Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\Temporary Internet Files"
Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\INetCookies\PrivacIE"
Remove-Item /s /q "$env:LocalAppData\Microsoft\Feeds Cache"
Remove-Item /s /q "$env:LocalAppData\Microsoft\InternetExplorer\DOMStore"
#Clear Google Chrome traces
Remove-Item /f /q "$env:LocalAppData\Google\Software Reporter Tool\*.log"
Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Google\Chrome\User Data"
Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data"
Remove-Item /s /q "$env:LocalAppData\Google\CrashReports\""
Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data\Crashpad\reports\""
#Clear Opera traces
Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Opera\Opera"
Remove-Item /s /q "$env:APPDATA\Opera\Opera"
Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Opera\Opera"
#Clear Safari traces
Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Traces"
Remove-Item /s /q "$env:APPDATA\Apple Computer\Safari"
Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Cache.db"
Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\WebpageIcons.db"
Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Traces"
Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Cache.db"
Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Safari\WebpageIcons.db"
#Clear Listary indexes
Remove-Item /f /s /q $env:APPDATA\Listary\UserData > nul
#Clear Java cache
Remove-Item /s /q "$env:APPDATA\Sun\Java\Deployment\cache"
#Clear Flash traces
Remove-Item /s /q "$env:APPDATA\Macromedia\Flash Player"
#Clear Steam dumps, logs and traces
Remove-Item /f /q %ProgramFiles(x86)%\Steam\Dumps
Remove-Item /f /q %ProgramFiles(x86)%\Steam\Traces
Remove-Item /f /q %ProgramFiles(x86)%\Steam\appcache\*.log
#Clear Visual Studio telemetry and feedback data
Remove-Item /s /q "$env:APPDATA\vstelemetry" 2>nul
Remove-Item /s /q "$env:LocalAppData\Microsoft\VSApplicationInsights" 2>nul
Remove-Item /s /q "$env:ProgramData\Microsoft\VSApplicationInsights" 2>nul
Remove-Item /s /q "$env:TEMP\Microsoft\VSApplicationInsights" 2>nul
Remove-Item /s /q "$env:TEMP\VSFaultInfo" 2>nul
Remove-Item /s /q "$env:TEMP\VSFeedbackPerfWatsonData" 2>nul
Remove-Item /s /q "$env:TEMP\VSFeedbackVSRTCLogs" 2>nul
Remove-Item /s /q "$env:TEMP\VSRemoteControl" 2>nul
Remove-Item /s /q "$env:TEMP\VSTelem" 2>nul
Remove-Item /s /q "$env:TEMP\VSTelem.Out" 2>nul
#Clear Dotnet CLI telemetry
Remove-Item /s /q "$env:USERPROFILE\.dotnet\TelemetryStorageService" 2>nul
#Clear regedit last key
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
#Clear regedit favorites
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
#Clear list of recent programs opened
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
#Clear Adobe Media Browser MRU
reg delete "HKCU\Software\Adobe\MediaBrowser\MRU" /va /f
#Clear MSPaint MRU
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
#Clear Wordpad MRU
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
#Clear Map Network Drive MRU MRU
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
#Clear Windows Search Assistant history
reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
#Clear list of Recent Files Opened, by Filetype
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
#Clear windows media player recent files and urls
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
#Clear Most Recent Application's Use of DirectX
reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f
#Clear Windows Run MRU & typedpaths
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
#Clear recently accessed files
Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
#Clear user pins
Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
#Clear regedit last key
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
