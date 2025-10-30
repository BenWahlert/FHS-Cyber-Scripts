###
# # (From Elevated Powershell)
# Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/wen012235/CP/main/Windows10/main.ps1'))
###


Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n useFipsCompliantChecksums
choco install -y git malwarebytes avast-premier-trial firefox laps --ignorechecksums
choco upgrade firefox notepadplusplus.install
refreshenv
mkdir ~\Downloads\cp
cd ~\Downloads\cp


& "C:\Program Files\Git\bin\git.exe" clone  https://github.com/BenWahlert/FHS-Cyber-Scripts.git .
mkdir ~\Downloads\cp\VDI
cd ~\Downloads\cp\VDI
if ((Get-WmiObject Win32_OperatingSystem).BuildNumber -gt 18360) {& "C:\Program Files\Git\bin\git.exe" clone https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool.git .}
else {& "C:\Program Files\Git\bin\git.exe" clone https://github.com/TheVDIGuys/Windows_10_VDI_Optimize.git . }
cd ~\Downloads\cp\Windows\CP-1-1\Windows10
cls
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show('Make sure to set the current user password to something with at least 14 characters, with at least one upper/lower/number/special character before you begin.  Press OK when you have set that password and are ready to continue.')
$msgBoxInput =  [System.Windows.MessageBox]::Show('Are you ready for some CP goodness?','Harden the Machine!','YesNo','Error')
  switch  ($msgBoxInput) {
  'Yes' { 
  ./CPGoodies.ps1
  [System.Windows.MessageBox]::Show("Wait a few seconds to make sure this script didn't lose any points.  If it did, look in the CPGoodies script to see what was done.")
  }
  'No' {Break }
  }
 
cls
$msgBoxInput =  [System.Windows.MessageBox]::Show('Are you ready to enable the good services and disable the bad ones?','Harden the Machine!','YesNo','Error')
  switch  ($msgBoxInput) {
  'Yes' { 
  ./services.ps1
  [System.Windows.MessageBox]::Show("Wait a few seconds to make sure this script didn't lose any points.  If it did, look in the services script to see what was done.")
  }
  'No' {Break }
  }
cls
$msgBoxInput =  [System.Windows.MessageBox]::Show('Are you ready to disable the bad features?','Harden the Machine!','YesNo','Error')
  switch  ($msgBoxInput) {
  'Yes' { 
  ./FeaturesApps.ps1
Start-Process "C:\Windows\System32\OptionalFeatures.exe"  
[System.Windows.MessageBox]::Show('Check features against the checklist to make sure all the bad ones have been removed')
[System.Windows.MessageBox]::Show("Wait a few seconds to make sure this script didn't lose any points.  If it did, look in the FeaturesApps script to see what was done.")
  }
  'No' {Break }
  }
cls
$msgBoxInput =  [System.Windows.MessageBox]::Show('Are you ready to set firewall and security policies?','Harden the Machine!','YesNo','Error')
  switch  ($msgBoxInput) {
  'Yes' {
  ./harden.ps1
  [System.Windows.MessageBox]::Show("Wait a few seconds to make sure this script didn't lose any points.  If it did, look in the harden script to see what was done.")
  }
  'No' {Break }
  }
  Write-Host "Searching for all the bad programs.  This could take a few minutes."
  ./badprograms.ps1
$firefox64 = "C:\Program Files\Mozilla Firefox\"
$firefox32 = "C:\Program Files (x86)\Mozilla Firefox\"
Write-Output "Installing Firefox Configurations - Please Wait."
Write-Output "Window will close after install is complete"
If (Test-Path -Path $firefox64){
    #Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox64 -Force -Recurse
    Copy-Item -Path ~\Downloads\cp\Windows10\mozilla.cfg -Destination $firefox64 -Force
    Copy-Item -Path ~\Downloads\cp\Windows10\local-settings.js -Destination "C:\Program Files\Mozilla Firefox\defaults\pref\" -Force 
    Write-Host "Firefox 64-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 64-Bit Is Not Installed"
}
If (Test-Path -Path $firefox32){
    #Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox32 -Force -Recurse
    Copy-Item -Path ~\Downloads\cp\Windows10\mozilla.cfg -Destination $firefox32 -Force
    Copy-Item -Path ~\Downloads\cp\Windows10\local-settings.js -Destination "C:\Program Files (x86)\Mozilla Firefox\defaults\pref\" -Force 
    Write-Host "Firefox 32-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 32-Bit Is Not Installed"
}  
#copy-item -path ~\Downloads\cp\Windows10\local-settings.js -Destination "C:\Program Files\Mozilla Firefox\defaults\pref"
#copy-item -path ~\Downloads\cp\Windows10\mozilla.cfg -Destination "C:\Program Files\Mozilla Firefox\"
#copy-item -path ~\Downloads\cp\Windows10\blacklist.txt -Destination ~\Desktop\
#Get-Package -ProviderName "Programs" >> ~/Desktop/programs.rtf
cls
Write-Warning "This system has been hardened by Fairview Students.  Now continue down the checklist and get those points!"
$Answer = [System.Windows.MessageBox]::Show("Reboot to make changes effective?", "Restart Computer", "YesNo", "Question")
switch ($Answer) {
    "Yes" { Write-Host "Performing Gpupdate"; Gpupdate /force /boot; Get-Job; Write-Warning "Restarting Computer in 15 Seconds"; Start-sleep -seconds 15; Restart-Computer -Force }
    "No" { Write-Host "Performing Gpupdate"; Gpupdate /force ; Get-Job; Write-Warning "A reboot is required for all changes to take effect" }
    Default { Write-Warning "A reboot is required for all changes to take effect" }
    }

