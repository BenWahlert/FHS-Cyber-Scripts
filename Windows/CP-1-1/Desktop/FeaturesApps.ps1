Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
Unblock-File -Path .\FeaturesApps.ps1
Set-ExecutionPolicy -ExecutionPolicy bypass
dism /online /disable-feature /featurename:IIS-WebServerRole -NoRestart
dism /online /disable-feature /featurename:IIS-WebServer -NoRestart
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures -NoRestart
dism /online /disable-feature /featurename:IIS-HttpErrors -NoRestart
dism /online /disable-feature /featurename:IIS-HttpRedirect -NoRestart
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment -NoRestart
dism /online /disable-feature /featurename:IIS-Security -NoRestart
dism /online /disable-feature /featurename:IIS-RequestFiltering -NoRestart
dism /online /disable-feature /featurename:IIS-NetFxExtensibility -NoRestart
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 -NoRestart
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics -NoRestart
dism /online /disable-feature /featurename:IIS-HttpLogging -NoRestart
dism /online /disable-feature /featurename:IIS-LoggingLibraries -NoRestart
dism /online /disable-feature /featurename:IIS-RequestMonitor -NoRestart
dism /online /disable-feature /featurename:IIS-HttpTracing -NoRestart
dism /online /disable-feature /featurename:IIS-URLAuthorization -NoRestart
dism /online /disable-feature /featurename:IIS-IPSecurity -NoRestart
dism /online /disable-feature /featurename:IIS-Performance -NoRestart
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic -NoRestart
dism /online /disable-feature /featurename:IIS-WebServerManagementTools -NoRestart
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools -NoRestart
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility -NoRestart
dism /online /disable-feature /featurename:IIS-Metabase -NoRestart
dism /online /disable-feature /featurename:IIS-HostableWebCore -NoRestart
dism /online /disable-feature /featurename:IIS-StaticContent -NoRestart
dism /online /disable-feature /featurename:IIS-DefaultDocument -NoRestart
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing -NoRestart
dism /online /disable-feature /featurename:IIS-WebDAV -NoRestart
dism /online /disable-feature /featurename:IIS-WebSockets -NoRestart
dism /online /disable-feature /featurename:IIS-ApplicationInit -NoRestart
dism /online /disable-feature /featurename:IIS-ASPNET -NoRestart
dism /online /disable-feature /featurename:IIS-ASPNET45 -NoRestart
dism /online /disable-feature /featurename:IIS-ASP -NoRestart
dism /online /disable-feature /featurename:IIS-CGI -NoRestart
dism /online /disable-feature /featurename:IIS-ISAPIExtensions -NoRestart
dism /online /disable-feature /featurename:IIS-ISAPIFilter -NoRestart
dism /online /disable-feature /featurename:IIS-ServerSideIncludes -NoRestart
dism /online /disable-feature /featurename:IIS-CustomLogging -NoRestart
dism /online /disable-feature /featurename:IIS-BasicAuthentication -NoRestart
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic -NoRestart
dism /online /disable-feature /featurename:IIS-ManagementConsole -NoRestart
dism /online /disable-feature /featurename:IIS-ManagementService -NoRestart
dism /online /disable-feature /featurename:IIS-WMICompatibility -NoRestart
dism /online /disable-feature /featurename:IIS-LegacyScripts -NoRestart
dism /online /disable-feature /featurename:IIS-LegacySnapIn -NoRestart
dism /online /disable-feature /featurename:IIS-FTPServer -NoRestart
dism /online /disable-feature /featurename:IIS-FTPSvc -NoRestart
dism /online /disable-feature /featurename:IIS-FTPExtensibility -NoRestart
dism /online /disable-feature /featurename:IIS-CertProvider -NoRestart
dism /online /disable-feature /featurename:IIS-WindowsAuthentication -NoRestart
dism /online /disable-feature /featurename:IIS-DigestAuthentication -NoRestart
dism /online /disable-feature /featurename:IIS-ClientCertificateMappingAuthentication -NoRestart
dism /online /disable-feature /featurename:IIS-IISCertificateMappingAuthentication -NoRestart
dism /online /disable-feature /featurename:IIS-ODBCLogging -NoRestart
dism /online /disable-feature /featurename:SMB1Protocol -NoRestart
dism /online /disable-feature /featurename:SMB1Protocol-Client -NoRestart
dism /online /disable-feature /featurename:SMB1Protocol-Server -NoRestart
dism /online /disable-feature /featurename:SMB1Protocol-Deprecation -NoRestart
dism /online /disable-feature /featurename:TelnetClient -NoRestart
dism /online /disable-feature /featurename:TFTP -NoRestart
dism /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2Root -NoRestart
dism /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2 -NoRestart
dism /online /disable-feature /featurename:WCF-TCP-Activation45 -NoRestart
dism /online /disable-feature /featurename:SimpleTCP -NoRestart
dism /online /disable-feature /featurename:WCF-TCP-PortSharing45 -NoRestart
dism /online /disable-feature /featurename:Printing-Foundation-InternetPrinting-Client -NoRestart
dism /online /disable-feature /featurename:MediaPlayback -NoRestart
dism /online /disable-feature /featurename:WindowsMediaPlayer -NoRestart
dism /online /disable-feature /featurename:Internet-Explorer-Optional-amd64 -NoRestart




#Uninstall Calendar and Mail	
	Get-AppxPackage *communications* | Remove-AppxPackage
#Uninstall Camera	
	Get-AppxPackage *camera* | Remove-AppxPackage
#Uninstall Dolby Access	
	Get-AppxPackage *dolbyaccess* | Remove-AppxPackage
#Uninstall Fitbit Coach	
	Get-AppxPackage *fitbitcoach* | Remove-AppxPackage
#Uninstall Get Office	
	Get-AppxPackage *officehub* | Remove-AppxPackage
#Uninstall Get Skype	
	Get-AppxPackage *skypeapp* | Remove-AppxPackage
#Uninstall Get Started	
	Get-AppxPackage *getstarted* | Remove-AppxPackage
#Uninstall Groove Music	
	Get-AppxPackage *zunemusic* | Remove-AppxPackage
#Uninstall Maps	
	Get-AppxPackage *maps* | Remove-AppxPackage
#Uninstall Microsoft Solitaire Collection	
	Get-AppxPackage *solitairecollection* | Remove-AppxPackage
#Uninstall Money	
	Get-AppxPackage *bingfinance* | Remove-AppxPackage
#Uninstall Movies & TV	
	Get-AppxPackage *zunevideo* | Remove-AppxPackage
#Uninstall News	
	Get-AppxPackage *bingnews* | Remove-AppxPackage
#Uninstall OneNote	
	Get-AppxPackage *onenote* | Remove-AppxPackage
#Uninstall People	
	Get-AppxPackage *people* | Remove-AppxPackage
#Uninstall Phone Companion	
	Get-AppxPackage *phone*  | Remove-AppxPackage
#Uninstall Phototastic Collage	
	Get-AppxPackage *phototastic* | Remove-AppxPackage
#Uninstall Photos	
	Get-AppxPackage *photos* | Remove-AppxPackage
#Uninstall PicsArt	
	Get-AppxPackage *picsart* | Remove-AppxPackage
#Uninstall Plex	
	Get-AppxPackage *plex* | Remove-AppxPackage
#Uninstall Store	
	Get-AppxPackage *windowsstore* | Remove-AppxPackage
#Uninstall Sports	
	Get-AppxPackage *bingsports* | Remove-AppxPackage
#Uninstall Voice Recorder	
	Get-AppxPackage *soundrecorder* | Remove-AppxPackage
#Uninstall Weather	
	Get-AppxPackage *bingweather* | Remove-AppxPackage
#Uninstall Xbox	
	Get-AppxPackage *Xbox* | Remove-AppxPackage  
Get-AppxPackage *Xbox* | Disable-UevAppxPackage 
Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage | Remove-AppxPackage
Get-AppxPackage -allusers *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *ConnectivityStore* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *FarmHeroesSaga* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.3dbuilder* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Appconnector* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Asphalt8Airborne* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingNews* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.BingWeather* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.DrawboardPDF* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.GetHelp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Getstarted* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MSPaint* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Microsoft3DViewer* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftOfficeOneNote* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.MixedReality.Portal* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.OneConnect* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.People* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Print3D* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.SkypeApp* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Wallet* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.Whiteboard* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsCommunicationsApps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsMaps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneMusic* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft.ZuneVideo* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Microsoft3DViewer* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *MinecraftUWP* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Netflix* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Office.Sway* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *PandoraMediaInc* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Todos* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *WindowsScan* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *candycrush* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *empires* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *microsoft.windowscommunicationsapps* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *spotify* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *windowsphone* | Remove-AppxPackage -AllUsers
Get-AppxPackage -allusers *xing* | Remove-AppxPackage -AllUsers
Get-AppxPackage Microsoft3DViewer | Remove-AppxPackage -AllUsers
[Array]$Apps =
	'Microsoft.3DBuilder',
	'Microsoft.Microsoft3DViewer',
	'Microsoft.Print3D',
	'Microsoft.Appconnector',
	'Microsoft.BingFinance',
	'Microsoft.BingNews',
	'Microsoft.BingSports',
	'Microsoft.BingTranslator',
	'Microsoft.BingWeather',
	'Microsoft.BingFoodAndDrink',
	'Microsoft.BingTravel',
	'Microsoft.BingHealthAndFitness',
	'Microsoft.FreshPaint',
	'Microsoft.MicrosoftOfficeHub',
	'Microsoft.WindowsFeedbackHub',
	'Microsoft.MicrosoftSolitaireCollection',
	'Microsoft.MicrosoftPowerBIForWindows',
	'Microsoft.MinecraftUWP',
	'Microsoft.MicrosoftStickyNotes',
	'Microsoft.NetworkSpeedTest',
	'Microsoft.Office.OneNote',
	'Microsoft.OneConnect',
	'Microsoft.People',
	'Microsoft.SkypeApp',
	'Microsoft.Wallet',
	'Microsoft.WindowsAlarms',
	'Microsoft.WindowsCamera',
	'Microsoft.windowscommunicationsapps',
	'Microsoft.WindowsMaps',
	'Microsoft.WindowsPhone',
	'Microsoft.WindowsSoundRecorder',
	'Microsoft.XboxApp',
	'Microsoft.XboxGameOverlay',
	'Microsoft.XboxIdentityProvider',
	'Microsoft.XboxSpeechToTextOverlay',
	'Microsoft.ZuneMusic',
	'Microsoft.ZuneVideo',
	'Microsoft.CommsPhone',
	'Microsoft.ConnectivityStore',
	'Microsoft.GetHelp',
	'Microsoft.Getstarted',
	'Microsoft.Messaging',
	'Microsoft.Office.Sway',
	'Microsoft.WindowsReadingList',
	'9E2F88E3.Twitter',
	'PandoraMediaInc.29680B314EFC2',
	'Flipboard.Flipboard',
	'ShazamEntertainmentLtd.Shazam',
	'king.com.CandyCrushSaga',
	'king.com.CandyCrushSodaSaga',
	'king.com.*',
	'ClearChannelRadioDigital.iHeartRadio',
	'4DF9E0F8.Netflix',
	'6Wunderkinder.Wunderlist',
	'Drawboard.DrawboardPDF',
	'2FE3CB00.PicsArt-PhotoStudio',
	'D52A8D61.FarmVille2CountryEscape',
	'TuneIn.TuneInRadio',
	'GAMELOFTSA.Asphalt8Airborne',
	'TheNewYorkTimes.NYTCrossword',
	'DB6EA5DB.CyberLinkMediaSuiteEssentials',
	'Facebook.Facebook',
	'flaregamesGmbH.RoyalRevolt2',
	'Playtika.CaesarsSlotsFreeCasino',
	'A278AB0D.MarchofEmpires',
	'KeeperSecurityInc.Keeper',
	'ThumbmunkeysLtd.PhototasticCollage',
	'XINGAG.XING',
	'89006A2E.AutodeskSketchBook',
	'D5EA27B7.Duolingo-LearnLanguagesforFree',
	'46928bounde.EclipseManager',
	'ActiproSoftwareLLC.562882FEEB491',
	'DolbyLaboratories.DolbyAccess',
	'A278AB0D.DisneyMagicKingdoms',
	'WinZipComputing.WinZipUniversal',
	'Microsoft.ScreenSketch',
	'Microsoft.XboxGamingOverlay',
	'Microsoft.Xbox.TCUI',
	'Microsoft.XboxGameCallableUI',
	'Microsoft.YourPhone'

Foreach ($App in $Apps) {
	Get-AppxPackage $App | Remove-AppxPackage -AllUsers -ErrorAction 'SilentlyContinue'
}
	
$apps = @(
#default Windows 10 apps
"Microsoft.3DBuilder"
"Microsoft.Appconnector"
"Microsoft.BingFinance"
"Microsoft.BingNews"
"Microsoft.BingSports"
"Microsoft.BingTranslator"
"Microsoft.BingWeather"
#"Microsoft.FreshPaint"
"Microsoft.GamingServices"
"Microsoft.Microsoft3DViewer"
"Microsoft.MicrosoftOfficeHub"
"Microsoft.MicrosoftPowerBIForWindows"
"Microsoft.MicrosoftSolitaireCollection"
#"Microsoft.MicrosoftStickyNotes"
"Microsoft.MinecraftUWP"
"Microsoft.NetworkSpeedTest"
"Microsoft.Office.OneNote"
"Microsoft.People"
"Microsoft.Print3D"
"Microsoft.SkypeApp"
"Microsoft.Wallet"
#"Microsoft.Windows.Photos"
"Microsoft.WindowsAlarms"
#"Microsoft.WindowsCalculator"
"Microsoft.WindowsCamera"
"microsoft.windowscommunicationsapps"
"Microsoft.WindowsMaps"
"Microsoft.WindowsPhone"
"Microsoft.WindowsSoundRecorder"
#"Microsoft.WindowsStore"   #can't be re-installed
#"Microsoft.Xbox.TCUI"
#"Microsoft.XboxApp"
#"Microsoft.XboxGameOverlay"
#"Microsoft.XboxGamingOverlay"
#"Microsoft.XboxSpeechToTextOverlay"
"Microsoft.YourPhone"
"Microsoft.ZuneMusic"
"Microsoft.ZuneVideo"

#Threshold 2 apps
"Microsoft.CommsPhone"
"Microsoft.ConnectivityStore"
"Microsoft.GetHelp"
"Microsoft.Getstarted"
"Microsoft.Messaging"
"Microsoft.Office.Sway"
"Microsoft.OneConnect"
"Microsoft.WindowsFeedbackHub"

#Creators Update apps
"Microsoft.Microsoft3DViewer"
#"Microsoft.MSPaint"

#Redstone apps
"Microsoft.BingFoodAndDrink"
"Microsoft.BingHealthAndFitness"
"Microsoft.BingTravel"
"Microsoft.WindowsReadingList"

#Redstone 5 apps
"Microsoft.MixedReality.Portal"
"Microsoft.ScreenSketch"
#"Microsoft.XboxGamingOverlay"
"Microsoft.YourPhone"

#non-Microsoft
"2FE3CB00.PicsArt-PhotoStudio"
"46928bounde.EclipseManager"
"4DF9E0F8.Netflix"
"613EBCEA.PolarrPhotoEditorAcademicEdition"
"6Wunderkinder.Wunderlist"
"7EE7776C.LinkedInforWindows"
"89006A2E.AutodeskSketchBook"
"9E2F88E3.Twitter"
"A278AB0D.DisneyMagicKingdoms"
"A278AB0D.MarchofEmpires"
"ActiproSoftwareLLC.562882FEEB491" #next one is for the Code Writer from Actipro Software LLC
"CAF9E577.Plex"  
"ClearChannelRadioDigital.iHeartRadio"
"D52A8D61.FarmVille2CountryEscape"
"D5EA27B7.Duolingo-LearnLanguagesforFree"
"DB6EA5DB.CyberLinkMediaSuiteEssentials"
"DolbyLaboratories.DolbyAccess"
"DolbyLaboratories.DolbyAccess"
"Drawboard.DrawboardPDF"
"Facebook.Facebook"
"Fitbit.FitbitCoach"
"Flipboard.Flipboard"
"GAMELOFTSA.Asphalt8Airborne"
"KeeperSecurityInc.Keeper"
"NORDCURRENT.COOKINGFEVER"
"PandoraMediaInc.29680B314EFC2"
"Playtika.CaesarsSlotsFreeCasino"
"ShazamEntertainmentLtd.Shazam"
"SlingTVLLC.SlingTV"
"SpotifyAB.SpotifyMusic"
#"TheNewYorkTimes.NYTCrossword"
"ThumbmunkeysLtd.PhototasticCollage"
"TuneIn.TuneInRadio"
"WinZipComputing.WinZipUniversal"
"XINGAG.XING"
"flaregamesGmbH.RoyalRevolt2"
"king.com.*"
"king.com.BubbleWitch3Saga"
"king.com.CandyCrushSaga"
"king.com.CandyCrushSodaSaga"

#apps which other apps depend on
"Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {
Write-Output "Trying to remove $app"

Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

Get-AppXProvisionedPackage -Online |
Where-Object DisplayName -EQ $app |
Remove-AppxProvisionedPackage -Online
}

#Prevents Apps from re-installing
$cdm = @(
"ContentDeliveryAllowed"
"FeatureManagementEnabled"
"OemPreInstalledAppsEnabled"
"PreInstalledAppsEnabled"
"PreInstalledAppsEverEnabled"
"SilentInstalledAppsEnabled"
"SubscribedContent-314559Enabled"
"SubscribedContent-338387Enabled"
"SubscribedContent-338388Enabled"
"SubscribedContent-338389Enabled"
"SubscribedContent-338393Enabled"
"SubscribedContentEnabled"
"SystemPaneSuggestionsEnabled"
)

Write-Output "Kill OneDrive process"
Stop-Process -Force -Force -Name "OneDrive.exe"
Stop-Process -Force -Force -Name "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
& "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
& "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
#check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
Mkdir -Force  "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

#Disable Razer Game Scanner Service
Stop-Service "Razer Game Scanner Service"
Set-Service  "Razer Game Scanner Service" -StartupType Disabled

