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
