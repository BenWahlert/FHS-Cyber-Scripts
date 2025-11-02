Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
Unblock-File -Path .\services.ps1
Set-ExecutionPolicy -ExecutionPolicy bypass
get-service | Format-Table -Autosize

$badServicesPath = '~\Downloads\cp\Windows\CP-1-1\Desktop\badservices.txt'
$badServices = Get-Content -Path $badServicesPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() }

$badServices | Stop-Service
Get-Content -Path ~\Downloads\cp\Windows\CP-1-1\Desktop\goodservices.txt | Start-Service
Foreach ($Service in $badServices) {
		Set-Service -Name $Service -StartupType 'Disabled'
		Stop-Service -Name $Service -Force
	}
