Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
Unblock-File -Path .\services.ps1
Set-ExecutionPolicy -ExecutionPolicy bypass
get-service | Format-Table -Autosize

Get-Content -Path ~\Downloads\cp\Windows10\badservices.txt | Stop-Service
Get-Content -Path ~\Downloads\cp\Windows10\goodservices.txt | Start-Service
