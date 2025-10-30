netsh advfirewall import "~\Downloads\cp\Server\Server2016Firewall.wfw"
netsh advfirewall set allprofiles state on
if ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 17763)
{
Copy-Item -Path ~\Downloads\cp\Windows10\LGPO.exe -Destination C:\Windows\System32
Copy-Item -Path ~\Downloads\cp\Server\Firewall2019 -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Firewall2019'
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Server\Server2019\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Server\Server2019\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
else 
{
Copy-Item -Path ~\Downloads\cp\Windows10\LGPO.exe -Destination C:\Windows\System32
Copy-Item -Path ~\Downloads\cp\Server\Firewall2016 -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Firewall2016'
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Server\Server2016\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Server\Server2016\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "This computer has been hardened by Hulstrom Students!"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value "*** Authorized Access Only ***"

