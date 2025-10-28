
Copy-Item -Path ~\Downloads\cp\Windows10\LGPO.exe -Destination C:\Windows\System32
Copy-Item -Path ~\Downloads\cp\Windows10\Firewall -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Firewall'


if ((Get-WmiObject Win32_OperatingSystem).BuildNumber -gt 19042)
{
#~/Downloads/cp/VDI/Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 2004 -Verbose
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Windows10\21H1\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Windows10\21H1\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 19042)
{
#~/Downloads/cp/VDI/Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 2004 -Verbose
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Windows10\20H2\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Windows10\20H2\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 19041)
{
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Windows10\2004\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Windows10\2004\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 18363)
{
#~/Downloads/cp/VDI/Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 1909 -Verbose
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1909\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1909\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 18362)
{
~/Downloads/cp/VDI/older/Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 1903 -Verbose
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1903\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1903\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 17763)
{
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1809\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1809\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 17134)
{
~/Downloads/cp/VDI/older/Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 1803 -Verbose
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1803\Standard -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Copy-Item -Path ~\Downloads\cp\Windows10\1803\Full -Destination C:\ -Recurse
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 16299)
{
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Move-Item -Path ~\Downloads\cp\Windows10\1709\Standard -Destination C:\ 
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Move-Item -Path ~\Downloads\cp\Windows10\1709\Full -Destination C:\ 
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 15063)
{
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Move-Item -Path ~\Downloads\cp\Windows10\1703\Standard -Destination C:\
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Move-Item -Path ~\Downloads\cp\Windows10\1703\Full -Destination C:\
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 14393)
{
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Move-Item -Path ~\Downloads\cp\Windows10\1607\Standard -Destination C:\
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Move-Item -Path ~\Downloads\cp\Windows10\1607\Full -Destination C:\
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ((Get-WmiObject Win32_OperatingSystem).BuildNumber -eq 10586)
{
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Move-Item -Path ~\Downloads\cp\Windows10\1511\Standard -Destination C:\
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Move-Item -Path ~\Downloads\cp\Windows10\1511\Full -Destination C:\
    cmd.exe /c 'lgpo /g C:\Full'
    }
}
else 
{
echo "Press 1 for a standard harden and 2 for a full harden"
$option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
    Move-Item -Path ~\Downloads\cp\Windows10\Standard -Destination C:\
    cmd.exe /c 'lgpo /g C:\Standard' }

    elseif ($option -eq 2) {
    Move-Item -Path ~\Downloads\cp\Windows10\Full -Destination C:\
    cmd.exe /c 'lgpo /g C:\Full'
    }
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "This computer has been hardened by Hulstrom Students!"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value "*** Authorized Access Only ***"

