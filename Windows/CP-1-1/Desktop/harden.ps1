Copy-Item -Path ~\Downloads\cp\Desktop\LGPO.exe -Destination C:\Windows\System32
Copy-Item -Path ~\Downloads\cp\Desktop\Firewall -Destination C:\ -Recurse
cmd.exe /c 'lgpo /g C:\Firewall'

$buildNumber = (Get-WmiObject Win32_OperatingSystem).BuildNumber

# --- Windows 11 builds (kept in Desktop folder for compatibility) ---
if ($buildNumber -ge 27500) {
    # Windows 11 25H2 (Build 27500+)
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\25H2\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\25H2\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -ge 26100 -and $buildNumber -lt 27500) {
    # Windows 11 24H2
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\24H2\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\24H2\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -ge 22631 -and $buildNumber -lt 26100) {
    # Windows 11 23H2
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\23H2\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\23H2\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -ge 22621 -and $buildNumber -lt 22631) {
    # Windows 11 22H2
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\22H2\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\22H2\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}

# --- Windows 10 builds ---
elseif ($buildNumber -gt 19042) {
    # 21H1
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\21H1\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\21H1\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 19042) {
    # 20H2
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\20H2\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\20H2\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 19041) {
    # 2004
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\2004\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\2004\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 18363) {
    # 1909
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1909\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1909\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 18362) {
    # 1903
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1903\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1903\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 17763) {
    # 1809
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1809\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1809\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 17134) {
    # 1803
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1803\Standard -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Copy-Item -Path ~\Downloads\cp\Desktop\1803\Full -Destination C:\ -Recurse
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 16299) {
    # 1709
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Move-Item -Path ~\Downloads\cp\Desktop\1709\Standard -Destination C:\
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Move-Item -Path ~\Downloads\cp\Desktop\1709\Full -Destination C:\
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 15063) {
    # 1703
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Move-Item -Path ~\Downloads\cp\Desktop\1703\Standard -Destination C:\
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Move-Item -Path ~\Downloads\cp\Desktop\1703\Full -Destination C:\
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 14393) {
    # 1607
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Move-Item -Path ~\Downloads\cp\Desktop\1607\Standard -Destination C:\
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Move-Item -Path ~\Downloads\cp\Desktop\1607\Full -Destination C:\
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
elseif ($buildNumber -eq 10586) {
    # 1511
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Move-Item -Path ~\Downloads\cp\Desktop\1511\Standard -Destination C:\
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Move-Item -Path ~\Downloads\cp\Desktop\1511\Full -Destination C:\
        cmd.exe /c 'lgpo /g C:\Full'
    }
}
else {
    # Fallback
    echo "Press 1 for a standard harden and 2 for a full harden"
    $option = Read-Host '
1. Standard
2. Full
'
    if ($option -eq 1) {
        Move-Item -Path ~\Downloads\cp\Desktop\Standard -Destination C:\
        cmd.exe /c 'lgpo /g C:\Standard'
    } elseif ($option -eq 2) {
        Move-Item -Path ~\Downloads\cp\Desktop\Full -Destination C:\
        cmd.exe /c 'lgpo /g C:\Full'
    }
}

# --- Banner text ---
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "legalnoticecaption" -Value "This computer has been hardened by Fairview Students!"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "legalnoticetext" -Value "*** Authorized Access Only ***"
