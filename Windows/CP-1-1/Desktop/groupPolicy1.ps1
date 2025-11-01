# Define the list of registry paths and their corresponding REG_DWORD and REG_SZ settings
$registrySettings = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"; Name = "RpcAuthnLevelPrivacyEnabled"; Value = 1; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name = "Start"; Value = 4; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB1"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"; Name = "EnableCertPaddingCheck"; Value = 1; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "DisableExceptionChainValidation"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name = "NodeType"; Value = 2; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "AutoAdminLogon"; Value = "0"; Type = "SZ" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisableIPSourceRouting"; Value = 2; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableIPSourceRouting"; Value = 2; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableICMPRedirect"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "KeepAliveTime"; Value = 300000; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name = "NoNameReleaseOnDemand"; Value = 1; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "PerformRouterDiscovery"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name = "SafeDllSearchMode"; Value = 1; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "ScreenSaverGracePeriod"; Value = "5"; Type = "SZ" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"; Name = "TcpMaxDataRetransmissions"; Value = 3; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpMaxDataRetransmissions"; Value = 3; Type = "DWORD" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"; Name = "WarningLevel"; Value = 90; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "DoHPolicy"; Value = 2; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "EnableNetbios"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "EnableMulticast"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableFontProviders"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name = "AllowInsecureGuestAuth"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "AllowLLTDIOOnDomain"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "AllowLLTDIOOnPublicNet"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "EnableLLTDIO"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "ProhibitLLTDIOOnPrivateNet"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "AllowRspndrOnDomain"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "AllowRspndrOnPublicNet"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "EnableRspndr"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"; Name = "ProhibitRspndrOnPrivateNet"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"; Name = "Disabled"; Value = 1; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name = "NC_AllowNetBridge_NLA"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name = "NC_ShowSharedAccessUI"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name = "NC_StdDomainUserSetLocation"; Value = 1; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name = "\\*\NETLOGON"; Value = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"; Type = "SZ" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name = "\\*\SYSVOL"; Value = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"; Type = "SZ" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"; Name = "DisabledComponents"; Value = 255; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "EnableRegistrars"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableUPnPRegistrar"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableInBand802DOT11Registrar"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableFlashConfigRegistrar"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; Name = "DisableWPDRegistrar"; Value = 0; Type = "DWORD" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"; Name = "DisableWcnUi"; Value = 1; Type = "DWORD" }
)

foreach ($setting in $registrySettings) {
    # Extract the registry path, value name, value, and type from the current setting
    $registryPath = $setting.Path
    $valueName = $setting.Name
    $value = $setting.Value
    $type = $setting.Type

    # Check if the registry path exists
    if (-not (Test-Path $registryPath)) {
        # Create the registry path if it does not exist
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set the registry value based on the type
    if ($type -eq "DWORD") {
        New-ItemProperty -Path $registryPath -Name $valueName -Value $value -PropertyType DWORD -Force | Out-Null
    } elseif ($type -eq "SZ") {
        New-ItemProperty -Path $registryPath -Name $valueName -Value $value -PropertyType String -Force | Out-Null
    }
}

Write-Output "All specified registry values have been updated."
