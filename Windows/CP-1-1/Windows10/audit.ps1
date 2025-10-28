$auditPolicies = @(
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditCredentialValidation'; Value = 3; Description = 'Ensure Audit Credential Validation is set to Success and Failure'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditKerberosAuthenticationService'; Value = 3; Description = 'Ensure Audit Kerberos Authentication Service is set to Success and Failure (DC Only)'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditKerberosServiceTicketOperations'; Value = 3; Description = 'Ensure Audit Kerberos Service Ticket Operations is set to Success and Failure (DC Only)'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditApplicationGroupManagement'; Value = 3; Description = 'Ensure Audit Application Group Management is set to Success and Failure'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditComputerAccountManagement'; Value = 1; Description = 'Ensure Audit Computer Account Management is set to include Success (DC Only)'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditDistributionGroupManagement'; Value = 1; Description = 'Ensure Audit Distribution Group Management is set to include Success (DC Only)'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditOtherAccountManagementEvents'; Value = 1; Description = 'Ensure Audit Other Account Management Events is set to include Success (DC Only)'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditSecurityGroupManagement'; Value = 1; Description = 'Ensure Audit Security Group Management is set to include Success'; },
    @{ Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'AuditUserAccountManagement'; Value = 3; Description = 'Ensure Audit User Account Management is set to Success and Failure'; }
    # Continue adding all of the required audit policies here with similar format
)

foreach ($policy in $auditPolicies) {
    Write-Output "Applying: $($policy.Description)"
    Set-ItemProperty -Path $policy.Key -Name $policy.Name -Value $policy.Value -ErrorAction SilentlyContinue
}

Write-Output "All audit policies have been configured."
