<#
.SYNOPSIS
    Interactive, case-sensitive local group synchronizer for competition hosts.

.DESCRIPTION
    Prompts for a group name and newline-delimited usernames. For each entry it:
      * Creates the user if it does not already exist (prompting for a password).
      * Ensures the account is a member of the specified group.
      * Enables password expiry (PasswordNeverExpires = $false).
    Members present in the group but absent from the provided list are removed.
    When targeting the builtin Users group, any non-protected local user account
    that is not listed is deleted outright.

    The loop repeats until the operator submits a blank group name.
#>

param()

function Invoke-ManageUsers {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error "Administrative privileges are required to manage local users and groups."
        return
    }

    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.LocalAccounts)) {
        Write-Error "Microsoft.PowerShell.LocalAccounts module is required."
        return
    }

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

    Write-Host "Local user/group synchronizer (Ctrl+C to exit)." -ForegroundColor Cyan

    while ($true) {
        $groupName = Read-Host 'Enter the local group to configure (blank to exit)'
        if ([string]::IsNullOrEmpty($groupName)) {
            Write-Host "Exiting." -ForegroundColor Cyan
            break
        }

        $groupName = $groupName.Trim()
        if ($groupName.Length -eq 0) {
            continue
        }

        try {
            $group = Get-LocalGroup -Name $groupName -ErrorAction Stop
        }
        catch {
            Write-Host "Local group '$groupName' not found. Creating it..." -ForegroundColor Yellow
            $group = New-LocalGroup -Name $groupName
        }

        Write-Host "Enter one username per line for group '$groupName'. Press ENTER on an empty line to finish." -ForegroundColor Cyan
        $userEntries = @()
        while ($true) {
            $value = Read-Host 'User'
            if ($value -eq '') {
                break
            }
            $userEntries += $value
        }

        $desiredUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($entry in $userEntries) {
            $trimmed = $entry.Trim()
            if ($trimmed.Length -eq 0) {
                continue
            }
            if (-not $desiredUsers.Add($trimmed)) {
                Write-Host "Duplicate entry '$trimmed' ignored." -ForegroundColor Yellow
            }
        }

        if ($desiredUsers.Count -eq 0) {
            Write-Host "No users supplied for '$groupName'. Nothing to do." -ForegroundColor Yellow
            continue
        }

        foreach ($userName in $desiredUsers) {
            $localUser = Get-LocalUser | Where-Object { $_.Name -ceq $userName }

            if (-not $localUser) {
                Write-Host "Creating local user '$userName'." -ForegroundColor Yellow
                $securePassword = Read-Host -AsSecureString "Enter password for '$userName'"
                if (-not $securePassword) {
                    Write-Warning "No password entered for '$userName'. Skipping user."
                    continue
                }

                try {
                    $localUser = New-LocalUser -Name $userName -Password $securePassword -PasswordNeverExpires:$false
                    Write-Host "Created user '$userName'." -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to create user '$userName'. $_"
                    continue
                }
            }

            try {
                Set-LocalUser -Name $localUser.Name -PasswordNeverExpires $false
            }
            catch {
                Write-Error "Unable to enforce password expiry for '$($localUser.Name)'. $_"
            }

            $memberMatch = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | Where-Object {
                $_.ObjectClass -eq 'User' -and ($_.Name.Split('\')[-1] -ceq $userName)
            }

            if (-not $memberMatch) {
                try {
                    Add-LocalGroupMember -Group $group.Name -Member $userName
                    Write-Host "Added '$userName' to '$groupName'." -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to add '$userName' to '$groupName'. $_"
                }
            }
            else {
                Write-Host "User '$userName' already in '$groupName'." -ForegroundColor Green
            }
        }

        $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
        if ($members) {
            foreach ($member in $members) {
                if ($member.ObjectClass -ne 'User') {
                    continue
                }

                $shortName = $member.Name.Split('\')[-1]
                if (-not $desiredUsers.Contains($shortName)) {
                    try {
                        Remove-LocalGroupMember -Group $group.Name -Member $member.Name -Confirm:$false
                        Write-Host "Removed '$shortName' from '$groupName'." -ForegroundColor Yellow
                    }
                    catch {
                        Write-Error "Failed to remove '$shortName' from '$groupName'. $_"
                    }
                }
            }
        }

        if ($group.Name -ceq 'Users') {
            $protected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount') | ForEach-Object { [void]$protected.Add($_) }

            foreach ($account in Get-LocalUser) {
                if ($protected.Contains($account.Name)) {
                    continue
                }

                if (-not $desiredUsers.Contains($account.Name)) {
                    try {
                        Remove-LocalUser -Name $account.Name
                        Write-Host "Deleted local user '$($account.Name)'." -ForegroundColor Yellow
                    }
                    catch {
                        Write-Error "Failed to delete local user '$($account.Name)'. $_"
                    }
                }
            }
        }

        Write-Host "Finished processing '$groupName'. Provide another group or press ENTER to exit." -ForegroundColor Cyan
    }
}

Invoke-ManageUsers
