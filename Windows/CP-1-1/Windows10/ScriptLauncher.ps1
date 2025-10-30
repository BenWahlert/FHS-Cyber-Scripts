#requires -Version 5.1
<#
.SYNOPSIS
    GUI helper to run Windows 10 hardening scripts from this repository.

.DESCRIPTION
    Presents a simple Windows Forms UI that allows an operator to choose which
    PowerShell scripts (CPGoodies, services, features, harden, badprograms) to run.
    Each script is invoked in its own PowerShell process with Execution Policy
    bypassed, and output is written to a timestamped log in the Logs directory
    beneath this file.

.NOTES
    Run from an elevated PowerShell prompt. The repository is expected to be cloned
    locally, and this script should remain in the same folder as the other
    Windows/CP-1-1/Windows10 scripts.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$scriptRoot   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$logDirectory = Join-Path $scriptRoot 'Logs'
[void][System.IO.Directory]::CreateDirectory($logDirectory)

$availableScripts = @(
    [PSCustomObject]@{ Name = 'CPGoodies.ps1';    Description = 'Firewall import, telemetry/privacy lockdown';             Path = Join-Path $scriptRoot 'CPGoodies.ps1'    },
    [PSCustomObject]@{ Name = 'services.ps1';     Description = 'Enable good services, disable unwanted ones';             Path = Join-Path $scriptRoot 'services.ps1'     },
    [PSCustomObject]@{ Name = 'FeaturesApps.ps1'; Description = 'Disable optional features and remove bloatware apps';     Path = Join-Path $scriptRoot 'FeaturesApps.ps1' },
    [PSCustomObject]@{ Name = 'harden.ps1';       Description = 'Firewall rules, security policies, registry hardening';   Path = Join-Path $scriptRoot 'harden.ps1'       },
    [PSCustomObject]@{ Name = 'badprograms.ps1';  Description = 'Remove disallowed software and tools';                    Path = Join-Path $scriptRoot 'badprograms.ps1'  }
)

$form                  = New-Object System.Windows.Forms.Form
$form.Text             = 'CP Hardening Script Launcher'
$form.Size             = New-Object System.Drawing.Size(620, 420)
$form.StartPosition    = 'CenterScreen'
$form.MaximizeBox      = $false
$form.FormBorderStyle  = 'FixedDialog'

$infoLabel                  = New-Object System.Windows.Forms.Label
$infoLabel.Text             = "Select the scripts you would like to run. Each script runs in sequence with logging in:`n$logDirectory"
$infoLabel.AutoSize         = $true
$infoLabel.Location         = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($infoLabel)

$checkList                  = New-Object System.Windows.Forms.CheckedListBox
$checkList.Location         = New-Object System.Drawing.Point(15, 50)
$checkList.Size             = New-Object System.Drawing.Size(575, 230)
$checkList.CheckOnClick     = $true

foreach ($item in $availableScripts) {
    $display = "{0} - {1}" -f $item.Name, $item.Description
    $null = $checkList.Items.Add($display)
}
$form.Controls.Add($checkList)

$selectAllButton                = New-Object System.Windows.Forms.Button
$selectAllButton.Text           = 'Select All'
$selectAllButton.Location       = New-Object System.Drawing.Point(15, 300)
$selectAllButton.Size           = New-Object System.Drawing.Size(90, 30)
$selectAllButton.Add_Click({
    for ($i = 0; $i -lt $checkList.Items.Count; $i++) {
        $checkList.SetItemChecked($i, $true)
    }
})
$form.Controls.Add($selectAllButton)

$clearButton                    = New-Object System.Windows.Forms.Button
$clearButton.Text               = 'Clear'
$clearButton.Location           = New-Object System.Drawing.Point(115, 300)
$clearButton.Size               = New-Object System.Drawing.Size(90, 30)
$clearButton.Add_Click({
    for ($i = 0; $i -lt $checkList.Items.Count; $i++) {
        $checkList.SetItemChecked($i, $false)
    }
})
$form.Controls.Add($clearButton)

$openLogsButton                 = New-Object System.Windows.Forms.Button
$openLogsButton.Text            = 'Open Logs Folder'
$openLogsButton.Location        = New-Object System.Drawing.Point(215, 300)
$openLogsButton.Size            = New-Object System.Drawing.Size(140, 30)
$openLogsButton.Add_Click({
    Start-Process explorer.exe $logDirectory
})
$form.Controls.Add($openLogsButton)

$runButton                      = New-Object System.Windows.Forms.Button
$runButton.Text                 = 'Run Selected Scripts'
$runButton.Location             = New-Object System.Drawing.Point(370, 300)
$runButton.Size                 = New-Object System.Drawing.Size(155, 30)

$closeButton                    = New-Object System.Windows.Forms.Button
$closeButton.Text               = 'Close'
$closeButton.Location           = New-Object System.Drawing.Point(530, 300)
$closeButton.Size               = New-Object System.Drawing.Size(60, 30)
$closeButton.Add_Click({ $form.Close() })
$form.Controls.Add($closeButton)

function Invoke-HardeningScript {
    param(
        [string]$ScriptPath,
        [string]$FriendlyName,
        [string]$LogDirectory
    )

    if (-not (Test-Path $ScriptPath)) {
        throw "Script not found: $ScriptPath"
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logPath   = Join-Path $LogDirectory ("{0}-{1}.log" -f $timestamp, ($FriendlyName -replace '\.ps1$', ''))
    $arguments = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', (Resolve-Path $ScriptPath).ProviderPath
    )

    $startInfo                       = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName              = (Get-Command powershell.exe).Source
    $startInfo.Arguments             = $arguments -join ' '
    $startInfo.WorkingDirectory      = $scriptRoot
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError  = $true
    $startInfo.UseShellExecute        = $false
    $startInfo.CreateNoWindow         = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $null = $process.Start()
    $output = $process.StandardOutput.ReadToEnd()
    $errorOutput = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    $logContent = @(
        "Script: $FriendlyName"
        "Path  : $ScriptPath"
        "Exit  : {0}" -f $process.ExitCode
        '--- Standard Output ---'
        $output
        '--- Standard Error ---'
        $errorOutput
    )
    $logContent | Out-File -FilePath $logPath -Encoding UTF8

    if ($process.ExitCode -ne 0) {
        throw "Script $FriendlyName exited with code $($process.ExitCode). Review $logPath"
    }
}

$runButton.Add_Click({
    $selectedIndices = @()
    for ($i = 0; $i -lt $checkList.Items.Count; $i++) {
        if ($checkList.GetItemChecked($i)) {
            $selectedIndices += $i
        }
    }

    if ($selectedIndices.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Please select at least one script before running.', 'No Scripts Selected', 'OK', 'Warning') | Out-Null
        return
    }

    $summary = ''
    $allSucceeded = $true
    foreach ($index in $selectedIndices) {
        $scriptInfo = $availableScripts[$index]
        try {
            Invoke-HardeningScript -ScriptPath $scriptInfo.Path -FriendlyName $scriptInfo.Name -LogDirectory $logDirectory
            $summary += "{0} - Success`n" -f $scriptInfo.Name
        } catch {
            $summary += "{0} - FAILED:`n    {1}`n" -f $scriptInfo.Name, $_.Exception.Message
            $allSucceeded = $false
        }
    }

    $title = if ($allSucceeded) { 'All scripts completed' } else { 'Some scripts failed' }
    [System.Windows.Forms.MessageBox]::Show($summary.Trim(), $title, 'OK', 'Information') | Out-Null
})

$form.Controls.Add($runButton)

[void]$form.ShowDialog()
