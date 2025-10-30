# Repository Guidelines

## Project Structure & Module Organization
- `Linux/` contains remediation helpers for disallowing specific kernel modules. `script.sh` batches the work per module in self-contained `{ … }` blocks; extend it by cloning the pattern and updating `l_mname` and `l_mtype`.
- `Windows/` holds Desired State Configuration assets. `main.ps1` chains `CISDesktop.ps1` (CIS Windows 10 baseline) and `services.ps1`; keep any node-specific data beside these entry points. Preserve PowerShell file names in PascalCase for DSC readability.
- Keep generated artifacts out of version control; document new directories in this guide as they appear.

## Build, Test, and Development Commands
- Validate Bash syntax and functions locally with `bash -n Linux/script.sh` and `shellcheck Linux/script.sh`; run scripts via `sudo bash Linux/script.sh` on lab hosts because the module tasks require elevated privileges.
- Execute the Windows baseline by launching `pwsh -ExecutionPolicy Bypass -File Windows/main.ps1`; use `Start-DscConfiguration -Path .\CIS_Windows10_v181 -Verbose` after compiling new DSC configurations.
- For smoke tests, gate risky Bash calls behind `if [[ ${DRY_RUN:-0} -eq 1 ]]; then … fi` and rehearse Windows runs on disposable VM snapshots.

## Coding Style & Naming Conventions
- Bash: prefer `#!/usr/bin/env bash`, brace-wrapped blocks, two-space indents, and snake_case function names (`module_loaded_fix`). Quote variables unless intentionally expanding globs; redirect status messages through `echo -e`.
- PowerShell: rely on four-space indents, PascalCase resource blocks, and singular nouns for configuration names. Default to DSC-friendly cmdlets and include inline comments that map to CIS control IDs.

## Testing Guidelines
- No automated test suite exists yet; run `shellcheck` for Bash and `Invoke-ScriptAnalyzer Windows/*.ps1` for PowerShell before opening a pull request.
- Validate module removals on a non-production Linux node and confirm DSC convergence with `Test-DscConfiguration` on Windows. Capture mismatches and remediation output in your PR description.

## Commit & Pull Request Guidelines
- Recent commits use short imperative summaries (`Update README.md`, `Added Windows Scripts as well`). Follow that convention and group platform-specific work into separate commits when possible.
- Pull requests should explain the targeted CIS control or remediation scenario, outline manual validation steps, and link to any tracked issue. Include screenshots or transcript excerpts when demonstrating DSC or module status changes.

## Security & Configuration Tips
- Treat configuration files as infrastructure code: never store credentials, and prefer parameterization over hard-coded node names.
- Keep scripts idempotent—ensure rerunning remediation steps only reports compliance without making redundant changes.
