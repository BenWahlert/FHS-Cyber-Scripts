# Repository Guidelines

## Scope
This repository contains the automation the Fairview High School Cyber team uses to harden competition hosts. Linux hardening is orchestrated through `Linux/script.sh`, while Windows automation lives under `Windows/CP-1-1/` with supporting Desired State Configuration resources. Treat the content as production-ready; every change must preserve repeatable, competition-safe execution.

## Layout
- `Linux/` holds the actively maintained Bash runbook plus the legacy toolkit in `Old-Ubuntu-Script/`. Any new Linux asset should stay inside this tree.
- `Windows/` contains PowerShell DSC definitions (`CISDesktop.ps1`) and the CyberPatriot toolkits for Windows 10, Server, Domain Controller, and VDI preparation.
- Docs (`README.md`, this guide) spell out operator workflows; update them whenever scripts move or behavior changes.

## Bash Contributions
- Keep scripts POSIX-friendly Bash; enable options (`set -euo pipefail`) only when tested end to end.
- Quote variable expansions, prefer array-safe patterns, and use `printf`/`mapfile` where possible.
- Validate with `bash -n` and `shellcheck` (`shellcheck -x path/to/script.sh`). Document required packages or kernel modules in comments near their first use.
- When touching legacy assets (`Old-Ubuntu-Script/`), ensure interactive prompts still match the original competition flow.

## PowerShell Contributions
- Target Windows PowerShell 5.1 unless explicitly gated for PowerShell 7+. Avoid language-specific features not available on 5.1.
- All new scripts should support `-WhatIf` or dry-run modes when practical. Use `Join-Path`, `Test-Path`, and `Resolve-Path` to avoid hard-coded separators.
- Group Policy backups in `Windows/CP-1-1/Windows10/<build>/` must remain importable via `LGPO.exe`; do not rename or restructure these directories without updating the README and launcher UI.

## Testing & Validation
- Bash: `sudo bash -n script.sh`, `sudo shellcheck script.sh`, and, when feasible, run on a disposable VM snapshot.
- PowerShell: `pwsh -NoProfile -File ./script.ps1 -Verbose` in an elevated session. Capture logs in `Windows/CP-1-1/Windows10/Logs` for regressions.
- Record manual verification steps in the PR description when automated testing is impractical.

## Pull Requests & Reviews
- Follow conventional commit subjects (e.g., `feat: add nftables baseline check`).
- Reference related issues or task IDs in the body. Summarize risk, validation method, and rollback plan.
- Expect reviews to focus on security impact and competition readiness. Address feedback promptly and note follow-up items in AGENTS.md or README.md if work is deferred.
