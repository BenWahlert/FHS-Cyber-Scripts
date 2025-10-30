# FHS Cyber Scripts

## To run Windows Scripts run the following commands in an Administrator Powershell
### Windows Desktop
`irm https://raw.githubusercontent.com/BenWahlert/FHS-Cyber-Scripts/main/Windows/CP-1-1/Windows10/main.ps1 | iex`
### Windows Standalone Server
`irm https://raw.githubusercontnet.com/BenWahlert/FHS-Cyber-Scripts/main/Windows/CP-1-1/Server/main.ps1 | iex`
### Windows DC Server
`irm https://raw.githubusercontnet.com/BenWahlert/FHS-Cyber-Scripts/main/Windows/CP-1-1/DomainController/main.ps1 | iex`

## Information

This repository bundles the automation the Fairview High School Cyber team uses to harden lab hosts quickly. It houses two main families of tooling:

- **Linux** remediation scripts that impose CIS-style kernel, AppArmor, firewall, and service controls.
- **Windows** Desired State Configuration (DSC) baselines and competition utilities for different Windows 10 feature releases.

Use this document as the field guide for choosing the right assets and executing them safely.

---

## Repository Layout

| Path | Purpose |
| ---- | ------- |
| `Linux/` | Bash remediation scripts. `script.sh` is the master runbook for Linux module lockdowns, AppArmor checks, nftables provisioning, and other CIS controls. |
| `Windows/CISDesktop.ps1` | PowerShell DSC configuration for Windows 10 (v1803+) that enforces CIS Level 1/2 password, audit, and policy settings. |
| `Windows/services.ps1`, `Windows/main.ps1`, etc. | Supporting DSC resources referenced by `CISDesktop.ps1`. |
| `Windows/CP-1-1/` | CyberPatriot (“CP”) automation. Contains Windows and Linux helper scripts, policy backups, and third-party assessor tooling. |
| `Windows/CP-1-1/Windows10/` | Windows 10 hardening scripts (`main.ps1`, `CPGoodies.ps1`, `services.ps1`, etc.) and Group Policy Object (GPO) backups for each Windows 10 version (folders named `1511`, `1607`, … `2004`). |
| `AGENTS.md` | Contributor guide describing coding conventions, review expectations, and validation tips. |

> **Tip:** Most Windows scripts expect to be run from inside `~\Downloads\cp` after cloning this repository. Linux scripts assume root access on the local host.

---

## Running the Linux Script (`Linux/script.sh`)

1. **Requirements**
   - Debian/Ubuntu system (script relies on `apt`, `systemctl`, `shellcheck`-friendly Bash).
   - Root privileges.
   - Optional: `shellcheck` to lint before execution (`shellcheck Linux/script.sh`).

2. **Preparation**
   ```bash
   sudo bash -n Linux/script.sh          # Syntax check
   sudo shellcheck Linux/script.sh       # Static analysis (optional but encouraged)
   ```

3. **Execution**
   ```bash
   sudo bash Linux/script.sh
   ```

   The script:
   - Disables unneeded kernel modules (e.g., `cramfs`, `usb-storage`) via `/etc/modprobe.d`.
   - Audits and enforces AppArmor settings, `/tmp` remount semantics, GRUB file permissions, nftables firewall policy, and various sysctl tunables.
   - Reports remediation status to the console; watch for warnings about missing modules or config files.

4. **Post-run Tasks**
   - Review `/etc/modprobe.d/`, `/etc/sysctl.d/`, and `/etc/nftables.rules` to ensure values align with your environment.
   - Reboot if kernel parameters or firewall services were enabled for the first time (`sudo reboot`).

---

## Running the Windows DSC Baseline (`Windows/CISDesktop.ps1`)

1. **Requirements**
   - Windows 10 machine (v1803 or newer).
   - Administrative PowerShell session.
   - `SecurityPolicyDsc`, `AuditPolicyDsc`, and `PSDesiredStateConfiguration` modules (script auto-installs from PowerShell Gallery).

2. **Usage**
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   pwsh -File Windows\main.ps1           # primes required modules
   pwsh -File Windows\CISDesktop.ps1     # compiles and applies the CIS configuration
   ```

3. **What It Does**
   - Downloads DSC resources (`AuditPolicyDsc`, `SecurityPolicyDsc`, `ComputerManagementDsc`).
   - Defines the `CIS_Windows10_v181` configuration covering password policies, user rights assignments, audit settings, and registry hardening.
   - Applies the configuration to the local node via DSC.

4. **Afterwards**
   - Review DSC output for resources that required remediation.
  - Run `Test-DscConfiguration` to confirm the machine is converged.
  - Combine with the Group Policy templates in `Windows/CP-1-1/Windows10/<build>/` if you need a GUI-based policy import.

---

## Running the Windows 10 CP Automation (`Windows/CP-1-1/Windows10/main.ps1`)

`main.ps1` is a guided wizard used during CyberPatriot events. It drives several subordinate scripts and policy imports.

1. **Open Elevated PowerShell**
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   pwsh -File Windows\CP-1-1\Windows10\main.ps1
   ```

2. **What Happens**
   - Installs Chocolatey plus baseline tooling (Git, Malwarebytes, Avast trial, Firefox, LAPS).
   - Clones this repository into `~\Downloads\cp`.
   - Offers interactive prompts to run:
     - `CPGoodies.ps1` (firewall import, telemetry/privacy tweaks, registry lockdown).
     - `services.ps1` (disables unwanted services, enables required ones).
     - `FeaturesApps.ps1` (removes optional Windows features and bundled apps).
     - `harden.ps1` (firewall + policy hardening).
   - Always runs `badprograms.ps1` to remove banned software.
   - Deploys Firefox configuration files.
   - Prompts for a reboot after running `gpupdate /force`.

3. **Version-Specific Policies**
   - After `main.ps1`, import Group Policy backups from `Windows/CP-1-1/Windows10/<build>/Standard` or `Full` using `LGPO.exe`.
   - The `<build>` folder should match the Windows 10 feature update installed (e.g., `1909`).

4. **Artifacts**
   - `~\Downloads\cp` holds cloned content, VDI optimization tools, and script logs.
   - `Windows/CP-1-1/Windows10/Firewall` includes reusable `.wfw` firewall exports.

---

## Windows Group Policy Backups (`Windows/CP-1-1/Windows10/<build>/`)

Each numbered directory (`1511`, `1607`, `1703`, `1709`, `1803`, `1809`, `1903`, `1909`, `2004`) contains:

- `Standard/` – CIS Level 1-aligned GPOs.
- `Full/` – Level 1 + Level 2 + competition extras (BitLocker, NetBIOS, etc.).
- Subfolders such as `COMP-L1`, `SERVICES-L1`, `USER-L1`, `BITLOCKER`, each holding an LGPO backup (`manifest.xml`, `Backup.xml`, `registry.pol`, etc.).

***

## Windows/CP-1-1 Toolkit Map

`Windows/CP-1-1` bundles everything the team uses during competitions. Highlights:

| Item | Description |
| ---- | ----------- |
| `Windows10/` | Windows 10 hardening hub containing `main.ps1`, supporting scripts (`CPGoodies.ps1`, `services.ps1`, `FeaturesApps.ps1`, `harden.ps1`, `badprograms.ps1`), Firefox policy files, firewall exports, and the version-specific GPO backups listed above. |
| `Server/` | Equivalent tooling for Windows Server 2016/2019, including server-focused scripts, firewall templates (`Firewall2016`, `Firewall2019`, `.wfw` exports), LGPO binaries, and GPO backups (`Server2016`, `Server2019`). |
| `VDI/` | Workspace used by `main.ps1` for cloning Microsoft’s Virtual Desktop Optimization Tool (or legacy VDI optimization repo on older builds). |
| `Assessor-CLI/` | CIS-CAT assessor bundle (Java CLI + data files) for generating CIS benchmark compliance reports. Run via `Windows/CP-1-1/CIS.sh` or execute the wrapped JAR directly. |
| `ubuntu16/`, `ubuntu18/`, `ubuntu20/` | Ubuntu CIS hardening content aligned with each LTS release. The Linux `main.sh` script invokes these tree paths. |
| `main.sh`, `main1.sh`, `CPgoodies1.sh`, `debloat.sh`, `lynis.sh`, `CIS.sh` | Bash helpers for Linux-based competition images. `main.sh` is the interactive entry point; `CPgoodies1.sh` performs extra cleanup; `debloat.sh`/`lynis.sh` remove bloat and run audits; `CIS.sh` launches the assessor. |
| `autoconfig.js`, `mozilla.cfg`, `local-settings.js`, `pwquality.conf`, `common-password` | Configuration payloads (Firefox autoconfig, password quality settings, banned-password list) that the scripts copy into place on target machines. |
| Documentation (`Ubuntu Manual Configuration.docx`, `finsihedcyberpatriot.inf`, etc.) | Reference notes and checklists packaged with the toolkit. |

Keep this map handy when you need to locate a specific script or asset quickly during a hardening run.

***


