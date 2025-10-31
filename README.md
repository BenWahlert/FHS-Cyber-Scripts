# FHS Cyber Scripts

## To run Windows Scripts run the following commands in an Administrator Powershell
### Windows Desktop
```bash
irm https://raw.githubusercontent.com/BenWahlert/FHS-Cyber-Scripts/main/Windows/CP-1-1/Windows10/main.ps1 | iex
```
### Windows Standalone Server
```bash
irm https://raw.githubusercontnet.com/BenWahlert/FHS-Cyber-Scripts/main/Windows/CP-1-1/Server/main.ps1 | iex
```
### Windows DC Server
```bash
irm https://raw.githubusercontnet.com/BenWahlert/FHS-Cyber-Scripts/main/Windows/CP-1-1/DomainController/main.ps1 | iex
```
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
| `Linux/CP-1-1/` | Legacy CyberPatriot Linux automation (interactive `main.sh`, cleanup helpers, Ubuntu 16/18/20 SCAP content, CIS-CAT assessor bundle, and supporting configs). |
| `Windows/CISDesktop.ps1` | PowerShell DSC configuration for Windows 10 (v1803+) that enforces CIS Level 1/2 password, audit, and policy settings. |
| `Windows/services.ps1`, `Windows/main.ps1`, etc. | Supporting DSC resources referenced by `CISDesktop.ps1`. |
| `Windows/CP-1-1/` | CyberPatriot Windows automation (Windows 10/Server/Domain Controller scripts, GPO backups, VDI prep, ScriptLauncher UI). |
| `Windows/CP-1-1/Windows10/` | Windows 10 hardening scripts (`main.ps1`, `CPGoodies.ps1`, `services.ps1`, etc.) and Group Policy Object (GPO) backups for each Windows 10 version (folders named `1511`, `1607`, … `2004`). |

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

## Running the Legacy CP Linux Toolkit (`Linux/CP-1-1/`)

After `Linux/script.sh` completes, you can optionally layer the older CyberPatriot automation to mirror the original competition workflow.

1. **Clone Legacy CP Content**  
   The toolkit expects a working copy in `~/tmp/cp`. Run the provided wrapper to fetch it:
   ```bash
   sudo bash Linux/CP-1-1/main.sh
   ```
   This script:
   - Ensures `~/tmp/cp` is populated with the upstream CP repository.
   - Prompts for the detected Ubuntu version (16.04 or 18.04) and launches the corresponding CIS hardening script from `~/tmp/cp/CP/ubuntu*/...`.
   - Offers to run `CPgoodies1.sh`, which deletes banned media, removes offensive packages, and copies Firefox/password templates.

   For Ubuntu 20.04, run `sudo bash Linux/CP-1-1/main1.sh`, which adds UFW defaults before invoking the 20.04 hardener (`~/tmp/cp/CP/ubuntu20/UBUNTU2004_LBK.sh`).

2. **Optional Helpers**
   - `Linux/CP-1-1/CPgoodies1.sh` — extra cleanup (media purge, package removals, firewall updates).
   - `Linux/CP-1-1/debloat.sh` — removes known unwanted packages (commented in `main1.sh`; run manually if needed).
   - `Linux/CP-1-1/lynis.sh` — executes a Lynis audit for reporting.
   - `Linux/CP-1-1/CIS.sh` — launches the CIS-CAT assessor (uses `Linux/CP-1-1/Assessor-CLI` bundle).

3. **Ubuntu Version Folders (`ubuntu16/`, `ubuntu18/`, `ubuntu20/`)**
   These directories hold the actual CIS/SCAP remediation content. You normally don’t run files inside them directly—`main.sh`/`main1.sh` call into them automatically. If you need a specific control, you can source the scripts manually:
   ```bash
   sudo bash Linux/CP-1-1/ubuntu18/ubuntu-scap-security-guides/cis-hardening/Canonical_Ubuntu_18.04_CIS_v1.0.0-harden.sh lvl1_workstation
   ```
   Adjust the path/level (`lvl1_workstation`, `lvl2_workstation`, etc.) for your needs.

4. **Configuration Payloads**
   - `Linux/CP-1-1/common-password`, `pwquality.conf` — PAM/password quality templates copied by the CP scripts.
   - `Linux/CP-1-1/autoconfig.js`, `mozilla.cfg` — Firefox autoconfig files.
   - `Linux/CP-1-1/Ubuntu Manual Configuration.docx` — checklist for manual tasks.

> **Tip:** The legacy scripts assume root, network access to GitHub, and Firefox installed at `/usr/lib/firefox`. Review them before use on modern systems.

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
   - Cloned content, VDI optimization tools, and script logs will be located under `~\Downloads\cp`.
   - `Windows/CP-1-1/Windows10/Firewall` includes reusable `.wfw` firewall exports.

---

## Windows Group Policy Backups (`Windows/CP-1-1/Windows10/<build>/`)

Each numbered directory (`1511`, `1607`, `1703`, `1709`, `1803`, `1809`, `1903`, `1909`, `2004`) contains:

- `Standard/` – CIS Level 1-aligned GPOs.
- `Full/` – Level 1 + Level 2 + competition extras (BitLocker, NetBIOS, etc.).
- Subfolders such as `COMP-L1`, `SERVICES-L1`, `USER-L1`, `BITLOCKER`, each holding an LGPO backup (`manifest.xml`, `Backup.xml`, `registry.pol`, etc.).

***

## Windows/CP-1-1 Toolkit Map

`Windows/CP-1-1` bundles the Windows-side tooling we use during competitions. Highlights:

| Item | Description |
| ---- | ----------- |
| `Windows10/` | Windows 10 hardening hub containing `main.ps1`, supporting scripts (`CPGoodies.ps1`, `services.ps1`, `FeaturesApps.ps1`, `harden.ps1`, `badprograms.ps1`, `ScriptLauncher.ps1`), Firefox policy files, firewall exports, and the version-specific GPO backups listed above. |
| `Server/` | Windows Server 2016/2019 automation (PowerShell scripts, firewall templates, LGPO binaries, and GPO backups in `Server2016`/`Server2019`). |
| `DomainController/` | Domain controller variant of the server toolkit with matching scripts, firewall exports, and policy backups. |
| `VDI/` | Workspace used by `Windows10/main.ps1` for cloning Microsoft’s Virtual Desktop Optimization Tool (or the legacy VDI optimization repo for older builds). |
| Documentation & templates (`finsihedcyberpatriot.inf`, `Windows10/Firewall/*`, etc.) | Security templates, firewall exports, and reference files applied during the Windows hardening process. |

Keep this map handy when you need to locate a specific script or asset quickly during a hardening run.

***

## Linux/CP-1-1 Toolkit Map

The legacy CyberPatriot Linux kit now lives under `Linux/CP-1-1`. Use these assets when you need the older interactive workflow instead of `Linux/script.sh`.

| Item | Description |
| ---- | ----------- |
| `main.sh`, `main1.sh` | Interactive entry points that clone the original CP repository into `~/tmp/cp`, prompt for Ubuntu version, and launch the appropriate CIS hardening scripts. `main1.sh` includes additional UFW tweaks and password policy resets. |
| `CPgoodies1.sh`, `debloat.sh`, `lynis.sh`, `CIS.sh` | Optional helpers: `CPgoodies1.sh` performs cleanup and package removal, `debloat.sh` removes unwanted software, `lynis.sh` runs a Lynis audit, and `CIS.sh` executes the CIS-CAT assessor CLI. |
| `Assessor-CLI/` | CIS-CAT assessor bundle (Java) used for compliance reporting. Referenced by `CIS.sh` if you run the assessor locally. |
| `ubuntu16/`, `ubuntu18/`, `ubuntu20/` | Ubuntu-specific CIS/SCAP hardening content aligned with each LTS build, matching the paths expected by the CP scripts. |
| `common-password`, `pwquality.conf`, `autoconfig.js`, `mozilla.cfg` | Configuration payloads that the CP scripts copy into `/etc/pam.d/common-password`, `/etc/security/pwquality.conf`, and Firefox directories. |
| `Ubuntu Manual Configuration.docx` | Competition checklist covering manual steps that accompany the automated scripts. |

***
