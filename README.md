# THE-Baseline
Windows 11 zero-trust rebuild baseline


The Baseline is a stateful, role-aware PowerShell framework for rebuilding and hardening Windows 11 systems using a phased security baseline.

It performs in-place upgrade (if needed), applies modern Microsoft security hardening, and produces an auditable final posture report. Each phase is resumable and controlled through a JSON configuration file, making the framework suitable for fresh installs, rebuilds, and security rebaselining.

## Key Features
```
+ Phased, resumable execution using a persistent state file

+ Role-aware configuration (Workstation, Dev, Lab, Lockdown)

+ In-place Windows 11 upgrade support with signature validation

+ Modern security hardening:

+ BitLocker (TPM / TPM+PIN)

+ Microsoft Defender (CFA + ASR, audit → enforce)

+ Credential protection (LSASS PPL, WDigest)

+ Legacy protocol removal (SMB1, PowerShell v2, LLMNR, NetBIOS)

+ Firewall baseline and audit policy

+ Application control via AppLocker XML (audit → enforce)

+ Exploit protection via XML policy import

+ Optional Sysmon deployment with custom configuration

+ Privacy and debloat controls driven by config

+ Inventory snapshot (services, drivers, ports, tasks, users, software)

+ Final health summary reporting key security states

+ Offline policy import model (XML-based security policies)
```

## Designed For
```
+ Post-compromise rebuilds

+ Fresh Windows 11 deployments

+ Lab or kiosk lockdown

+ Gold image preparation

+ Local security baselines without GPO/Intune
```

## Operation
```
+ Configuration is controlled via:

+ config.json (role, enforcement levels, optional features)

+ state.json (phase tracking for resumable execution)
```

The framework safely supports:
```
+ Reboots between phases

+ Partial execution

+ Audit-first enforcement

+ Idempotent re-runs
```
