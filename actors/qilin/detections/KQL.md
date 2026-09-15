# Qilin — Microsoft Defender XDR / KQL Hunting Queries

**Status:** reviewed defensive hunts, not production alerts or Qilin attribution signatures. Reviewed 2026-09-10. No connected query backend was available; validation is static. Each hunt states source, sensor assumptions and tuning.

MDE queries require the named Defender for Endpoint tables. SHA256 may be empty; preserve SHA1 and process identity in pivots. Registry/path representations and ActionType support need tenant verification. Splunk examples assume Windows XML extraction, `index=windows`, `Computer`, `User`, `Image`, `CommandLine`, `TargetFilename` and the stated EventCode/sourcetype. Configure Sysmon collection first; Event 4104 uses PowerShell logging and may require block-fragment reassembly. No query scans hypervisor logs implicitly.

Avoid blanket tool allowlists. Combine approved owner, instance/tenant, hash/signer, path and maintenance window. Time buckets are co-occurrence; none of these aggregates proves stage ordering. Process ancestry can be deeper than the fields shown. See [coverage and limitations](Detections.md).

## Coverage, Telemetry and Tuning Register

Query identifiers Q01–Q19 are stable across KQL and SPL; their numbered sections organize the same investigation families as the other actor dossiers. Individual queries retain their own evidence, telemetry and tuning notes.

| Query family | Evidence | Required interpretation / false positives |
|---|---|---|
| 1.x credential access | Q03–Q04; Talos credential toolkit | Authorized password recovery and IR can match; a setting change does not prove theft |
| 2.x discovery | Q07, Q15; RMM case and Group-IB computer enumeration | Inventory and administration match; the query is not an actor identifier |
| 3.x RMM/C2 | Q05; MSP instance installation | Distinguish customer instance and operator; signatures do not establish authorization |
| 4.x tunnels | Q16; Trend proxy artifact | File staging does not establish a running proxy; confirm load and traffic |
| 5.x impairment / DLL | Q13; Talos/Trend drivers | File drop and driver load are different evidence stages |
| 6.x archive / transfer | Q06, Q17; Talos/Sophos exfiltration | Connection or compression is not successful theft |
| 7.x recovery inhibition | Q09; boot/VSS evidence | Recovery testing can match; verify actual impact |
| 8.x deployment / impact | Q11–Q12, Q18; notes, logs and PsExec | Restores/research folders and legitimate deployment can match |
| 9.x multi-stage | Q19; source-linked lifecycle synthesis | Co-occurrence is not an ordered attack; first matching stage and time-bucket limits apply |
| 10.x campaign-specific | Q01–Q02, Q08, Q10, Q14 | Source and sensor scope stated per hunt; WSL remains a hypothesis |

## 1. Credential Access

### 1.1 Q03 — WDigest plaintext retention enabled

**Telemetry:** MDE RegistryValueSet or Sysmon registry Event 13.

**Review / tuning:** Legacy compatibility/security labs can match. Registry change makes future credential exposure possible; it is not evidence a password was dumped. Verify OS behavior and follow-on credential tooling.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\Control\SecurityProviders\WDigest"
| where RegistryValueName =~ "UseLogonCredential"
| where RegistryValueData in~ ("1", "0x00000001")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 1.2 Q04 — Credential toolkit and output orchestration

**Telemetry:** Process creation; script block/module logs improve renamed-tool visibility.

**Review / tuning:** NirSoft and Mimikatz have legitimate forensic/assessment uses. Prioritize new accounts/paths and proximity to WDigest changes or SMTP output. Filenames alone are evadable and not actor attribution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("netpass.exe", "WebBrowserPassView.exe", "BypassCredGuard.exe", "mimikatz.exe")
    or ProcessCommandLine contains "SharpDecryptPwd"
    or ProcessCommandLine contains "!light.bat"
    or ProcessCommandLine contains "pars.vbs"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA1, SHA256
```

## 2. Active Directory and Network Discovery

### 2.1 Q07 — RMM-launched domain reconnaissance

**Telemetry:** Endpoint process ancestry; collect parent and grandparent when available.

**Review / tuning:** MSPs legitimately enumerate domains. Review tenant/customer scope, session administrator, schedule and neighboring agent installations. Parent process checks can miss deeper shells; pivot on process tree.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName contains "ScreenConnect"
    or InitiatingProcessParentFileName contains "ScreenConnect"
    or InitiatingProcessFileName =~ "SRManager.exe"
| where ProcessCommandLine contains "/domain_trusts"
    or ProcessCommandLine contains "/dclist"
    or ProcessCommandLine contains "domain admins"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName
```

### 2.2 Q15 — Domain computer discovery or RSAT preparation

**Telemetry:** Process command lines; PowerShell script blocks improve visibility when commands are read from a file.

**Review / tuning:** Inventory, server setup and authorized administration can match. This discovers computers, not user accounts. Correlate the initiating identity and later remote service execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "ServerManagerCmd.exe")
| where ProcessCommandLine contains "Get-ADComputer"
    or ProcessCommandLine contains "RSAT-AD-PowerShell"
    or ProcessCommandLine contains "RSAT.ActiveDirectory"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
```

## 3. RMM / RAT and Remote Administration

### 3.1 Q05 — ScreenConnect instance installed through an existing RMM session

**Telemetry:** Process ancestry and installation command; verify software installation and RMM tenant logs.

**Review / tuning:** Legitimate agent rollout and upgrades are common. The suspicious distinction is an unapproved instance/customer identifier or control endpoint. ru.msi alone is insufficient; do not mistake this for a product exploit.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine contains "ru.msi" or ProcessCommandLine contains "ScreenConnect"
| where InitiatingProcessFileName contains "ScreenConnect"
    or InitiatingProcessParentFileName contains "ScreenConnect"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
```

## 4. Tunneling and C2

### 4.1 Q16 — Reported proxy-DLL staging artifact

**Telemetry:** MDE file creation/modification or Sysmon Event 11; no assumption of network traffic from a file event.

**Review / tuning:** The DLL name is generic and changeable. This is a staging lead, not detection of an active tunnel or a SystemBC family signature. Confirm the loading process, sample and subsequent network destinations.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName =~ "socks64.dll"
| where FolderPath startswith @"C:\ProgramData\"
| project Timestamp, DeviceId, DeviceName, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 5. Defense Impairment / Evasion

### 5.1 Q13 — Reported driver and DLL artifacts

**Telemetry:** MDE file events; Splunk Sysmon driver-load Event 6. The platforms detect different stages.

**Review / tuning:** Legitimate utilities may include similarly named drivers. A file drop is weaker than an actual load. Verify hash/signature, service owner, driver behavior and nearby endpoint-agent termination; no kernel exploit is inferred solely from name.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName in~ ("eskle.sys", "rwdrv.sys", "hlpdrv.sys", "dark.sys")
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 6. Collection and Exfiltration

### 6.1 Q06 — Cyberduck connection to Backblaze

**Telemetry:** MDE network events; Splunk Sysmon Event 3 requires DestinationHostname enrichment.

**Review / tuning:** Authorized backups and migrations match. Connection alone does not establish direction or bytes uploaded; obtain Cyberduck history, destination bucket/account and cloud audit. No hostname means this query can miss an event.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "Cyberduck.exe"
| where RemoteUrl endswith ".backblazeb2.com" or RemoteUrl =~ "backblazeb2.com"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessSHA1
```

### 6.2 Q17 — WinRAR archive creation

**Telemetry:** Process command line; successful archive creation and transfer require separate file/network evidence.

**Review / tuning:** Routine compression and backups match. Correlate the source data, archive path, account and subsequent browser or transfer utility. The command does not demonstrate sensitive content or completed exfiltration.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("WinRAR.exe", "rar.exe")
| where ProcessCommandLine matches regex @"(?i)(^|\s)a(\s|$)"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
```

## 7. Recovery Inhibition

### 7.1 Q09 — Safe Mode and recovery-inhibition commands

**Telemetry:** Process command lines; validate boot/System logs and VSS audit separately.

**Review / tuning:** Disaster-recovery testing and maintenance can match. The aggregate is co-occurrence, not an ordered attack chain. Require unapproved change context and preserve pre-reboot telemetry.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "bcdedit.exe" and ProcessCommandLine has "safeboot" and ProcessCommandLine contains "/set")
    or (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete", "shadows"))
    or (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl", "clear-log"))
| summarize Events=count, Tools=make_set(FileName), Commands=make_set(ProcessCommandLine, 20)
    by DeviceId, DeviceName, AccountSid, bin(Timestamp, 30m)
```

## 8. Ransomware Deployment / Impact

### 8.1 Q11 — Ransom-note creation with variable company identifier

**Telemetry:** MDE file events or Sysmon Event 11.

**Review / tuning:** Recovery simulations, research archives and restored notes match. Match either ordering; do not require a fixed ten-character extension. Alerting needs creator/process/volume context and evidence of actual file impact.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName matches regex @"(?i)^(?:README-RECOVER-.+|.+-RECOVER-README)\.txt$"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessSHA1
```

### 8.2 Q12 — QLOG encryptor-worker artifacts

**Telemetry:** File-creation telemetry; writes must be enabled for temp paths.

**Review / tuning:** Unrelated software can use QLOG/ThreadId names. The combined directory and exact filename structure is stronger; correlate with note drops, share writes and known sample hashes. Presence is not proof encryption completed.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains @"\QLOG\" or FolderPath endswith @"\QLOG"
| where FileName matches regex @"(?i)^ThreadId\([0-9]+\)\.LOG$"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 8.3 Q18 — PsExec distribution or remote service execution

**Telemetry:** Process creation; service installation and SMB auditing can corroborate remote execution.

**Review / tuning:** Software deployment and approved administration use PsExec. Renaming can evade this filename hunt. Identify both the initiating host and remote service host, account and copied payload before claiming ransomware deployment.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("PsExec.exe", "PsExec64.exe", "PSEXESVC.exe")
    or InitiatingProcessFileName =~ "PSEXESVC.exe"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 9. Multi-Stage Ransomware Correlation

### 9.1 Q19 — Multiple ransomware-relevant stages on one device and account

**Telemetry:** Process commands only. The aggregate does not implicitly include network, registry or hypervisor events.

**Review / tuning:** Three stage labels in a fixed hour are co-occurrence, not temporal ordering or attribution. Boundary-spanning activity and account changes can evade it; IR automation can match. The first matching case branch wins, and encoded/script-file commands may be invisible.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where isnotempty(AccountSid)
| extend Cmd=tolower(ProcessCommandLine), Proc=tolower(FileName)
| extend Stage=case(
    Cmd contains "mimikatz" or Cmd contains "sharpdecryptpwd" or Cmd contains "!light.bat", "CredentialAccess",
    Cmd contains "get-adcomputer" or Cmd contains "nltest", "Discovery",
    Proc in ("winrar.exe", "rar.exe", "cyberduck.exe", "rclone.exe"), "CollectionTransfer",
    Cmd contains "safeboot" or (Cmd contains "vssadmin" and Cmd contains "delete"), "RecoveryImpairment",
    Proc in ("psexec.exe", "psexec64.exe", "psexesvc.exe"), "RemoteExecution",
    "")
| where Stage != ""
| summarize Stages=dcount(Stage), StageNames=make_set(Stage),
            Commands=make_set(ProcessCommandLine, 30)
    by DeviceId, DeviceName, AccountSid, bin(Timestamp, 1h)
| where Stages >= 3
```

## 10. Source-Linked Campaign Hunts

### 10.1 Q01 — Unexpected logon scripts written into SYSVOL

**Telemetry:** MDE file events or Sysmon Event 11; collect SYSVOL paths on DCs.

**Review / tuning:** Approved policy maintenance and deployment scripts can match. Confirm policy version/owner, writer identity and endpoint execution. SYSVOL replication can duplicate events; a write is not proof a GPO was linked.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains @"\SYSVOL\"
| where FileName in~ ("IPScanner.ps1", "logon.bat")
| project Timestamp, DeviceId, DeviceName, FileName, FolderPath,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 10.2 Q02 — Credential output staged back into SYSVOL

**Telemetry:** MDE file creation/modification or Sysmon Event 11.

**Review / tuning:** LD and temp.log are generic names. Stronger context is new host-specific directories and the Q01 logon script; baseline replication and administration. Fixed buckets can miss pairs crossing boundaries.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains @"\SYSVOL\"
| where FileName in~ ("LD", "temp.log")
| extend StagingDirectory=replace_regex(FolderPath, @"(?i)\\(?:LD|temp[.]log)$", "")
| summarize Kinds=dcount(FileName), Files=make_set(FileName),
            Producers=make_set(InitiatingProcessFileName, 10)
    by DeviceId, DeviceName, StagingDirectory, bin(Timestamp, 30m)
| where Kinds == 2
```

### 10.3 Q08 — Qilin restoration-task or Run-key artifacts

**Telemetry:** Process creation for task commands; registry telemetry for Run value content.

**Review / tuning:** TeamViewer installation/repair is legitimate. Require task name plus restoration argument, or suspicious encryptor-style arguments in a Run value. Renamed task/payload can evade; generic --password alone is weak.

```kusto
let Tasks = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "TVInstallRestore" and ProcessCommandLine contains "/RESTORE"
| project Timestamp, DeviceName, Evidence=ProcessCommandLine, Account=AccountName, Kind="Task";
let Runs = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueData contains "--password" and RegistryValueData contains "--no-admin"
| project Timestamp, DeviceName, Evidence=RegistryValueData, Account=InitiatingProcessAccountName, Kind="Run";
union Tasks, Runs
```

### 10.4 Q10 — PowerShell vCenter cluster and hypervisor changes

**Telemetry:** Command-line hunting on management hosts; ScriptBlockText query for Splunk Event 4104.

**Review / tuning:** Authorized PowerCLI maintenance is expected. Commands read from a script may not appear on the command line; KQL coverage is intentionally partial. Confirm vCenter tasks, principal, SSH changes and time before treating HA/DRS changes as malicious.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "execInstalledOnly"
    or (ProcessCommandLine contains "Set-Cluster"
        and (ProcessCommandLine contains "HAEnabled" or ProcessCommandLine contains "DrsEnabled"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### 10.5 Q14 — Linux-payload or WSL clues under RMM ancestry

**Telemetry:** Windows process ancestry only; Linux/WSL auditing required to verify execution.

**Review / tuning:** WSL is legitimate developer infrastructure. This is a hypothesis-oriented hunt for the report’s unresolved execution path, not a confirmed Qilin WSL technique. A transferred ELF file may never execute locally; investigate remote target and process tree.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "SRManager.exe"
    or InitiatingProcessParentFileName =~ "SRManager.exe"
    or InitiatingProcessFileName contains "MeshAgent"
| where FileName in~ ("wsl.exe", "bash.exe") or ProcessCommandLine contains "mmh_linux_x86-64"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName
```
