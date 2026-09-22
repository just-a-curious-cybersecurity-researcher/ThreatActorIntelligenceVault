# LockBit — Microsoft Defender XDR / KQL Hunting Queries

**Presentation reviewed:** 2026-09-17.

**Status:** defensive hunts requiring local validation and tuning; not actor-attribution signatures. No connected KQL/SPL backend was available for execution.

## Scope and Requirements

Most entries use Defender for Endpoint Advanced Hunting tables. L19 uses the separate Sentinel/Azure Monitor `WindowsEvent` table; L36 uses `Syslog` containing forwarded ESXi telemetry. Those two entries require their stated connectors and must run in a workspace containing those tables. ESXi has no assumed native Defender endpoint agent.

SHA-256 fields can be empty. File-event coverage is selective and does not constitute a complete record of every file write. The rename-burst query requires previous filename and process creation time. Commands are string observations, not proof of API calls or successful effects.

> **Environment-specific tuning is mandatory.** Baseline administration, RMM, backups, red-team work and evidence-handling systems. Exclusions should combine account, signer/hash, path and approved purpose rather than a tool name alone.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 4 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 2. Active Directory and Network Discovery | 3 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 3. Persistence and Remote Administration | 4 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 4. Tunneling and C2 | 3 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 5. Defense Evasion and Impairment | 6 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 6. Collection and Exfiltration | 3 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 7. Recovery Inhibition | 2 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 8. Deployment and Impact | 4 queries | Per-entry source, telemetry and tuning; correlate before attribution |
| 9. Multi-Stage Correlation | 1 query | Per-entry source, telemetry and tuning; correlate before attribution |
| 10. Campaign Artifact Hunts | 10 queries | Per-entry source, telemetry and tuning; correlate before attribution |

## Interpretation Notes

Every ID is paired across KQL and Splunk by investigative intent. Differences in event sources and aggregation are stated in the entry; the pair is not a claim of byte-for-byte identical results. Thresholds are starting points. Fixed time buckets can miss boundary-spanning bursts; same-host ordering does not prove causation. Pair PID with creation time to reduce PID-reuse mistakes.

Exact-hash sets keep builders, decryptors, legitimate utilities and SmokeLoader outside confirmed ransomware-payload hunts. Possible impostors have their own query. Published source predicates adapted to another engine are marked as local adaptations; none is represented as a vendor-authored KQL/SPL query.

The [detection index](Detections.md) records coverage; source-to-query provenance is centralized in [References](../References.md#detection-implementation-provenance).

## 1. Credential Access

### 1.1 L01 — LSASS dump through comsvcs MiniDump

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** MiniDump may target a numeric PID; inspect the target process and resulting file. Approved diagnostics can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rundll32.exe" and ProcessCommandLine contains "comsvcs.dll" and ProcessCommandLine contains "MiniDump"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 1.2 L02 — Credential extraction utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Names can change. Security research, authorized tests and password recovery can match; correlate with account and destination.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("mimikatz.exe","lazagne.exe","passwordfox.exe","extpassword.exe") or ProcessCommandLine contains "sekurlsa::" or ProcessCommandLine contains "lsadump::"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 1.3 L03 — SAM and SYSTEM hive export

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** This observes export intent, not successful collection. Registry backup and forensic collection are legitimate alternatives.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "reg.exe" and ProcessCommandLine has "save" and (ProcessCommandLine contains @"HKLM\SAM" or ProcessCommandLine contains @"HKLM\SYSTEM" or ProcessCommandLine contains @"HKEY_LOCAL_MACHINE\SAM")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 1.4 L04 — Citrix campaign dump and cabinet artifacts

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents / normalized EDR file events.

**Review / tuning:** Generic filenames require matching public/tasks directory context and a suspicious writer. Restored evidence can match.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where (FileName =~ "a.png" and FolderPath contains @"\Users\Public") or (FileName in~ ("a.cab","am.cab","em.cab","z.txt") and FolderPath contains @"\Windows\Tasks")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, SHA256
```

## 2. Active Directory and Network Discovery

### 2.1 L05 — Directory discovery utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Use approved assessment scope and administrative baseline; executable names alone are low-specificity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("adfind.exe","sharphound.exe","bloodhound.exe","seatbelt.exe") or ProcessCommandLine has "SharpHound"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 2.2 L06 — Native domain and session discovery

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Discovery is common. Prioritize new remote sessions and multiple discovery commands followed by tool deployment.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has_any ("group","view","user")) or FileName in~ ("nltest.exe","quser.exe","whoami.exe")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 2.3 L07 — SMB and remote-management connection fan-out

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents / normalized EDR network events.

**Review / tuning:** Approximate unique-host count and five-minute buckets are tunable. Inventory tools, management servers and bucket boundaries affect results.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess" and RemotePort in (445,3389,5985,5986)
| where isnotempty(InitiatingProcessCreationTime)
| summarize Targets=dcount(RemoteIP), Addresses=make_set(RemoteIP,100)
    by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessId,
       InitiatingProcessCreationTime, bin(Timestamp,5m)
| where Targets >= 20
```

## 3. Persistence and Remote Administration

### 3.1 L08 — Remote service and WMI execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** PsExec and WMI are legitimate. Determine source account, remote target and payload; PSEXESVC may be renamed.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe","psexec64.exe","psexesvc.exe","wmiexec.exe") or InitiatingProcessFileName =~ "wmiprvse.exe"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 3.2 L09 — Scheduled-task creation and UpdateAdobeTask

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** schtasks command lines miss task creation through COM/RPC. Collect task registration events as an additional source.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe" and (ProcessCommandLine contains "/create" or ProcessCommandLine contains "UpdateAdobeTask" or ProcessCommandLine contains "MEGAcmd")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 3.3 L10 — Remote administration software execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Match unapproved installation/use, not all instances of an approved vendor. Process metadata may survive file renaming.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("anydesk.exe","anydeskmsi.exe","teamviewer.exe","ateraagent.exe","srutility.exe") or FileName startswith "ScreenConnect" or ProcessVersionInfoProductName contains "ScreenConnect"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 3.4 L11 — Executable Run-key references in writable paths

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents / normalized EDR registry events.

**Review / tuning:** Generic persistence hunt. Key writes are not proof that a relaunch occurred; approved updaters can match.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d) and ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\CurrentVersion\Run" or RegistryKey endswith @"\CurrentVersion\RunOnce"
| where RegistryValueData contains @"\Temp\" or RegistryValueData contains @"\Users\Public\"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 4. Tunneling and C2

### 4.1 L12 — SSH forwarding and renamed Plink

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** This inspects case-sensitive uppercase forwarding flags; lowercase SSH -l is a login name. Approved tunnels can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("plink.exe","ssh.exe","servicehost.exe")
| where ProcessCommandLine matches regex @"(?:^|\s)-[RLD](?:\s|\d)"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
          AccountName, InitiatingProcessFileName
```

### 4.2 L13 — Ngrok and Ligolo execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Development tunnels and penetration testing are common alternatives. Renamed tools can evade this name/argument hunt.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ngrok.exe","ligolo.exe","ligolo-ng.exe") or (ProcessCommandLine contains "ngrok" and ProcessCommandLine has_any ("tcp","http","start"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 4.3 L14 — Historical Citrix-campaign network endpoints

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents / normalized EDR network events.

**Review / tuning:** Historical pivot only. Revalidate ownership; connection establishes contact, not a fresh compromise or a 5.0 campaign.

```kusto
let HistoricalIPs=dynamic(["81.19.135.219","81.19.135.220","81.19.135.226","193.201.9.224","62.233.50.25","168.100.9.137","206.188.197.22","141.98.9.137"]);
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteIP in (HistoricalIPs)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType
```

## 5. Defense Evasion and Impairment

### 5.1 L15 — Elevation-related COM activation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** CLSID activation can be legitimate. Correlate the initiating binary and integrity transition; this does not prove a successful bypass.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "dllhost.exe" and (ProcessCommandLine contains "3E5FC7F9-9A51-4367-9063-A120244FBEC7" or ProcessCommandLine contains "D2E7041B-2927-42FB-8E9F-7CE93B6DC937")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 5.2 L16 — Defender configuration changes through PowerShell

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** This captures process-command strings, not script blocks or successful policy changes. Configuration management and incident response may match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Set-MpPreference","Add-MpPreference") and ProcessCommandLine has_any ("DisableRealtimeMonitoring","ExclusionPath","ExclusionProcess")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 5.3 L17 — Safe Mode boot configuration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Administrative repair can use Safe Mode. Boot configuration requests are not evidence that a reboot or encryption followed.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bcdedit.exe" and ProcessCommandLine has "safeboot" and ProcessCommandLine contains "/set"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 5.4 L18 — Backup or security service stop commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Generic command route. Direct API service stops are outside this query; match successful state changes separately.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sc.exe","net.exe","net1.exe","powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("stop","Stop-Service","Set-Service","config") and ProcessCommandLine has_any ("vss","sqlwriter","veeam","windefend","wbengine")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 5.5 L19 — Event-log clearing, including API-originated effects

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sentinel WindowsEvent / Windows event channels forwarded to Splunk.

**Review / tuning:** WindowsEvent is a Sentinel/Azure Monitor table, not a Defender-only table. Event forwarding must precede local clearing; maintenance can match.

```kusto
WindowsEvent
| where TimeGenerated > ago(7d)
| where (EventID == 1102 and Channel =~ "Security")
    or (EventID == 104 and Provider =~ "Microsoft-Windows-Eventlog")
| project TimeGenerated, Computer, Channel, Provider, EventID, EventData, RawEventData
```

### 5.6 L20 — Process and security-tool manipulation utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** These utilities have legitimate uses and may be renamed. Combine with security-service changes or a malicious payload.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("processhacker.exe","gmer.exe","pchunter64.exe","tdsskiller.exe","backstab.exe","defendercontrol.exe","powertool.exe")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

## 6. Collection and Exfiltration

### 6.1 L21 — Rclone and MEGA transfer clients

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Transfers and synchronization are legitimate. Validate account, destination, volume and data owner; a process is not proof of theft.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("rclone.exe","rclone") and ProcessCommandLine has_any ("copy","sync","move")) or FileName in~ ("megacmd.exe","mega-put.exe","megasync.exe")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 6.2 L22 — Archive creation and cabinet staging

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Baselines should include backup, packaging and deployment systems. Archive creation alone does not prove exfiltration.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("7z.exe","7za.exe") and ProcessCommandLine has "a") or (FileName =~ "makecab.exe" and (ProcessCommandLine contains @"\Windows\Tasks" or ProcessCommandLine contains @"\Users\Public"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 6.3 L23 — StealBit-named artifact triage

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Name-only heuristic. Renaming evades it and researcher files can match. Confirm hash/configuration and outbound transfer before classification.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName startswith "stealbit" or ProcessVersionInfoOriginalFileName startswith "stealbit"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

## 7. Recovery Inhibition

### 7.1 L24 — Shadow-copy deletion through native utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Successful deletion requires privileges and valid syntax. WMI/COM calls without a child utility are not covered.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows")) or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 7.2 L25 — Backup removal and recovery-boot changes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Maintenance and disaster recovery can match. Determine whether backups were removed and whether boot changes became effective.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete") or (FileName =~ "bcdedit.exe" and (ProcessCommandLine contains "recoveryenabled" or ProcessCommandLine contains "bootstatuspolicy"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

## 8. Deployment and Impact

### 8.1 L26 — Executable placement in domain policy paths

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents / normalized EDR file events.

**Review / tuning:** Software-distribution files in SYSVOL can be legitimate. Correlate with GPO changes, task creation and the writer identity.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where (FolderPath contains @"\SYSVOL\" or FolderPath contains @"\NETLOGON\") and (FileName endswith ".exe" or FileName endswith ".dll")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, SHA256
```

### 8.2 L27 — Historical and Black note or suffix artifacts

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents / normalized EDR file events.

**Review / tuning:** The generated README pattern is shared by other families. Restores, evidence handling and source-code repositories can match.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName =~ "Restore-My-Files.txt" or FileName endswith ".lockbit" or FileName matches regex @"(?i)^[a-z0-9]{9}\.README\.txt$"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, SHA256
```

### 8.3 L28 — Burst of new hexadecimal suffixes

**Origin:** Repository-authored KQL/SPL adaptation of Trend Micro's published Vision One rename predicate; local thresholding.

**Telemetry:** DeviceFileEvents rename events / EDR with rename and previous-name telemetry.

**Review / tuning:** Local aggregation added to the vendor's predicate. Require process identity; thresholds and bucket boundaries need tuning. Not an entropy or invisible-mode detector.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType == "FileRenamed"
| where FileName matches regex @"(?i)\.[a-f0-9]{16}$"
| where not(PreviousFileName matches regex @"(?i)\.[a-f0-9]{16}$")
| where isnotempty(InitiatingProcessCreationTime)
| extend FileIdentity=strcat(FolderPath, "\\", FileName)
| summarize Files=dcount(FileIdentity), Examples=make_set(FileName,10)
    by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessId,
       InitiatingProcessCreationTime, bin(Timestamp,5m)
| where Files >= 25
```

### 8.4 L29 — 5.0 note or hexadecimal suffix triage

**Origin:** Repository-authored KQL/SPL adaptation of Trend Micro's published Vision One artifact predicates.

**Telemetry:** DeviceFileEvents / normalized EDR file events.

**Review / tuning:** The OR preserves note-only matches. A hexadecimal suffix can also occur in native 4.0 or benign data. Correlate with a writer and recent file impact.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName =~ "ReadMeForDecrypt.txt" or FileName matches regex @"(?i)\.[a-f0-9]{16}$"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, SHA256
```

## 9. Multi-Stage Correlation

### 9.1 L30 — Recovery inhibition followed by note creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents + DeviceFileEvents / normalized EDR process and file events.

**Review / tuning:** Ordered same-host correlation within 30 minutes, not proof of causation or the same process. Multiple candidates can create duplicate pairs; scope the host/time during investigation.

```kusto
let recovery = DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
| project DeviceId, RecoveryTime=Timestamp, RecoveryCommand=ProcessCommandLine;
DeviceFileEvents
| where Timestamp > ago(1d) and ActionType == "FileCreated"
| where FileName in~ ("ReadMeForDecrypt.txt","Restore-My-Files.txt")
    or FileName matches regex @"(?i)^[a-z0-9]{9}\.README\.txt$"
| project DeviceId, DeviceName, NoteTime=Timestamp, FileName, FolderPath, InitiatingProcessFileName
| join kind=inner recovery on DeviceId
| where NoteTime between (RecoveryTime .. RecoveryTime + 30m)
| project DeviceName, RecoveryTime, NoteTime, RecoveryCommand, FileName, FolderPath, InitiatingProcessFileName
```

## 10. Campaign Artifact Hunts

### 10.1 L31 — Published 5.0 payload hashes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents + DeviceFileEvents / normalized EDR SHA-256.

**Review / tuning:** Exact historical artifact match only; missing SHA256 reduces coverage. Evidence repositories and quarantine/restores can match. No sample execution is implied by a file record.

```kusto
let PublishedHashes=dynamic(["7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82","180e93a091f8ab584a827da92c560c78f468c45f2539f73ab2deb308fb837b38","4dc06ecee904b9165fa699b026045c1b6408cc7061df3d2a7bc2b7b4f0879f4d","90b06f07eb75045ea3d4ba6577afc9b58078eafeb2cdd417e2a88d7ccf0c0273","98d8c7870c8e99ca6c8c25bb9ef79f71c25912fbb65698a9a6f22709b8ad34b6","6d0166d181db1f6c381c3ff5fff4fe4106fbc17bc29316e3cf3f65136ee4803c"]);
union
    (DeviceProcessEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="Process"),
    (DeviceFileEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="File")
| where isnotempty(SHA256) and SHA256 in~ (PublishedHashes)
| project Timestamp, DeviceName, RecordType, FileName, FolderPath, SHA256
```

### 10.2 L32 — Black payload hashes, excluding builder and decryptor

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents + DeviceFileEvents / normalized EDR SHA-256.

**Review / tuning:** Exact historical artifact match only; missing SHA256 reduces coverage. Evidence repositories and quarantine/restores can match. No sample execution is implied by a file record. The builder leak prevents automatic service attribution.

```kusto
let PublishedHashes=dynamic(["0d38f8bf831f1dbbe9a058930127171f24c3df8dae81e6aa66c430a63cbe0509","9a34909703d679b590d316eb403e12e26f73c8e479812f1d346dcba47b44bc6e","39c363d01fb5cd0ed3eeb17ca47be0280d93a07dda9bc0236a0f11b20ed95b4c","80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce","391a97a2fe6beb675fe350eb3ca0bc3a995fda43d02a7a6046cd48f042052de5","506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51","742489bd828bdcd5caaed00dccdb7a05259986801bfd365492714746cb57eb55","a56b41a6023f828cccaaef470874571d169fdb8f683a75edd430fbd31a2c3f6e","b951e30e29d530b4ce998c505f1cb0b8adc96f4ba554c2b325c0bd90914ac944","c6cf5fd8f71abaf5645b8423f404183b3dea180b69080f53b9678500bab6f0de","d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee","f9b9d45339db9164a3861bf61758b7f41e6bcfb5bc93404e296e2918e52ccc10","fd98e75b65d992e0ccc64e512e4e3e78cb2e08ed28de755c2b192e0b7652c80a","f34dd8449b9b03fedde335f8be51bdc7f96cda29a2dde176c3db667ba0713c6f"]);
union
    (DeviceProcessEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="Process"),
    (DeviceFileEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="File")
| where isnotempty(SHA256) and SHA256 in~ (PublishedHashes)
| project Timestamp, DeviceName, RecordType, FileName, FolderPath, SHA256
```

### 10.3 L33 — NG-Dev configuration suffix

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents / normalized EDR file events.

**Review / tuning:** Suffix is configurable and can occur in evidence copies. This is not an identification of the native 2025 4.0 branch.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName endswith ".locked_for_LockBit"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, SHA256
```

### 10.4 L34 — Citrix staging DLLs and scripts

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents / normalized EDR file events.

**Review / tuning:** Names are generic. Require writable-directory context, matching hashes and remote-execution ancestry where available.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName in~ ("Mag.dll","adobelib.dll","123.ps1") and (FolderPath contains @"\Users\Public" or FolderPath contains @"\Temp")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, SHA256
```

### 10.5 L35 — Payload zeroing through fsutil

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Sparse-file maintenance and administrative tooling can match. Verify the target is the ransomware launcher and correlate with process termination.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "fsutil.exe" and ProcessCommandLine has_all ("file","setZeroData")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

### 10.6 L36 — VM inventory and power-state operations in forwarded ESXi logs

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sentinel Syslog from ESXi / Splunk forwarded ESXi shell or management logs.

**Review / tuning:** Requires actual forwarded shell/management command text. These are normal administration operations; combine with unusual ELF execution and datastore impact. Logs may not include full commands.

```kusto
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage contains "vim-cmd"
| where SyslogMessage contains "getallvms" or SyslogMessage contains "power.off"
| project TimeGenerated, Computer, HostName, ProcessName, SyslogMessage
```

### 10.7 L37 — Native 4.0 sample hashes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents + DeviceFileEvents / normalized EDR SHA-256.

**Review / tuning:** Exact historical artifact match only; missing SHA256 reduces coverage. Evidence repositories and quarantine/restores can match. No sample execution is implied by a file record.

```kusto
let PublishedHashes=dynamic(["563cd800e80253a7051ea8a1bd690d123cf7820c355addeeaaabaa227984d9cb","82d89a75d80e80e4be42c9eb79e401558c9fa3175648cd0c0467f2de1a07a908","3552dda80bd6875c1ed1273ca7562c9ace3de2f757266dae70f60bf204089a4a","20dd91f589ea77b84c8ed0f67bce837d1f4d7688e56754e709d467db0bea03c9","33376f74c2f071ff30bab1c2d19d9361d16ebaa3dee73d3b595f6d789c15f620","2f5051217414f6e465f4c9ad0f59c3920efe8ff11ba8e778919bac8bd53d915c","48e2033a286775c3419bea8702a717de0b2aaf1e737ef0e6b3bf31ef6ae00eb5","21e51ee7ba87cd60f692628292e221c17286df1c39e36410e7a0ae77df0f6b4b","9733092223c428fc0e44a90b01c7f77a97bb1205def8be1224ac68969182638e","a33f21d28bd83a9501257ee727c46486989bdfea6d5cb9f1c12c9a67296b21b1","0ace4e1158ab5b7723493f39d6949309e00e4a71804f0b09e33d5d48a28cb061","36f48ef3776c01d63a2fd594d52dfb7402ea634162fd079b0d942367a2fbed56","4f76df691e2ea292b56812eb3167efcab655382d632048ff63781f5d41f86433","67ac04c1b7526288194e53da33cc0e9661687fd4fbbf12156e5ef6dd2a4108eb"]);
union
    (DeviceProcessEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="Process"),
    (DeviceFileEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="File")
| where isnotempty(SHA256) and SHA256 in~ (PublishedHashes)
| project Timestamp, DeviceName, RecordType, FileName, FolderPath, SHA256
```

### 10.8 L38 — Original and Red historical payloads

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents + DeviceFileEvents / normalized EDR SHA-256.

**Review / tuning:** Exact historical artifact match only; missing SHA256 reduces coverage. Evidence repositories and quarantine/restores can match. No sample execution is implied by a file record. Excludes the separately classified historical decryptor.

```kusto
let PublishedHashes=dynamic(["0a937d4fe8aa6cb947b95841c490d73e452a3cafcd92645afc353006786aba76","0e66029132a885143b87b1e49e32663a52737bbff4ab96186e9e5e829aa2915f","0f178bc093b6b9d25924a85d9a7dde64592215599733e83e3bbc6df219564335","0f5d71496ab540c3395cfc024778a7ac5c6b5418f165cc753ea2b2befbd42d51","13849c0c923bfed5ab37224d59e2d12e3e72f97dc7f539136ae09484cbe8e5e0","15a7d528587ffc860f038bb5be5e90b79060fbba5948766d9f8aa46381ccde8a","1b109db549dd0bf64cadafec575b5895690760c7180a4edbf0c5296766162f18","1e3bf358c76f4030ffc4437d5fcd80c54bd91b361abb43a4fa6340e62d986770","256e2bf5f3c819e0add95147b606dc314bbcbac32a801a59584f43a4575e25dc","26b6a9fecfc9d4b4b2c2ff02885b257721687e6b820f72cf2e66c1cae2675739","2b8117925b4b5b39192aaaea130426bda39ebb5f363102641003f2c2cb33b785","3f29a368c48b0a851db473a70498e168d59c75b7106002ac533711ca5cfabf89","410c884d883ebe2172507b5eadd10bc8a2ae2564ba0d33b1e84e5f3c22bd3677","4acc0b5ed29adf00916dea7652bcab8012d83d924438a410bee32afbcdb995cc","5b9bae348788cd2a1ce0ba798f9ae9264c662097011adbd44ecfab63a8c4ae28","6292c2294ad1e84cd0925c31ee6deb7afd300f935004a9e8a7a43bf80034abae","0545f842ca2eb77bcac0fd17d6d0a8c607d7dbc8669709f3096e5c1828e1c049","9feed0c7fa8c1d32390e1c168051267df61f11b048ec62aa5b8e66f60e8083af"]);
union
    (DeviceProcessEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="Process"),
    (DeviceFileEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="File")
| where isnotempty(SHA256) and SHA256 in~ (PublishedHashes)
| project Timestamp, DeviceName, RecordType, FileName, FolderPath, SHA256
```

### 10.9 L39 — Possible 4.0 impostor artifact identification

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents + DeviceFileEvents / normalized EDR SHA-256.

**Review / tuning:** Exact historical artifact match only; missing SHA256 reduces coverage. Evidence repositories and quarantine/restores can match. No sample execution is implied by a file record. Deliberately separate from confirmed service payload sets.

```kusto
let PublishedHashes=dynamic(["0447c931bb8efc6dc531f69a891f2a0f28a85a18b25e04366fdb59bf827b2eb1","31208a2640c1f2806d21bb8b40abd47b24dd3be85dedb1fdb9f33dac47b23152","9b5f1ec1ca04344582d1eca400b4a21dfff89bc650aba4715edd7efb089d8141","b3a994f26b694fcfdc68e57fc6aeea2aa4b4906ff50b0319e00c693537a3b25c","f8935a295a316e15f60fadf465383f19cf881a42ba008ed1792cbeecb21580dc"]);
union
    (DeviceProcessEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="Process"),
    (DeviceFileEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, RecordType="File")
| where isnotempty(SHA256) and SHA256 in~ (PublishedHashes)
| project Timestamp, DeviceName, RecordType, FileName, FolderPath, SHA256
```

### 10.10 L40 — 5.0-generation masquerade metadata

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents / normalized EDR process events.

**Review / tuning:** Untrusted version metadata is not a valid signature. A real company and a product name can be impersonated; neither brand is implicated.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessVersionInfoCompanyName =~ "Corteva" and (ProcessVersionInfoProductName contains "Solstice Google Photos" or ProcessVersionInfoFileDescription contains "Solstice Google Photos")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, ProcessId, ProcessCreationTime,
          InitiatingProcessFileName, SHA256
```

