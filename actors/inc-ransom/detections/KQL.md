# INC Ransom — Microsoft Defender XDR / KQL Hunting Queries

**Presentation reviewed:** 2026-09-22.

**Status:** repository-authored defensive hunts; not vendor-published signatures or actor-attribution rules. No connected SIEM was available for backend execution.

## Scope and Requirements

Most queries use Defender XDR process, file, network or registry tables. Enable the required sensors and preserve process lineage. SHA256 may be empty. I19 uses forwarded ESXi syslog in Sentinel/Log Analytics, not a Defender XDR process table.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 3 queries | Entry-specific collection and false-positive notes |
| 2. Active Directory and Network Discovery | 3 queries | Entry-specific collection and false-positive notes |
| 3. Persistence and Remote Administration | 4 queries | Entry-specific collection and false-positive notes |
| 4. Tunneling and C2 | 2 queries | Entry-specific collection and false-positive notes |
| 5. Defense Evasion and Impairment | 3 queries | Entry-specific collection and false-positive notes |
| 6. Collection and Exfiltration | 4 queries | Entry-specific collection and false-positive notes |
| 7. Recovery Inhibition | 2 queries | Entry-specific collection and false-positive notes |
| 8. Deployment and Impact | 4 queries | Entry-specific collection and false-positive notes |
| 9. Multi-Stage Correlation | 1 queries | Entry-specific collection and false-positive notes |
| 10. Campaign Artifact Hunts | 4 queries | Entry-specific collection and false-positive notes |

## Interpretation Notes

Names, administrative tools and cloud services are often legitimate. Tune by approved owner, account, signer, host role, tenant and time; do not blanket-allowlist a filename. API-only payload actions require additional telemetry. Tool execution is not proof of a successful attack.

The 30 entries share IDs with the paired query file. Source mappings are centralized in [References](../References.md); the [detection index](Detections.md) summarizes coverage. The queries are readable/copyable starting points and need testing against local data.

## 1. Credential Access

### 1.1 I01 — Veeam-related credential script text

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Matches visible command text only; encoded/file-based scripts need PowerShell script-block collection. Authorized recovery scripts can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "Veeam" and ProcessCommandLine has_any ("Credentials", "Unprotect", "Veeam-Get-Creds")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 1.2 I02 — Named credential-access utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Name-based investigative pivot; renamed or in-memory tools evade it. Verify target process and authorized assessments.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("mimikatz.exe", "lsassy.exe") or ProcessCommandLine contains "lsassy"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 1.3 I03 — Directory-database acquisition commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Directory maintenance and backup operations can match. Check identity, output paths and subsequent file access.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "ntdsutil.exe" and ProcessCommandLine has "ifm") or (FileName =~ "esentutl.exe" and ProcessCommandLine contains "ntds.dit")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 2. Active Directory and Network Discovery

### 2.1 I04 — Network scanners

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Inventory teams also use these tools. OriginalFileName in Splunk depends on collected Sysmon version fields.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("netscan.exe","advanced_ip_scanner.exe","ipscan.exe") or ProcessVersionInfoOriginalFileName in~ ("netscan.exe","advanced_ip_scanner.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 2.2 I05 — Domain discovery tools

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Baseline domain administration; investigate new remote sessions and nonadministrative hosts.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "adfind.exe" or (FileName =~ "nltest.exe" and ProcessCommandLine has_any ("dclist","domain_trusts","dsgetdc"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 2.3 I06 — Share and domain-group discovery

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Commands show discovery intent, not successful enumeration or INC attribution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has "view" or (ProcessCommandLine has "group" and ProcessCommandLine contains "/domain")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 3. Persistence and Remote Administration

### 3.1 I07 — Remote administration process inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Compare approved tenants, install owner and sessions. This inventory is intentionally broad.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("anydesk.exe","teamviewer.exe") or FileName startswith "ScreenConnect."
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 3.2 I08 — Task creation with case-related artifacts

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Only command-line task creation is covered; RPC/COM-created tasks require Task Scheduler or Security logs.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine contains "/create"
| where ProcessCommandLine contains "Recovery Diagnostics" or ProcessCommandLine has_any ("Vendettister","jocularities","winupdate.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 3.3 I09 — SafeBoot service registration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceRegistryEvents; Sysmon Event 13 registry values.

**Review / tuning:** Classic sample-specific pivot. Registry key creation without a value event needs additional collection. Authorized recovery software may register SafeBoot services.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey contains @"\Control\SafeBoot\"
| where RegistryKey contains "dmksvc" or InitiatingProcessFileName in~ ("win.exe","windows.exe")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.4 I29 — Case-related service registry configuration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents or Sysmon registry-value Event 13.

**Review / tuning:** Complements command-line searches when services are configured through APIs. Generic names can be reused; correlate service creation/loading and file identity.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey contains @"\Services\"
| where RegistryKey endswith @"\dmksvc" or RegistryKey endswith @"\HwAudio"
| where RegistryValueName in~ ("ImagePath","Start","Type","ObjectName")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 4. Tunneling and C2

### 4.1 I10 — Reported campaign network endpoints

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceNetworkEvents; Sysmon Event 3 network connections.

**Review / tuning:** Historical August 2026 artifacts; no assertion of current control. Hostname availability depends on telemetry.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "213.111.185.108" or RemoteUrl =~ "throughoutes.net" or RemoteUrl endswith ".throughoutes.net"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 4.2 I11 — RMM outbound session inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceNetworkEvents; Sysmon Event 3.

**Review / tuning:** Legitimate support is common. Validate approval and tenant/session identity; this is not proof of tunneling.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("anydesk.exe","teamviewer.exe") or InitiatingProcessFileName startswith "ScreenConnect."
| summarize FirstObserved=min(Timestamp), LastObserved=max(Timestamp), Connections=count(), Hosts=make_set(RemoteUrl,100), IPs=make_set(RemoteIP,100) by DeviceName, InitiatingProcessFileName
```

## 5. Defense Evasion and Impairment

### 5.1 I12 — SystemSettingsAdminFlows from an unusual parent

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Broad adaptation of the reported behavioral opportunity, not the vendor's Sigma rule. Correlate Defender 5007/5001 events and actual setting changes.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "SystemSettingsAdminFlows.exe"
| where InitiatingProcessFileName !~ "SystemSettings.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 5.2 I13 — Process-termination utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Filename/argument heuristic; verify binary identity, target and service interruption. Legitimate troubleshooting can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("av.exe","edr.exe","ProcTerminator.exe","ProcessTerminator.exe","pskill.exe")
| where ProcessCommandLine has_any ("CylanceSvc","Sophos","MsMpEng") or ProcessCommandLine matches regex @"(?i)(^|\s)-p(\s|$)" or FileName =~ "edr.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 5.3 I14 — Reported driver files written

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceFileEvents; Sysmon Event 11.

**Review / tuning:** File creation is not driver loading or exploitation. Add Sysmon 6, service and signature evidence.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("HWAuidoOs2Ec.sys","filwfp.sys","filnk.sys","fildds.sys")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 6. Collection and Exfiltration

### 6.1 I15 — Archive staging tools

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Broad staging inventory; correlate archive output and later upload. GUI archivers may expose few arguments.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("7z.exe","7za.exe","7zg.exe","7.exe","winrar.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 6.2 I16 — Rclone transfer or selected-file collection

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Backups and migrations match. Inspect destination and authorization; command execution does not prove upload completion.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rclone.exe" or ProcessVersionInfoOriginalFileName =~ "rclone.exe"
| where ProcessCommandLine has_any ("copy","sync","move") or ProcessCommandLine contains "--include-from"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 6.3 I17 — Restic or renamed backup client

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Environment-only repository values may not appear in process logs. Confirm product metadata and destination; winupdate is a generic name.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("restic.exe","winupdate.exe") or ProcessCommandLine contains "RESTIC_REPOSITORY"
| where ProcessCommandLine has_any ("backup","snapshots","restic","init") or ProcessCommandLine contains "RESTIC_REPOSITORY"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 6.4 I30 — Backup-client connections to Wasabi endpoints

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents or Sysmon network Event 3 with hostname enrichment.

**Review / tuning:** Wasabi is legitimate shared storage. Review backup authorization and tenant/bucket evidence. Missing hostnames and renamed clients cause misses; a connection does not prove transfer.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("restic.exe","winupdate.exe","rclone.exe")
| where RemoteUrl =~ "wasabisys.com" or RemoteUrl endswith ".wasabisys.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

## 7. Recovery Inhibition

### 7.1 I18 — Shell-based shadow-copy or recovery changes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Adjacent recovery/Safe Mode coverage; direct DeviceIoControl actions have no required child process and are not detected by this query.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete","resize")) or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete")) or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled","bootstatuspolicy","safeboot"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 7.2 I19 — ESXi VM and snapshot management commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Forwarded ESXi shell/management syslog; Sentinel/Log Analytics Syslog or Splunk VMware syslog sourcetypes.

**Review / tuning:** KQL runs in Sentinel/Log Analytics, not Defender XDR. Configure ESXi forwarding and scope to hypervisor hosts. Shell commands must be present in collected messages; API-only actions can differ. Authorized VM maintenance matches. Commands establish attempts, not successful shutdown or snapshot removal.

```kusto
Syslog
| where TimeGenerated > ago(7d)
| where (SyslogMessage contains "vim-cmd" and (SyslogMessage contains "power.off" or SyslogMessage contains "snapshot.remove"))
    or (SyslogMessage contains "esxcli" and SyslogMessage contains "vm process kill")
| project TimeGenerated, Computer, HostName, ProcessName, SyslogMessage
```

## 8. Deployment and Impact

### 8.1 I20 — INC-like combined runtime arguments

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Related families and research invocations can match. This combination is a hunt, not an exclusive INC signature.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine contains "--mode"
| where ProcessCommandLine contains "--sup" or ProcessCommandLine contains "--ens" or ProcessCommandLine contains "--lhd"
| where FileName !in~ ("cmd.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 8.2 I21 — Ransom-note file creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceFileEvents; Sysmon Event 11.

**Review / tuning:** Research collections and restored files can match. Inspect contents and nearby actual encryption; retain the second-note distinction.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("INC-README.txt","INC-README.html","Inc_readme.html","DATALEAK_PRESS_RELEASE.txt")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 8.3 I22 — Burst of INC-named file activity

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceFileEvents; Sysmon Event 11 where collected.

**Review / tuning:** .inc is also a legitimate source-code extension. Baseline builds/research. Fixed buckets can split bursts; Sysmon file-create coverage is not equivalent to all rename events.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".inc"
| summarize Events=count(), Files=dcount(strcat(FolderPath, "/", FileName)), Examples=make_set(FileName,10) by DeviceId, DeviceName, InitiatingProcessFileName, bin(Timestamp,5m)
| where Files >= 20
```

### 8.4 I23 — WMIC remote process execution or PsExec service naming

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Administrative remote execution matches. Verify target-side service/logon evidence and actual binary identity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "wmic.exe" and ProcessCommandLine contains "/node" and ProcessCommandLine has_all ("process","create")) or (ProcessCommandLine contains "winupd" and ProcessCommandLine contains "-r")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 9. Multi-Stage Correlation

### 9.1 I24 — Transfer client followed by a ransom-note event

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process + file events; Sysmon Events 1 and 11.

**Review / tuning:** Ordered same-host correlation, not proof of upload success or causality. Splunk retains the latest preceding client; MDE returns matching pairs. Start with a bounded investigation host/time window at scale.

```kusto
let Transfers = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("rclone.exe","restic.exe","winupdate.exe","MEGAsync.exe")
| project DeviceId, TransferTime=Timestamp, TransferFile=FileName, TransferCommand=ProcessCommandLine;
let Notes = DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("INC-README.txt","INC-README.html","Inc_readme.html")
| project DeviceId, DeviceName, NoteTime=Timestamp, NotePath=FolderPath;
Transfers
| join kind=inner Notes on DeviceId
| where NoteTime >= TransferTime and NoteTime <= TransferTime + 24h
| summarize FirstTransfer=min(TransferTime), FirstFollowingNote=min(NoteTime), Commands=make_set(TransferCommand,20) by DeviceId, DeviceName, TransferFile
```

## 10. Campaign Artifact Hunts

### 10.1 I25 — Published encryptor SHA-256 set

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Exact published artifacts only. MDE SHA256 is sometimes absent; Sysmon must collect SHA256 hashes. No claim of variant-wide coverage.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ ("accd8bc0d0c2675c15c169688b882ded17e78aed0d914793098337afc57c289c",
    "e17c601551dfded76ab99a233957c5c4acf0229b46cd7fc2175ead7fe1e3d261",
    "e034a4c00f168134900bfe235ff2f78daf8bfcfa8b594cd2dd563d43f5de1b13",
    "31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502",
    "ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22",
    "8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4",
    "bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc",
    "6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f",
    "1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449",
    "24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7",
    "dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da",
    "acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4",
    "90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c",
    "ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b",
    "97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2",
    "1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11",
    "f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347",
    "d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb",
    "765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a",
    "d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570",
    "589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880",
    "7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245",
    "5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241",
    "60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6",
    "6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 10.2 I26 — Auxiliary incident hashes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** These are edr.exe/HRSword, av.exe and kaz.exe artifacts, not three encryptors. Preserve their separate roles.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ ("1d15b57db62c079fc6274f8ea02ce7ec3d6b158834b142f5345db14f16134f0d", "36eb4290aa11a950e60d12ab18a8e139d25464355ce761f98891e1ea94f39445", "fc39cca5d71b1a9ed3c71cca6f1b86cfe03466624ad78cdb57580dba90847851")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 10.3 I27 — August case paths and loader names

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Incident-specific naming; HealthUpdater was a legitimate renamed product in the report. Verify identity before containment decisions.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine contains @"\Vendettister\jocularities.ps1" or FileName =~ "hwau.exe" or (FileName =~ "HealthUpdater.exe" and FolderPath contains @"\7-Zip")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 10.4 I28 — dmksvc or HwAudio service-control arguments

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Command-line pivot only; payload API-created services require System 7045/Security 4697 or registry telemetry. Service names may be reused.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sc.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("dmksvc","HwAudio")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```
