# INC Ransom — Splunk Hunting Searches

**Presentation reviewed:** 2026-09-22.

**Status:** repository-authored defensive hunts; not vendor-published signatures or actor-attribution rules. No connected SIEM was available for backend execution.

## Scope and Requirements

Queries use Windows Sysmon XML events with standard Image, CommandLine, TargetFilename and Computer extractions. Replace index=* with approved indexes and confirm sourcetype/field names before deployment. EventCode must be normalized if the local source uses EventID. The ESXi example requires separately collected and parsed host logs.

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

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("powershell.exe","pwsh.exe") AND like(cmd,"%veeam%") AND (like(cmd,"%credentials%") OR like(cmd,"%unprotect%") OR like(cmd,"%veeam-get-creds%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 1.2 I02 — Named credential-access utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Name-based investigative pivot; renamed or in-memory tools evade it. Verify target process and authorized assessments.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("mimikatz.exe","lsassy.exe") OR like(cmd,"%lsassy%")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 1.3 I03 — Directory-database acquisition commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Directory maintenance and backup operations can match. Check identity, output paths and subsequent file access.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (name="ntdsutil.exe" AND match(cmd,"(?i)\\bifm\\b")) OR (name="esentutl.exe" AND like(cmd,"%ntds.dit%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```

## 2. Active Directory and Network Discovery

### 2.1 I04 — Network scanners

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Inventory teams also use these tools. OriginalFileName in Splunk depends on collected Sysmon version fields.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("netscan.exe","advanced_ip_scanner.exe","ipscan.exe") OR like(lower(OriginalFileName),"%netscan%")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 2.2 I05 — Domain discovery tools

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Baseline domain administration; investigate new remote sessions and nonadministrative hosts.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name="adfind.exe" OR (name="nltest.exe" AND (like(cmd,"%dclist%") OR like(cmd,"%domain_trusts%") OR like(cmd,"%dsgetdc%")))
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 2.3 I06 — Share and domain-group discovery

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Commands show discovery intent, not successful enumeration or INC attribution.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("net.exe","net1.exe") AND (match(cmd,"(?i)\\bview\\b") OR (match(cmd,"(?i)\\bgroup\\b") AND like(cmd,"%/domain%")))
| table _time Computer User Image CommandLine ParentImage Hashes
```

## 3. Persistence and Remote Administration

### 3.1 I07 — Remote administration process inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Compare approved tenants, install owner and sessions. This inventory is intentionally broad.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("anydesk.exe","teamviewer.exe") OR like(name,"screenconnect.%")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 3.2 I08 — Task creation with case-related artifacts

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Only command-line task creation is covered; RPC/COM-created tasks require Task Scheduler or Security logs.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name="schtasks.exe" AND like(cmd,"%/create%") AND (like(cmd,"%recovery diagnostics%") OR like(cmd,"%vendettister%") OR like(cmd,"%jocularities%") OR like(cmd,"%winupdate.exe%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 3.3 I09 — SafeBoot service registration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceRegistryEvents; Sysmon Event 13 registry values.

**Review / tuning:** Classic sample-specific pivot. Registry key creation without a value event needs additional collection. Authorized recovery software may register SafeBoot services.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| eval target=lower(TargetObject), image=lower(Image)
| where match(target,"(?i)[\\\\/]control[\\\\/]safeboot[\\\\/]") AND (like(target,"%dmksvc%") OR match(image,"(?i)[\\\\/](win|windows)\\.exe$"))
| table _time Computer Image TargetObject Details
```

### 3.4 I29 — Case-related service registry configuration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents or Sysmon registry-value Event 13.

**Review / tuning:** Complements command-line searches when services are configured through APIs. Generic names can be reused; correlate service creation/loading and file identity.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| where match(TargetObject,"(?i)[\\\\/]services[\\\\/](dmksvc|HwAudio)[\\\\/](ImagePath|Start|Type|ObjectName)$")
| table _time Computer Image TargetObject Details
```

## 4. Tunneling and C2

### 4.1 I10 — Reported campaign network endpoints

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceNetworkEvents; Sysmon Event 3 network connections.

**Review / tuning:** Historical August 2026 artifacts; no assertion of current control. Hostname availability depends on telemetry.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-30d
| eval dest=lower(DestinationHostname)
| where DestinationIp="213.111.185.108" OR dest="throughoutes.net" OR like(dest,"%.throughoutes.net")
| table _time Computer Image DestinationIp DestinationHostname DestinationPort
```

### 4.2 I11 — RMM outbound session inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceNetworkEvents; Sysmon Event 3.

**Review / tuning:** Legitimate support is common. Validate approval and tenant/session identity; this is not proof of tunneling.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]",""))
| where name IN ("anydesk.exe","teamviewer.exe") OR like(name,"screenconnect.%")
| stats earliest(_time) as FirstObserved latest(_time) as LastObserved count as Connections values(DestinationHostname) as Hosts values(DestinationIp) as IPs by Computer Image
```

## 5. Defense Evasion and Impairment

### 5.1 I12 — SystemSettingsAdminFlows from an unusual parent

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Broad adaptation of the reported behavioral opportunity, not the vendor's Sigma rule. Correlate Defender 5007/5001 events and actual setting changes.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name="systemsettingsadminflows.exe" AND NOT match(parent,"(?i)[\\\\/]systemsettings\\.exe$")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 5.2 I13 — Process-termination utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Filename/argument heuristic; verify binary identity, target and service interruption. Legitimate troubleshooting can match.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("av.exe","edr.exe","procterminator.exe","processterminator.exe","pskill.exe") AND (like(cmd,"%cylancesvc%") OR like(cmd,"%sophos%") OR like(cmd,"%msmpeng%") OR match(cmd,"(?i)(^|\\s)-p(\\s|$)") OR name="edr.exe")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 5.3 I14 — Reported driver files written

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceFileEvents; Sysmon Event 11.

**Review / tuning:** File creation is not driver loading or exploitation. Add Sysmon 6, service and signature evidence.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| eval name=lower(replace(TargetFilename,"^.*[\\\\/]",""))
| where name IN ("hwauidoos2ec.sys","filwfp.sys","filnk.sys","fildds.sys")
| table _time Computer Image TargetFilename
```

## 6. Collection and Exfiltration

### 6.1 I15 — Archive staging tools

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Broad staging inventory; correlate archive output and later upload. GUI archivers may expose few arguments.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("7z.exe","7za.exe","7zg.exe","7.exe","winrar.exe")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 6.2 I16 — Rclone transfer or selected-file collection

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Backups and migrations match. Inspect destination and authorization; command execution does not prove upload completion.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (name="rclone.exe" OR lower(OriginalFileName)="rclone.exe") AND (match(cmd,"(?i)\\b(copy|sync|move)\\b") OR like(cmd,"%--include-from%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 6.3 I17 — Restic or renamed backup client

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Environment-only repository values may not appear in process logs. Confirm product metadata and destination; winupdate is a generic name.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (name IN ("restic.exe","winupdate.exe") OR like(cmd,"%restic_repository%")) AND (match(cmd,"(?i)\\b(backup|snapshots|restic|init)\\b") OR like(cmd,"%restic_repository%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 6.4 I30 — Backup-client connections to Wasabi endpoints

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents or Sysmon network Event 3 with hostname enrichment.

**Review / tuning:** Wasabi is legitimate shared storage. Review backup authorization and tenant/bucket evidence. Missing hostnames and renamed clients cause misses; a connection does not prove transfer.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), dest=lower(DestinationHostname)
| where name IN ("restic.exe","winupdate.exe","rclone.exe")
| where dest="wasabisys.com" OR like(dest,"%.wasabisys.com")
| table _time Computer Image DestinationHostname DestinationIp DestinationPort
```

## 7. Recovery Inhibition

### 7.1 I18 — Shell-based shadow-copy or recovery changes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Adjacent recovery/Safe Mode coverage; direct DeviceIoControl actions have no required child process and are not detected by this query.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (name="vssadmin.exe" AND match(cmd,"(?i)\\b(delete|resize)\\b")) OR (name="wmic.exe" AND like(cmd,"%shadowcopy%") AND like(cmd,"%delete%")) OR (name="bcdedit.exe" AND (like(cmd,"%recoveryenabled%") OR like(cmd,"%bootstatuspolicy%") OR like(cmd,"%safeboot%")))
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 7.2 I19 — ESXi VM and snapshot management commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Forwarded ESXi shell/management syslog; Sentinel/Log Analytics Syslog or Splunk VMware syslog sourcetypes.

**Review / tuning:** KQL runs in Sentinel/Log Analytics, not Defender XDR. Configure ESXi forwarding and scope to hypervisor hosts. Shell commands must be present in collected messages; API-only actions can differ. Authorized VM maintenance matches. Commands establish attempts, not successful shutdown or snapshot removal.

```spl
index=* (sourcetype=vmw-syslog OR sourcetype=vmware:esxlog*) earliest=-7d
| where (like(_raw,"%vim-cmd%") AND (like(_raw,"%power.off%") OR like(_raw,"%snapshot.remove%")))
    OR (like(_raw,"%esxcli%") AND like(_raw,"%vm process kill%"))
| table _time host source sourcetype _raw
```

## 8. Deployment and Impact

### 8.1 I20 — INC-like combined runtime arguments

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Related families and research invocations can match. This combination is a hunt, not an exclusive INC signature.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where like(cmd,"%--mode%") AND (like(cmd,"%--sup%") OR like(cmd,"%--ens%") OR like(cmd,"%--lhd%")) AND NOT name IN ("cmd.exe","powershell.exe","pwsh.exe")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 8.2 I21 — Ransom-note file creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceFileEvents; Sysmon Event 11.

**Review / tuning:** Research collections and restored files can match. Inspect contents and nearby actual encryption; retain the second-note distinction.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| eval name=lower(replace(TargetFilename,"^.*[\\\\/]",""))
| where name IN ("inc-readme.txt","inc-readme.html","inc_readme.html","dataleak_press_release.txt")
| table _time Computer Image TargetFilename
```

### 8.3 I22 — Burst of INC-named file activity

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceFileEvents; Sysmon Event 11 where collected.

**Review / tuning:** .inc is also a legitimate source-code extension. Baseline builds/research. Fixed buckets can split bursts; Sysmon file-create coverage is not equivalent to all rename events.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| where match(TargetFilename,"(?i)\\.inc$")
| bin _time span=5m
| stats count as Events dc(TargetFilename) as Files values(TargetFilename) as Examples by _time Computer Image
| where Files>=20
```

### 8.4 I23 — WMIC remote process execution or PsExec service naming

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Administrative remote execution matches. Verify target-side service/logon evidence and actual binary identity.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (name="wmic.exe" AND like(cmd,"%/node%") AND like(cmd,"%process%") AND like(cmd,"%create%")) OR (like(cmd,"%winupd%") AND like(cmd,"%-r%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```

## 9. Multi-Stage Correlation

### 9.1 I24 — Transfer client followed by a ransom-note event

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process + file events; Sysmon Events 1 and 11.

**Review / tuning:** Ordered same-host correlation, not proof of upload success or causality. Splunk retains the latest preceding client; MDE returns matching pairs. Start with a bounded investigation host/time window at scale.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (1,11) earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), target=lower(replace(TargetFilename,"^.*[\\\\/]",""))
| eval transfer=if(EventCode=1 AND name IN ("rclone.exe","restic.exe","winupdate.exe","megasync.exe"),1,0), note=if(EventCode=11 AND target IN ("inc-readme.txt","inc-readme.html","inc_readme.html"),1,0)
| where transfer=1 OR note=1
| sort 0 _time
| eval transfer_time=if(transfer=1,_time,null()), transfer_cmd=if(transfer=1,CommandLine,null())
| streamstats current=f last(transfer_time) as prior_transfer last(transfer_cmd) as prior_command by Computer
| where note=1 AND isnotnull(prior_transfer) AND _time>=prior_transfer AND _time-prior_transfer<=86400
| table _time Computer prior_transfer prior_command TargetFilename
```

## 10. Campaign Artifact Hunts

### 10.1 I25 — Published encryptor SHA-256 set

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Exact published artifacts only. MDE SHA256 is sometimes absent; Sysmon must collect SHA256 hashes. No claim of variant-wide coverage.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| rex field=Hashes "(?i)SHA256=(?<sha256>[0-9a-f]{64})"
| eval sha256=lower(sha256)
| where sha256 IN ("accd8bc0d0c2675c15c169688b882ded17e78aed0d914793098337afc57c289c",
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
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 10.2 I26 — Auxiliary incident hashes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** These are edr.exe/HRSword, av.exe and kaz.exe artifacts, not three encryptors. Preserve their separate roles.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| rex field=Hashes "(?i)SHA256=(?<sha256>[0-9a-f]{64})"
| eval sha256=lower(sha256)
| where sha256 IN ("1d15b57db62c079fc6274f8ea02ce7ec3d6b158834b142f5345db14f16134f0d", "36eb4290aa11a950e60d12ab18a8e139d25464355ce761f98891e1ea94f39445", "fc39cca5d71b1a9ed3c71cca6f1b86cfe03466624ad78cdb57580dba90847851")
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 10.3 I27 — August case paths and loader names

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Incident-specific naming; HealthUpdater was a legitimate renamed product in the report. Verify identity before containment decisions.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where like(cmd,"%vendettister%jocularities.ps1%") OR name="hwau.exe" OR (name="healthupdater.exe" AND like(lower(Image),"%7-zip%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```

### 10.4 I28 — dmksvc or HwAudio service-control arguments

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE DeviceProcessEvents; Splunk Sysmon Event 1 with Image/CommandLine/ParentImage.

**Review / tuning:** Command-line pivot only; payload API-created services require System 7045/Security 4697 or registry telemetry. Service names may be reused.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval name=lower(replace(Image,"^.*[\\\\/]","")), cmd=lower(CommandLine), parent=lower(ParentImage)
| where name IN ("sc.exe","powershell.exe","pwsh.exe") AND (like(cmd,"%dmksvc%") OR like(cmd,"%hwaudio%"))
| table _time Computer User Image CommandLine ParentImage Hashes
```
