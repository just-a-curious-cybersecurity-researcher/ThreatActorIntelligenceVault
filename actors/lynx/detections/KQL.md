# Lynx — Microsoft Defender XDR / KQL Hunting Queries

**Presentation reviewed:** 2026-10-07.
**Last updated:** 2026-10-07  
**TLP:** CLEAR

## Scope and Requirements

Queries target Microsoft Defender XDR tables. Adjust retention, thresholds, approved RMM/scanner inventory and RFC1918 handling before production use. All LNX queries are repository-authored from evidence documented in this dossier.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| LNX01–LNX06 | Remote access, credential testing and discovery | Baseline jump hosts, vulnerability scanners and administrators |
| LNX07–LNX11 | Persistence, remote administration and historical access | Validate service signer, account requester and IP history |
| LNX12–LNX18 | Evasion, collection, exfiltration and recovery inhibition | Confirm API outcome, transfer volume and maintenance windows |
| LNX19–LNX28 | Locker identity, impact, sequence and campaign artifacts | Exact indicators and affiliate artifacts are narrow and historical |

## Interpretation Notes

A hit is an investigation lead. RDP, AnyDesk, NetScan, NetExec and 7-Zip are legitimate or dual-use. Preserve process ancestry, signer, account, device, remote address and timing before attributing activity.

## 1. Credential Access

### 1.1 LNX01 — External RDP success from a rare source

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** Defender XDR DeviceLogonEvents.

**Review / tuning:** Maintain approved jump-host/VPN egress lists and adapt private-address logic.

```kusto
let common = DeviceLogonEvents
| where Timestamp > ago(30d) and LogonType =~ "RemoteInteractive" and ActionType =~ "LogonSuccess"
| summarize Devices=dcount(DeviceName), Events=count() by RemoteIP
| where Devices >= 5 or Events >= 25;
DeviceLogonEvents
| where Timestamp > ago(7d) and LogonType =~ "RemoteInteractive" and ActionType =~ "LogonSuccess"
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| join kind=leftanti common on RemoteIP
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName, InitiatingProcessFileName
```

### 1.2 LNX02 — NetExec-style SMB password spray

**Origin:** Repository-authored from observed `nxc.exe smb` activity.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Authorized penetration tests can match; verify account owner and change window.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("nxc.exe","netexec.exe","crackmapexec.exe")
| where ProcessCommandLine has " smb " and ProcessCommandLine has_any (" -u "," --username ") and ProcessCommandLine has_any (" -p "," --password ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName
```

## 2. Active Directory and Network Discovery

### 2.1 LNX03 — SoftPerfect NetScan execution or case hash

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Inventory teams commonly use NetScan; confirm unusual user, path and downstream RDP.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("netscan.exe","netscan64.exe") or SHA256 =~ "517288e12c05a92e483e6d80b9136c19bc58c46851720680bb6d1b7016034c37"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName
```

### 2.2 LNX04 — NetScan share write-access probe

**Origin:** Repository-authored from published `delete.me` behavior.

**Telemetry:** MDE DeviceFileEvents.

**Review / tuning:** Search/indexing products can use temporary marker files; require multiple shares or NetScan ancestry.

```kusto
DeviceFileEvents
| where Timestamp > ago(30d) and FileName =~ "delete.me"
| summarize Shares=dcount(FolderPath), Paths=make_set(FolderPath,50), First=min(Timestamp), Last=max(Timestamp)
  by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessSHA256
| where Shares >= 3 or InitiatingProcessFileName in~ ("netscan.exe","netscan64.exe")
```

### 2.3 LNX05 — Native discovery burst

**Origin:** Repository-authored from observed commands.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Require concentration under one account/parent; help-desk scripts can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("ipconfig.exe","route.exe","systeminfo.exe","ping.exe","net.exe","net1.exe","nslookup.exe","nbtstat.exe","reg.exe")
| summarize Tools=dcount(FileName), Commands=make_set(ProcessCommandLine,30), First=min(Timestamp), Last=max(Timestamp)
  by DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp,30m)
| where Tools >= 5
```

### 2.4 LNX06 — Virtualization and directory MMC discovery

**Origin:** Repository-authored from observed GUI tooling.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Administrators legitimately use these snap-ins; hunt for rare accounts and RDP sessions.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName =~ "mmc.exe"
| where ProcessCommandLine has_any ("dsa.msc","lusrmgr.msc","virtmgmt.msc")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 3. Persistence and Remote Administration

### 3.1 LNX07 — Domain account creation followed by privileged group addition

**Origin:** Repository-authored from the lookalike-account persistence case.

**Telemetry:** Defender XDR IdentityDirectoryEvents.

**Review / tuning:** Normalize ActionType values for the tenant and exclude approved provisioning.

```kusto
let created = IdentityDirectoryEvents
| where Timestamp > ago(30d) and ActionType has_any ("Account created","User Account Created")
| project CreatedTime=Timestamp, AccountName=TargetAccountUpn, CreatingAccount=AccountUpn, DeviceName;
IdentityDirectoryEvents
| where Timestamp > ago(30d) and ActionType has_any ("Added to group","Group Membership changed")
| where AdditionalFields has_any ("Domain Admins","Group Policy Creator Owners","Administrators")
| project AddedTime=Timestamp, AccountName=TargetAccountUpn, GroupData=AdditionalFields, AddingAccount=AccountUpn, DeviceName
| join kind=inner created on AccountName
| where AddedTime between (CreatedTime .. CreatedTime + 24h)
```

### 3.2 LNX08 — AnyDesk service installation

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Exclude managed deployments by package, signer, account and expected path.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "anydesk.exe" and ProcessCommandLine has_any ("--install","--start-with-win","--service"))
   or (FileName in~ ("sc.exe","powershell.exe","cmd.exe") and ProcessCommandLine has "AnyDesk" and ProcessCommandLine has_any (" create ","New-Service"," start "))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName
```

### 3.3 LNX09 — Non-expiring account configuration near account creation

**Origin:** Repository-authored from observed account configuration.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Service accounts can legitimately be non-expiring; require recent creation or privilege addition.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("net.exe","net1.exe","powershell.exe","pwsh.exe","dsmod.exe")
| where ProcessCommandLine has_any ("/expires:never","PasswordNeverExpires","-pwdneverexpires yes")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## 4. Tunneling and C2

### 4.1 LNX10 — Rare AnyDesk network activity

**Origin:** Repository-authored from incident RMM installation.

**Telemetry:** MDE DeviceNetworkEvents.

**Review / tuning:** Exclude enterprise-managed endpoints and approved relays.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(30d) and InitiatingProcessFileName =~ "anydesk.exe"
| summarize Connections=count(), Remotes=make_set(RemoteUrl,20), IPs=make_set(RemoteIP,20), First=min(Timestamp), Last=max(Timestamp)
  by DeviceName, InitiatingProcessAccountName, InitiatingProcessSHA256
| where Connections > 0
```

### 4.2 LNX11 — Historical Lynx affiliate RDP sources

**Origin:** Exact IPs from the DFIR case.

**Telemetry:** MDE DeviceLogonEvents and DeviceNetworkEvents.

**Review / tuning:** Historical IP ownership can change; use as a retrospective pivot only.

```kusto
let ips = dynamic(["195.211.190.189","77.90.153.30","79.141.172.131","185.33.87.207"]);
union isfuzzy=true
(DeviceLogonEvents | where Timestamp > ago(180d) and RemoteIP in (ips) | project Timestamp, DeviceName, AccountName, Evidence=RemoteIP, ActionType, LogonType),
(DeviceNetworkEvents | where Timestamp > ago(180d) and RemoteIP in (ips) | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Evidence=RemoteIP, ActionType, LogonType="network")
```

## 5. Defense Evasion and Impairment

### 5.1 LNX12 — Burst of backup/database service stops

**Origin:** Repository-authored from Lynx kill-list behavior.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Maintenance can stop services; require multiple families or later impact.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sc.exe","net.exe","net1.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (" stop ","Stop-Service","Set-Service")
| where ProcessCommandLine has_any ("sql","veeam","backup","exchange")
| summarize Commands=make_set(ProcessCommandLine,30), Families=dcount(case(ProcessCommandLine has "veeam","veeam",ProcessCommandLine has "sql","sql",ProcessCommandLine has "exchange","exchange","backup"))
  by DeviceName, AccountName, bin(Timestamp,30m)
| where Families >= 2
```

### 5.2 LNX13 — Locker flags for hidden, silent or safe-mode behavior

**Origin:** Published Lynx CLI.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Stronger when two flags or a locker hash are present.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("--load-drives","--stop-processes","--encrypt-network","--hide-cmd","--safe-mode","--no-background","--no-print","--noprint")
| summarize Flags=make_set(ProcessCommandLine,20), Events=count() by DeviceName, AccountName, FileName, SHA256, bin(Timestamp,15m)
| where Events >= 1
```

### 5.3 LNX14 — High-rate ownership or ACL changes before file modification

**Origin:** Repository-authored from the SeTakeOwnership/DACL branch.

**Telemetry:** MDE DeviceProcessEvents for native equivalents; EDR file-security telemetry recommended.

**Review / tuning:** Backup restore and administrative remediation can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("takeown.exe","icacls.exe")
| where ProcessCommandLine has_any (" /f "," /grant "," /setowner ")
| summarize Commands=make_set(ProcessCommandLine,30), Count=count() by DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp,30m)
| where Count >= 5 or InitiatingProcessFileName !in~ ("cmd.exe","powershell.exe","pwsh.exe")
```

## 6. Collection and Exfiltration

### 6.1 LNX15 — 7-Zip archive creation from an interactive desktop

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** User archives are common; prioritize privileged accounts, network paths and multiple archives.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d) and FileName in~ ("7zg.exe","7z.exe","7za.exe")
| where ProcessCommandLine has_any (" a ",".7z",".zip") or InitiatingProcessFileName =~ "explorer.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 6.2 LNX16 — Browser connection to `temp.sh` after archive creation

**Origin:** Repository-authored from confirmed browser uploads.

**Telemetry:** MDE DeviceProcessEvents and DeviceNetworkEvents.

**Review / tuning:** Legitimate use is possible; confirm bytes sent and `/upload` in proxy logs.

```kusto
let archives = DeviceProcessEvents
| where Timestamp > ago(14d) and FileName in~ ("7zg.exe","7z.exe","7za.exe")
| project ArchiveTime=Timestamp, DeviceId, DeviceName, AccountName;
DeviceNetworkEvents
| where Timestamp > ago(14d) and RemoteUrl =~ "temp.sh"
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe","firefox.exe")
| join kind=inner archives on DeviceId
| where Timestamp between (ArchiveTime .. ArchiveTime + 6h)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, ArchiveTime
```

## 7. Recovery Inhibition

### 7.1 LNX17 — Shadow-copy or VSS storage impairment commands

**Origin:** Repository-authored around recovery inhibition; built-in Lynx device control may not produce these commands.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Confirm success and shadow-copy inventory. This catches operator alternatives, not the API-only path.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vssadmin.exe","wmic.exe","powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("delete shadows","shadowcopy delete","Win32_ShadowCopy","Resize ShadowStorage"))
   or (FileName =~ "diskshadow.exe" and ProcessCommandLine has_any ("delete","reset"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 7.2 LNX18 — ESXi VM force-stop or snapshot removal loop

**Origin:** Published Lynx Linux/ESXi scripts.

**Telemetry:** Forwarded ESXi shell audit or process telemetry in custom table `Syslog`.

**Review / tuning:** Planned host maintenance can match; correlate with mass datastore writes and note creation.

```kusto
Syslog
| where TimeGenerated > ago(30d)
| where SyslogMessage has_all ("esxcli","vm process","kill") or SyslogMessage has_all ("vim-cmd","snapshot.removeall")
| project TimeGenerated, Computer, Facility, SeverityLevel, SyslogMessage
```

## 8. Deployment and Impact

### 8.1 LNX19 — Exact published Lynx locker SHA-256

**Origin:** Published sample corpus.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Exact identity, but validate execution and containment scope.

```kusto
let hashes = dynamic(["eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc","571f5de9dd0d509ed7e5242b9b7473c2b2cbb36ba64d38b32122a0a337d6cf8b","82eb1910488657c78bef6879908526a2a2c6c31ab2f0517fcc5f3f6aa588b513","b378b7ef0f906358eec595777a50f9bb5cc7bb6635e0f031d65b818a26bdc4ee","ecbfea3e7869166dd418f15387bc33ce46f2c72168f571071916b5054d7f6e49","85699c7180ad77f2ede0b15862bb7b51ad9df0478ed394866ac7fa9362bf5683","09c5ff735d3d7b8c47b4df7de35e1c72b530b2c2566628bc29aaa54feb4d89f4","07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a","c3b57cd2c04ffd6dd173edfd975d2b05b7f6f502062a56b8585bda8776824a18","6e65483764d7c25523a5bbef5be99eb42349eef39d5517c46b3a4af262a80ceb"]);
union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(180d) and SHA256 in (hashes) | project Timestamp, DeviceName, Evidence=strcat(FolderPath,"\\",FileName), SHA256, ActionType, AccountName),
(DeviceFileEvents | where Timestamp > ago(180d) and SHA256 in (hashes) | project Timestamp, DeviceName, Evidence=strcat(FolderPath,"\\",FileName), SHA256, ActionType, AccountName=InitiatingProcessAccountName)
```

### 8.2 LNX20 — Lynx command-line mode and scope

**Origin:** Published CLI and observed `w.exe` execution.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Require a mode plus a scope/impact flag to reduce collisions.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("--mode fast","--mode medium","--mode slow","--mode entire")
| where ProcessCommandLine has_any ("--dir","--file","--encrypt-network","--load-drives","--noprint","--no-print")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName
```

### 8.3 LNX21 — `.LYNX` and `README.txt` fan-out

**Origin:** Published output artifacts.

**Telemetry:** MDE DeviceFileEvents.

**Review / tuning:** The extension can collide with legitimate files; require scale or paired note creation.

```kusto
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName endswith ".lynx" or FileName =~ "README.txt"
| summarize LynxFiles=countif(FileName endswith ".lynx"), Notes=countif(FileName =~ "README.txt"), Paths=dcount(FolderPath), Examples=make_set(strcat(FolderPath,"\\",FileName),20)
  by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(Timestamp,10m)
| where LynxFiles >= 20 or (LynxFiles >= 5 and Notes >= 1)
```

## 9. Multi-Stage Correlation

### 9.1 LNX22 — Discovery, archive and impact on one device

**Origin:** Repository-authored from the nine-day affiliate sequence.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Seven-day binning is a triage aid; use timestamps for ordered validation.

```kusto
let p = DeviceProcessEvents
| where Timestamp > ago(30d)
| extend Stage=case(FileName in~ ("netscan.exe","nxc.exe","netexec.exe"),"discovery",FileName in~ ("7zg.exe","7z.exe","7za.exe"),"archive",ProcessCommandLine has "--mode " and ProcessCommandLine has_any ("--dir","--file"),"locker","")
| where isnotempty(Stage)
| summarize Stages=make_set(Stage), Commands=make_set(ProcessCommandLine,30), First=min(Timestamp), Last=max(Timestamp) by DeviceName, bin(Timestamp,7d);
let f = DeviceFileEvents
| where Timestamp > ago(30d) and FileName endswith ".lynx"
| summarize Encrypted=count() by DeviceName, bin(Timestamp,7d);
p | join kind=leftouter f on DeviceName, Timestamp
| where array_length(Stages) >= 2 or Encrypted >= 20
```

## 10. Campaign Artifact Hunts

### 10.1 LNX23 — Exact case hashes for NetScan and NetExec

**Origin:** The DFIR Report case artifacts.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Exact legitimate/dual-use tool versions; a hit does not identify Lynx without sequence evidence.

```kusto
let hashes = dynamic(["517288e12c05a92e483e6d80b9136c19bc58c46851720680bb6d1b7016034c37","6285d32a9491a0084da85a384a11e15e203badf67b1deed54155f02b7338b108"]);
union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(180d) and SHA256 in (hashes) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, AccountName, ProcessCommandLine),
(DeviceFileEvents | where Timestamp > ago(180d) and SHA256 in (hashes) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, AccountName=InitiatingProcessAccountName, ProcessCommandLine=InitiatingProcessCommandLine)
```

### 10.2 LNX24 — NetScan, NetExec and locker artifact bundle

**Origin:** Repository-authored from the documented case.

**Telemetry:** MDE DeviceFileEvents.

**Review / tuning:** Require several distinct artifacts on the same device; paths may vary.

```kusto
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("netscan.xml","netscan.lic","ss.xml","delete.me","nxc.exe","nxc.txt","smb.db","w.exe","README.txt") or FileName endswith ".lynx"
| summarize Artifacts=make_set(FileName,30), DistinctArtifacts=dcount(FileName), First=min(Timestamp), Last=max(Timestamp)
  by DeviceName, InitiatingProcessAccountName, bin(Timestamp,24h)
| where DistinctArtifacts >= 4
```

### 10.3 LNX25 — Unexpected Atera or Splashtop service activity

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** MDE DeviceProcessEvents and DeviceEvents.

**Review / tuning:** Allow approved RMM tenants, signed paths and deployment windows.

```kusto
union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(30d) | where FileName in~ ("AteraAgent.exe","SRService.exe") or ProcessCommandLine has_any ("AteraAgent","Splashtop Remote") | project Timestamp, DeviceName, AccountName, Evidence=strcat(FolderPath,"\\",FileName), ActionType, Details=ProcessCommandLine),
(DeviceEvents | where Timestamp > ago(30d) and ActionType has "Service" | where AdditionalFields has_any ("AteraAgent","Splashtop","SRService") | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Evidence=InitiatingProcessFileName, ActionType, Details=tostring(AdditionalFields))
```

### 10.4 LNX26 — Mimikatz or SessionGopher staging

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Authorized assessments can match; correlate with VPN/RMM access and credential events.

```kusto
union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(30d) | where FileName in~ ("mimikatz.exe","powershell.exe","pwsh.exe") | where FileName =~ "mimikatz.exe" or ProcessCommandLine has "SessionGopher" | project Timestamp, DeviceName, AccountName, Evidence=ProcessCommandLine, SHA256, ActionType),
(DeviceFileEvents | where Timestamp > ago(30d) and FileName in~ ("mimikatz.exe","SessionGopher.ps1") | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Evidence=strcat(FolderPath,"\\",FileName), SHA256, ActionType)
```

### 10.5 LNX27 — Rclone with Lynx case wrapper artifacts

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Rclone is legitimate. Raise priority when case wrapper files appear on the same device.

```kusto
let tools = DeviceProcessEvents
| where Timestamp > ago(30d) and (FileName =~ "rclone.exe" or ProcessCommandLine has_any ("rcl.bat","nocmd.vbs"))
| summarize ToolCommands=make_set(ProcessCommandLine,20), First=min(Timestamp), Last=max(Timestamp) by DeviceName, bin(Timestamp,24h);
let artifacts = DeviceFileEvents
| where Timestamp > ago(30d) and FileName in~ ("rcl.bat","nocmd.vbs","hosts.txt","domain_ips.txt")
| summarize Artifacts=make_set(strcat(FolderPath,"\\",FileName),20) by DeviceName, bin(Timestamp,24h);
tools | join kind=leftouter artifacts on DeviceName, Timestamp
```

### 10.6 LNX28 — GPO and NETLOGON locker deployment

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Validate administrators and change windows; `gpscript.exe` is legitimate outside suspicious task/payload creation.

```kusto
union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(30d) | where FileName in~ ("gpscript.exe","schtasks.exe") | where ProcessCommandLine has_any ("NETLOGON","pushprinterconnections.exe","\\\\SYSVOL\\") | project Timestamp, DeviceName, AccountName, Evidence=ProcessCommandLine, ActionType),
(DeviceFileEvents | where Timestamp > ago(30d) | where FolderPath has_any ("\\NETLOGON","\\SYSVOL") and FileName in~ ("pushprinterconnections.exe","w.exe","1.exe") | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Evidence=strcat(FolderPath,"\\",FileName), ActionType)
```
