# Lynx — Splunk Hunting Searches

**Presentation reviewed:** 2026-10-07.
**Last updated:** 2026-10-07  
**TLP:** CLEAR

## Scope and Requirements

Searches assume Sysmon/EDR in `index=endpoint`, Windows Security in `index=wineventlog`, authentication in `index=auth`, network/proxy data in `index=network`, and forwarded ESXi logs in `index=esxi`. Replace indexes and fields with local CIM mappings.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| LNX01–LNX06 | Remote access, credential testing and discovery | Baseline jump hosts, scanners and administrators |
| LNX07–LNX11 | Persistence, remote administration and historical access | Validate requester, signer and IP history |
| LNX12–LNX18 | Evasion, collection, exfiltration and recovery inhibition | Confirm outcomes and maintenance windows |
| LNX19–LNX28 | Locker identity, impact, sequence and campaign artifacts | Exact values and affiliate artifacts are narrow and historical |

## Interpretation Notes

Field names vary by sensor. These searches return hunting leads; RDP, AnyDesk, NetScan, NetExec and 7-Zip require surrounding identity, signer, path, destination and chronology.

## 1. Credential Access

### 1.1 LNX01 — External RDP success from a rare source

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** Windows Security 4624 or normalized authentication logs.

**Review / tuning:** Exclude approved VPN egress and jump hosts; tune public/private addressing.

```spl
index=wineventlog EventCode=4624 LogonType=10 src_ip!="" NOT src_ip IN ("10.*","172.16.*","192.168.*")
| eventstats count as src_events dc(host) as src_hosts by src_ip
| where src_events<25 AND src_hosts<5
| table _time host TargetUserName src_ip WorkstationName AuthenticationPackageName
```

### 1.2 LNX02 — NetExec-style SMB password spray

**Origin:** Repository-authored from observed `nxc.exe smb` activity.

**Telemetry:** Sysmon Event 1 or EDR process telemetry.

**Review / tuning:** Authorized testing can match; verify account and scope.

```spl
index=endpoint EventCode=1 Image IN ("*\\nxc.exe","*\\netexec.exe","*\\crackmapexec.exe") CommandLine="* smb *" (CommandLine="* -u *" OR CommandLine="* --username *") (CommandLine="* -p *" OR CommandLine="* --password *")
| table _time host User Image CommandLine ParentImage SHA256 ProcessGuid
```

## 2. Active Directory and Network Discovery

### 2.1 LNX03 — SoftPerfect NetScan execution or case hash

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Inventory teams use NetScan; validate account, path and downstream activity.

```spl
index=endpoint EventCode=1 (Image IN ("*\\netscan.exe","*\\netscan64.exe") OR SHA256="517288e12c05a92e483e6d80b9136c19bc58c46851720680bb6d1b7016034c37")
| table _time host User Image CommandLine ParentImage SHA256 ProcessGuid
```

### 2.2 LNX04 — NetScan share write-access probe

**Origin:** Repository-authored from `delete.me` behavior.

**Telemetry:** Sysmon Event 11 or Windows share event 5145.

**Review / tuning:** Require multiple paths or NetScan process context.

```spl
(index=endpoint EventCode=11 TargetFilename="*\\delete.me") OR (index=wineventlog EventCode=5145 RelativeTargetName="*delete.me")
| bin _time span=30m
| stats dc(TargetFilename) as paths values(TargetFilename) as files values(Image) as images by _time host User
| where paths>=3 OR mvfind(images,"(?i)netscan")>=0
```

### 2.3 LNX05 — Native discovery burst

**Origin:** Repository-authored from observed commands.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Help-desk and inventory scripts can match.

```spl
index=endpoint EventCode=1 Image IN ("*\\ipconfig.exe","*\\route.exe","*\\systeminfo.exe","*\\ping.exe","*\\net.exe","*\\net1.exe","*\\nslookup.exe","*\\nbtstat.exe","*\\reg.exe")
| bin _time span=30m
| stats dc(Image) as tools values(CommandLine) as commands by _time host User ParentImage
| where tools>=5
```

### 2.4 LNX06 — Virtualization and directory MMC discovery

**Origin:** Repository-authored from observed GUI tooling.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Administrators use these snap-ins; correlate with unusual RDP sessions.

```spl
index=endpoint EventCode=1 Image="*\\mmc.exe" (CommandLine="*dsa.msc*" OR CommandLine="*lusrmgr.msc*" OR CommandLine="*virtmgmt.msc*")
| table _time host User Image CommandLine ParentImage ParentCommandLine
```

## 3. Persistence and Remote Administration

### 3.1 LNX07 — Domain account creation followed by privileged group addition

**Origin:** Repository-authored from lookalike-account persistence.

**Telemetry:** Windows Security 4720, 4728, 4732 and 4756.

**Review / tuning:** Exclude approved provisioning and service accounts.

```spl
index=wineventlog EventCode IN (4720,4728,4732,4756)
| transaction TargetUserName maxspan=24h startswith=(EventCode=4720)
| where eventcount>=2 AND (mvfind(GroupName,"(?i)Domain Admins")>=0 OR mvfind(GroupName,"(?i)Group Policy Creator Owners")>=0 OR mvfind(GroupName,"(?i)Administrators")>=0)
| table _time host SubjectUserName TargetUserName GroupName EventCode duration
```

### 3.2 LNX08 — AnyDesk service installation

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** Sysmon Event 1 and Windows System 7045.

**Review / tuning:** Exclude managed deployment by signer, package and account.

```spl
(index=endpoint EventCode=1 ((Image="*\\AnyDesk.exe" CommandLine IN ("*--install*","*--start-with-win*","*--service*")) OR (Image IN ("*\\sc.exe","*\\powershell.exe","*\\cmd.exe") CommandLine="*AnyDesk*")))
OR (index=wineventlog EventCode=7045 (ServiceName="*AnyDesk*" OR ImagePath="*AnyDesk*"))
| table _time host EventCode User ServiceName ImagePath Image CommandLine ParentImage
```

### 3.3 LNX09 — Non-expiring account configuration

**Origin:** Repository-authored from observed account configuration.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Service-account configuration is a common benign cause.

```spl
index=endpoint EventCode=1 Image IN ("*\\net.exe","*\\net1.exe","*\\powershell.exe","*\\pwsh.exe","*\\dsmod.exe") (CommandLine="*/expires:never*" OR CommandLine="*PasswordNeverExpires*" OR CommandLine="*-pwdneverexpires yes*")
| table _time host User Image CommandLine ParentImage ProcessGuid
```

## 4. Tunneling and C2

### 4.1 LNX10 — Rare AnyDesk network activity

**Origin:** Repository-authored from incident RMM installation.

**Telemetry:** Sysmon Event 3 or normalized endpoint network data.

**Review / tuning:** Exclude enterprise-managed endpoints and approved relays.

```spl
index=endpoint EventCode=3 Image="*\\AnyDesk.exe"
| stats count values(DestinationHostname) as destinations values(DestinationIp) as ips earliest(_time) as first latest(_time) as last by host User SHA256
```

### 4.2 LNX11 — Historical Lynx affiliate RDP sources

**Origin:** Exact IPs from the DFIR case.

**Telemetry:** Windows authentication and network telemetry.

**Review / tuning:** Retrospective pivot; ownership can change.

```spl
(index=wineventlog EventCode=4624 LogonType=10 src_ip IN ("195.211.190.189","77.90.153.30","79.141.172.131","185.33.87.207")) OR (index=endpoint EventCode=3 SourceIp IN ("195.211.190.189","77.90.153.30","79.141.172.131","185.33.87.207") OR DestinationIp IN ("195.211.190.189","77.90.153.30","79.141.172.131","185.33.87.207"))
| table _time host User TargetUserName src_ip SourceIp DestinationIp Image WorkstationName
```

## 5. Defense Evasion and Impairment

### 5.1 LNX12 — Burst of backup/database service stops

**Origin:** Repository-authored from Lynx kill-list behavior.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Planned maintenance can match; require later impact or several service families.

```spl
index=endpoint EventCode=1 Image IN ("*\\sc.exe","*\\net.exe","*\\net1.exe","*\\powershell.exe","*\\pwsh.exe") (CommandLine="* stop *" OR CommandLine="*Stop-Service*" OR CommandLine="*Set-Service*") (CommandLine="*sql*" OR CommandLine="*veeam*" OR CommandLine="*backup*" OR CommandLine="*exchange*")
| bin _time span=30m
| stats count values(CommandLine) as commands by _time host User ParentImage
| where count>=2
```

### 5.2 LNX13 — Locker flags for hidden, silent or safe-mode behavior

**Origin:** Published Lynx CLI.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Validate multiple flags, hash and subsequent file impact.

```spl
index=endpoint EventCode=1 (CommandLine="*--load-drives*" OR CommandLine="*--stop-processes*" OR CommandLine="*--encrypt-network*" OR CommandLine="*--hide-cmd*" OR CommandLine="*--safe-mode*" OR CommandLine="*--no-background*" OR CommandLine="*--no-print*" OR CommandLine="*--noprint*")
| table _time host User Image CommandLine ParentImage SHA256 ProcessGuid
```

### 5.3 LNX14 — High-rate ownership or ACL changes

**Origin:** Repository-authored from the file-ownership/DACL branch.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Restore and remediation workflows can match; API-only Lynx behavior needs EDR telemetry.

```spl
index=endpoint EventCode=1 Image IN ("*\\takeown.exe","*\\icacls.exe") (CommandLine="* /f *" OR CommandLine="* /grant *" OR CommandLine="* /setowner *")
| bin _time span=30m
| stats count values(CommandLine) as commands by _time host User ParentImage
| where count>=5 OR NOT ParentImage IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe")
```

## 6. Collection and Exfiltration

### 6.1 LNX15 — 7-Zip archive creation from an interactive desktop

**Origin:** Repository-authored from the DFIR case.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Prioritize privileged accounts, network paths and multiple archives.

```spl
index=endpoint EventCode=1 Image IN ("*\\7zG.exe","*\\7z.exe","*\\7za.exe") (CommandLine="* a *" OR CommandLine="*.7z*" OR CommandLine="*.zip*" OR ParentImage="*\\explorer.exe")
| table _time host User Image CommandLine ParentImage SHA256 ProcessGuid
```

### 6.2 LNX16 — Browser upload to `temp.sh` after archive creation

**Origin:** Repository-authored from confirmed browser uploads.

**Telemetry:** Proxy/network logs plus endpoint process data.

**Review / tuning:** Confirm upload path and bytes sent; legitimate use is possible.

```spl
(index=endpoint EventCode=1 Image IN ("*\\7zG.exe","*\\7z.exe","*\\7za.exe")) OR (index=network dest_domain="temp.sh" process_name IN ("msedge.exe","chrome.exe","firefox.exe"))
| eval stage=if(index="network","upload","archive")
| transaction host User maxspan=6h
| where mvfind(stage,"archive")>=0 AND mvfind(stage,"upload")>=0
| table _time host User stage Image CommandLine dest_domain uri bytes_out
```

## 7. Recovery Inhibition

### 7.1 LNX17 — Shadow-copy or VSS storage impairment commands

**Origin:** Repository-authored around recovery inhibition; built-in device control may not create a child command.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Confirm command result and before/after VSS state.

```spl
index=endpoint EventCode=1 ((Image IN ("*\\vssadmin.exe","*\\wmic.exe","*\\powershell.exe","*\\pwsh.exe") (CommandLine="*delete shadows*" OR CommandLine="*shadowcopy delete*" OR CommandLine="*Win32_ShadowCopy*" OR CommandLine="*Resize ShadowStorage*")) OR (Image="*\\diskshadow.exe" (CommandLine="*delete*" OR CommandLine="*reset*")))
| table _time host User Image CommandLine ParentImage SHA256
```

### 7.2 LNX18 — ESXi VM force-stop or snapshot removal loop

**Origin:** Published Lynx Linux/ESXi scripts.

**Telemetry:** Forwarded ESXi shell/syslog.

**Review / tuning:** Planned host maintenance can match; correlate with datastore file changes.

```spl
index=esxi (message="*esxcli vm process kill*" OR message="*vim-cmd vmsvc/snapshot.removeall*")
| table _time host user process message
```

## 8. Deployment and Impact

### 8.1 LNX19 — Exact published Lynx locker SHA-256

**Origin:** Published sample corpus.

**Telemetry:** Sysmon Event 1/11 or EDR file/process data.

**Review / tuning:** Exact sample identity; confirm execution and affected scope.

```spl
index=endpoint SHA256 IN ("eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc","571f5de9dd0d509ed7e5242b9b7473c2b2cbb36ba64d38b32122a0a337d6cf8b","82eb1910488657c78bef6879908526a2a2c6c31ab2f0517fcc5f3f6aa588b513","b378b7ef0f906358eec595777a50f9bb5cc7bb6635e0f031d65b818a26bdc4ee","ecbfea3e7869166dd418f15387bc33ce46f2c72168f571071916b5054d7f6e49","85699c7180ad77f2ede0b15862bb7b51ad9df0478ed394866ac7fa9362bf5683","09c5ff735d3d7b8c47b4df7de35e1c72b530b2c2566628bc29aaa54feb4d89f4","07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a","c3b57cd2c04ffd6dd173edfd975d2b05b7f6f502062a56b8585bda8776824a18","6e65483764d7c25523a5bbef5be99eb42349eef39d5517c46b3a4af262a80ceb")
| table _time host User EventCode Image TargetFilename CommandLine ParentImage SHA256
```

### 8.2 LNX20 — Lynx command-line mode and scope

**Origin:** Published CLI and observed `w.exe` execution.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Require mode plus scope/impact flag.

```spl
index=endpoint EventCode=1 (CommandLine="*--mode fast*" OR CommandLine="*--mode medium*" OR CommandLine="*--mode slow*" OR CommandLine="*--mode entire*") (CommandLine="*--dir*" OR CommandLine="*--file*" OR CommandLine="*--encrypt-network*" OR CommandLine="*--load-drives*" OR CommandLine="*--noprint*" OR CommandLine="*--no-print*")
| table _time host User Image CommandLine ParentImage SHA256 ProcessGuid
```

### 8.3 LNX21 — `.LYNX` and `README.txt` fan-out

**Origin:** Published output artifacts.

**Telemetry:** Sysmon Event 11 or EDR file telemetry.

**Review / tuning:** Require scale or note-and-extension pairing.

```spl
index=endpoint EventCode=11 (TargetFilename="*.LYNX" OR TargetFilename="*\\README.txt")
| eval lynx=if(match(lower(TargetFilename),"\\.lynx$"),1,0), note=if(match(lower(TargetFilename),"\\\\readme\\.txt$"),1,0)
| bin _time span=10m
| stats sum(lynx) as lynx_files sum(note) as notes dc(TargetFilename) as paths values(TargetFilename) as examples by _time host Image SHA256 User
| where lynx_files>=20 OR (lynx_files>=5 AND notes>=1)
```

## 9. Multi-Stage Correlation

### 9.1 LNX22 — Discovery, archive and impact on one device

**Origin:** Repository-authored from the nine-day affiliate sequence.

**Telemetry:** Sysmon process/file telemetry.

**Review / tuning:** Use a broad window for hunting, then validate order with raw timestamps.

```spl
index=endpoint ((EventCode=1 (Image IN ("*\\netscan.exe","*\\nxc.exe","*\\netexec.exe","*\\7zG.exe","*\\7z.exe","*\\7za.exe") OR CommandLine="*--mode *")) OR (EventCode=11 TargetFilename="*.LYNX"))
| eval stage=case(match(lower(Image),"netscan|nxc|netexec"),"discovery",match(lower(Image),"7zg|7z.exe|7za"),"archive",match(CommandLine,"--mode "),"locker",match(lower(TargetFilename),"\\.lynx$"),"impact")
| bin _time span=7d
| stats dc(stage) as stages values(stage) as stage_set values(CommandLine) as commands by _time host User
| where stages>=3
```

## 10. Campaign Artifact Hunts

### 10.1 LNX23 — Exact case hashes for NetScan and NetExec

**Origin:** The DFIR Report case artifacts.

**Telemetry:** Sysmon/EDR process and file events.

**Review / tuning:** Exact legitimate/dual-use versions; require sequence evidence for attribution.

```spl
index=endpoint SHA256 IN ("517288e12c05a92e483e6d80b9136c19bc58c46851720680bb6d1b7016034c37","6285d32a9491a0084da85a384a11e15e203badf67b1deed54155f02b7338b108")
| table _time host User EventCode Image TargetFilename CommandLine ParentImage SHA256
```

### 10.2 LNX24 — NetScan, NetExec and locker artifact bundle

**Origin:** Repository-authored from the documented case.

**Telemetry:** Sysmon Event 11 or EDR file telemetry.

**Review / tuning:** Require several distinct artifacts on one device.

```spl
index=endpoint EventCode=11 (TargetFilename IN ("*\\netscan.xml","*\\netscan.lic","*\\ss.xml","*\\delete.me","*\\nxc.exe","*\\nxc.txt","*\\smb.db","*\\w.exe","*\\README.txt") OR TargetFilename="*.LYNX")
| bin _time span=24h
| stats dc(TargetFilename) as artifacts values(TargetFilename) as files by _time host User Image
| where artifacts>=4
```

### 10.3 LNX25 — Unexpected Atera or Splashtop service activity

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** Sysmon Event 1 and Windows System Event 7045.

**Review / tuning:** Allow approved RMM tenants, signed paths and deployment windows.

```spl
(index=endpoint EventCode=1 (Image IN ("*\\AteraAgent.exe","*\\SRService.exe") OR CommandLine IN ("*AteraAgent*","*Splashtop Remote*"))) OR (index=wineventlog EventCode=7045 (ServiceName IN ("*Atera*","*Splashtop*","*SRService*") OR ImagePath IN ("*Atera*","*Splashtop*")))
| table _time host User EventCode Image CommandLine ServiceName ImagePath
```

### 10.4 LNX26 — Mimikatz or SessionGopher staging

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** Sysmon Events 1/11 and PowerShell 4104.

**Review / tuning:** Authorized assessments can match; correlate with remote access and authentication anomalies.

```spl
(index=endpoint EventCode IN (1,11) (Image="*\\mimikatz.exe" OR TargetFilename IN ("*\\mimikatz.exe","*\\SessionGopher.ps1") OR CommandLine="*SessionGopher*")) OR (index=wineventlog EventCode=4104 ScriptBlockText="*SessionGopher*")
| table _time host User EventCode Image TargetFilename CommandLine ScriptBlockText SHA256
```

### 10.5 LNX27 — Rclone with Lynx case wrapper artifacts

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** Sysmon process/file telemetry.

**Review / tuning:** Rclone is legitimate; prioritize co-occurring wrapper and discovery files.

```spl
index=endpoint ((EventCode=1 (Image="*\\rclone.exe" OR CommandLine IN ("*rcl.bat*","*nocmd.vbs*"))) OR (EventCode=11 TargetFilename IN ("*\\rcl.bat","*\\nocmd.vbs","*\\hosts.txt","*\\domain_ips.txt")))
| bin _time span=24h
| stats values(Image) as images values(CommandLine) as commands values(TargetFilename) as files dc(TargetFilename) as artifacts by _time host User
```

### 10.6 LNX28 — GPO and NETLOGON locker deployment

**Origin:** PacketWatch 2026 incident response.

**Telemetry:** Sysmon Events 1/11 and scheduled-task telemetry.

**Review / tuning:** Validate change windows and administrative ownership.

```spl
index=endpoint ((EventCode=1 Image IN ("*\\gpscript.exe","*\\schtasks.exe") (CommandLine IN ("*NETLOGON*","*pushprinterconnections.exe*","*\\SYSVOL\\*"))) OR (EventCode=11 TargetFilename IN ("*\\NETLOGON\\*pushprinterconnections.exe","*\\NETLOGON\\*w.exe","*\\NETLOGON\\*1.exe","*\\SYSVOL\\*pushprinterconnections.exe")))
| table _time host User EventCode Image ParentImage CommandLine TargetFilename SHA256
```
