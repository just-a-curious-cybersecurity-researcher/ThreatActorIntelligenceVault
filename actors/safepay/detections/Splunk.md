# SafePay — Splunk Hunting Searches

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope and Requirements

Searches assume Sysmon/EDR data in `index=endpoint`, Windows security events in `index=wineventlog`, identity or VPN events in `index=auth` and normalized web/network events in `index=network`. Replace indexes and fields with local CIM mappings.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| SP01–SP06 | Authentication, credential access and discovery | Baseline help-desk, scanner and administrator behavior |
| SP07–SP12 | Persistence, RMM and QDoor/C2 | Validate signer, tenant, parent process and destination ownership |
| SP13–SP21 | Locker execution, evasion, collection and recovery inhibition | Correlate command line with outcome and maintenance windows |
| SP22–SP31 | Exact artifacts, impact, correlations and campaign pivots | Exact values are historical; sequence logic needs local thresholds |

## Interpretation Notes

These searches are repository-authored and return hunting leads. Preserve process GUIDs, ancestry, account, signer, source address and file/network events before making an attribution judgment.

## 1. Credential Access

### 1.1 SP01 — VPN or remote-access password spray followed by success

**Origin:** Repository-authored from DCSO and NCC incident evidence.

**Telemetry:** Normalized VPN/RDP authentication logs.

**Review / tuning:** Normalize result values and exclude health checks, scanners and recurring user mistakes.

```spl
index=auth application IN ("*VPN*","*RDP*","*Remote Desktop*","*Forti*")
| eval failure=if(match(action,"(?i)fail|deny"),1,0), success=if(match(action,"(?i)success|allow"),1,0)
| bin _time span=30m
| stats sum(failure) as failures dc(eval(if(failure=1,user,null()))) as failed_users sum(success) as successes values(user) as users by _time src application
| where (failures>=15 OR failed_users>=5) AND successes>=1
```

### 1.2 SP02 — Mimikatz or RemoteRegDump-like activity

**Origin:** Repository-authored from Microsoft/Halcyon tooling and NCC incident evidence.

**Telemetry:** Sysmon Event 1/11 or equivalent EDR process/file telemetry.

**Review / tuning:** Security testing can match; verify parent, path, signer and credential-store access.

```spl
index=endpoint (EventCode=1 (Image="*\\mimikatz.exe" OR CommandLine IN ("*sekurlsa::*","*lsadump::*","*privilege::debug*","*comsvcs.dll, MiniDump*")))
OR (EventCode=11 (TargetFilename="*\\RRZqKUbG.tmp" OR SHA1="07353237350c35d6dc2c8f143b649cd07c71f62b"))
| table _time host User EventCode Image CommandLine ParentImage TargetFilename SHA1 SHA256
```

### 1.3 SP03 — Administrative password or privileged-group changes near impact

**Origin:** Repository-authored from NCC's observed administrator-password changes.

**Telemetry:** Sysmon Event 1 and Windows Security 4723/4724/4728/4732.

**Review / tuning:** Planned identity administration can match; correlate with source host and later impact.

```spl
(index=endpoint EventCode=1 Image IN ("*\\net.exe","*\\net1.exe","*\\powershell.exe","*\\pwsh.exe","*\\dsmod.exe")
 (CommandLine="* user *" OR CommandLine="*Set-ADAccountPassword*" OR CommandLine="*localgroup administrators*" OR CommandLine="*Domain Admins*"))
OR (index=wineventlog EventCode IN (4723,4724,4728,4732))
| table _time host EventCode User SubjectUserName TargetUserName MemberName Image CommandLine ParentImage
```

## 2. Active Directory and Network Discovery

### 2.1 SP04 — ShareFinder, SharpShares or related share discovery

**Origin:** Repository-authored from Huntress and DCSO cases.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Approved security assessment and inventory activity can match.

```spl
index=endpoint EventCode=1
(Image IN ("*\\ShareFinder.exe","*\\SharpShares.exe") OR CommandLine IN ("*Invoke-ShareFinder*","*Find-InterestingDomainShare*","*SharpShares*"))
| table _time host User Image CommandLine ParentImage Hashes ProcessGuid
```

### 2.2 SP05 — Native discovery burst

**Origin:** Repository-authored from SafePay incident-response command patterns.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Require a burst from an unusual account or parent process.

```spl
index=endpoint EventCode=1 Image IN ("*\\whoami.exe","*\\ipconfig.exe","*\\nltest.exe","*\\net.exe","*\\net1.exe","*\\quser.exe","*\\qwinsta.exe","*\\tasklist.exe","*\\wmic.exe")
| bin _time span=15m
| stats dc(Image) as commands values(CommandLine) as examples by _time host User ParentImage
| where commands>=4
```

### 2.3 SP06 — SMB fan-out from one process

**Origin:** Repository-authored from SMB deployment and remote-share encryption evidence.

**Telemetry:** Sysmon Event 3 or normalized endpoint network events.

**Review / tuning:** Baseline backup, deployment and file-server processes.

```spl
index=endpoint EventCode=3 DestinationPort=445
| bin _time span=10m
| stats dc(DestinationIp) as targets values(DestinationIp) as remote_hosts by _time host Image ProcessGuid User
| where targets>=15
```

## 3. Persistence and Remote Administration

### 3.1 SP07 — ScreenConnect service creation or configuration

**Origin:** Repository-authored from NCC and Microsoft reporting.

**Telemetry:** Sysmon Event 1 or Windows System 7045.

**Review / tuning:** Compare service path, signer and tenant with approved ScreenConnect inventory.

```spl
(index=endpoint EventCode=1 (Image IN ("*\\sc.exe","*\\powershell.exe","*\\pwsh.exe","*\\ScreenConnect.ClientService.exe")
 (CommandLine="*ScreenConnect Client*" OR CommandLine="*ScreenConnect.ClientService*" OR CommandLine="*New-Service*")))
OR (index=wineventlog EventCode=7045 ServiceName="*ScreenConnect*")
| table _time host EventCode User Image CommandLine ParentImage ServiceName ImagePath
```

### 3.2 SP08 — New autorun value referencing an uncommon executable

**Origin:** Repository-authored from Microsoft-observed optional Run-key persistence.

**Telemetry:** Sysmon Event 13.

**Review / tuning:** Software installation commonly creates autoruns; validate signer and path.

```spl
index=endpoint EventCode=13 TargetObject IN ("*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*","*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*")
(Details="*.exe*" OR Details="*.dll*" OR Details="*regsvr32*" OR Details="*rundll32*")
| table _time host User Image TargetObject Details ProcessGuid
```

### 3.3 SP09 — First-seen ScreenConnect or transfer utility

**Origin:** Repository-authored from SafePay RMM and transfer-tool evidence.

**Telemetry:** Sysmon Event 1 or CIM Endpoint.Processes.

**Review / tuning:** Compare against sanctioned installers and managed endpoints.

```spl
index=endpoint EventCode=1
(Image IN ("*screenconnect*","*filezilla*","*fzsftp*","*rclone*") OR Product IN ("*ScreenConnect*","*FileZilla*","*Rclone*"))
| stats min(_time) as first max(_time) as last values(CommandLine) as commands values(Hashes) as hashes by host User Image
| where first>=relative_time(now(),"-7d")
```

## 4. Tunneling and C2

### 4.1 SP10 — Published SafePay/QDoor C2 endpoints

**Origin:** Repository-authored from NCC, Microsoft and Halcyon indicators.

**Telemetry:** Sysmon Event 3 or normalized network telemetry.

**Review / tuning:** Historical infrastructure can be reassigned; validate ownership and observation time.

```spl
index=endpoint EventCode=3 DestinationIp IN ("88.119.167.239","45.91.201.247","77.37.49.40","80.78.28.63")
| table _time host User Image CommandLine DestinationIp DestinationPort ProcessGuid Hashes
```

### 4.2 SP11 — Imgur wallpaper resource retrieval

**Origin:** Repository-authored from Microsoft SafePay behavior.

**Telemetry:** Proxy, DNS or endpoint network telemetry.

**Review / tuning:** Imgur is legitimate; require the exact resource and surrounding impact activity.

```spl
index=network (url="*i.imgur.com/zhCjntO.png*" OR (dest_ip="199.232.192.193" process IN ("powershell.exe","pwsh.exe")))
| table _time host user process process_command_line url dest_ip dest_port
```

### 4.3 SP12 — QDoor-style `regsvr32` launch followed by `WerFault.exe`

**Origin:** Repository-authored from NCC reverse engineering.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Ordinary crash handling can launch WerFault; inspect regsvr32 ancestry and DLL identity.

```spl
index=endpoint EventCode=1
((Image="*\\regsvr32.exe" (CommandLine="*soc.dll*" OR CommandLine="*/s*")) OR (Image="*\\WerFault.exe" ParentImage="*\\regsvr32.exe"))
| table _time host User Image CommandLine ParentImage ParentCommandLine Hashes ProcessGuid ParentProcessGuid
```

## 5. Defense Evasion and Impairment

### 5.1 SP13 — SafePay locker command-line cluster

**Origin:** Repository-authored from Huntress and NCC binary/incident analysis.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Preserve the full command line and parent; the combined switches are high-context.

```spl
index=endpoint EventCode=1 CommandLine="*-pass=*" (CommandLine="*-enc=*" OR CommandLine="*-enc *")
(CommandLine="*-path=*" OR CommandLine="*-network*" OR CommandLine="*-netdrive*" OR CommandLine="*-selfdelete*" OR CommandLine="*-uac*")
| table _time host User Image CommandLine ParentImage Hashes ProcessGuid
```

### 5.2 SP14 — CMSTPLUA auto-elevation sequence

**Origin:** Repository-authored from Huntress binary analysis.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Correlate CLSID or DllHost ancestry with locker arguments.

```spl
index=endpoint EventCode=1
(CommandLine="*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}*" OR (Image="*\\DllHost.exe" (ParentCommandLine="*-uac*" OR ParentCommandLine="*-pass=*" OR ParentCommandLine="*-enc=*")))
| table _time host User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 5.3 SP15 — Defender impairment through command line or trusted UI flow

**Origin:** Repository-authored from Huntress and Microsoft observations.

**Telemetry:** Sysmon Event 1 and Defender Operational 5001/5007.

**Review / tuning:** Approved security administration can match; verify initiating account and later impact.

```spl
(index=endpoint EventCode=1 Image IN ("*\\powershell.exe","*\\pwsh.exe","*\\SystemSettingsAdminFlows.exe","*\\MpCmdRun.exe")
 (CommandLine IN ("*DisableRealtimeMonitoring*","*Set-MpPreference*","*Add-MpPreference*","*WindowsDefender*","*VirusThreatProtection*") OR Image="*\\SystemSettingsAdminFlows.exe"))
OR (index=wineventlog EventCode IN (5001,5007) source="*Windows Defender*")
| table _time host EventCode User Image CommandLine ParentImage Message
```

### 5.4 SP16 — Burst of service or process termination

**Origin:** Repository-authored from SafePay locker service/process kill lists.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Maintenance can stop services; require multiple targets and impact context.

```spl
index=endpoint EventCode=1 Image IN ("*\\sc.exe","*\\net.exe","*\\net1.exe","*\\taskkill.exe","*\\powershell.exe","*\\pwsh.exe")
(CommandLine="* stop *" OR CommandLine="*taskkill*" OR CommandLine="*Stop-Service*" OR CommandLine="*Stop-Process*")
| bin _time span=10m
| stats count as stops values(CommandLine) as targets by _time host User ParentImage
| where stops>=5
```

### 5.5 SP17 — Self-delete or delayed deletion of an executable

**Origin:** Repository-authored from the SafePay `-selfdelete` capability.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Installers can self-delete; prioritize impact switches and temporary paths.

```spl
index=endpoint EventCode=1
(CommandLine="*-selfdelete*" OR (Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe") (CommandLine="*del /f /q*" OR CommandLine="*Remove-Item*") (CommandLine="*.exe*" OR CommandLine="*.dll*")))
| table _time host User Image CommandLine ParentImage ParentCommandLine
```

## 6. Collection and Exfiltration

### 6.1 SP18 — WinRAR archiving of remote-user or share data

**Origin:** Repository-authored from Huntress and DCSO incident evidence.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Authorized archival jobs can match; prioritize UNC paths and user-profile data.

```spl
index=endpoint EventCode=1 Image IN ("*\\rar.exe","*\\winrar.exe")
(CommandLine="*\\\\*" OR CommandLine="*\\Users\\*" OR CommandLine="*\\Shares\\*" OR CommandLine="* -v*" OR CommandLine="* a *")
| table _time host User Image CommandLine ParentImage Hashes ProcessGuid
```

### 6.2 SP19 — Transfer or compression utilities

**Origin:** Repository-authored from Microsoft, Huntress and FortiGuard reporting.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Validate package provenance, destination and transfer volume.

```spl
index=endpoint EventCode=1 Image IN ("*\\filezilla.exe","*\\fzsftp.exe","*\\rclone.exe","*\\7z.exe","*\\7za.exe")
| table _time host User Image CommandLine ParentImage Hashes ProcessGuid
```

## 7. Recovery Inhibition

### 7.1 SP20 — Shadow-copy deletion

**Origin:** Repository-authored from Huntress, DCSO, NCC and Microsoft behavior.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Backup maintenance can match; correlate with parent and file impact.

```spl
index=endpoint EventCode=1
((Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*") OR
 (Image="*\\wmic.exe" CommandLine="*shadowcopy*" CommandLine="*delete*") OR
 (Image IN ("*\\powershell.exe","*\\pwsh.exe") (CommandLine="*Win32_ShadowCopy*" OR CommandLine="*Get-WmiObject Win32_Shadowcopy*")))
| table _time host User Image CommandLine ParentImage Hashes ProcessGuid
```

### 7.2 SP21 — Boot recovery disabled

**Origin:** Repository-authored from published SafePay recovery commands.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Rare outside recovery or imaging workflows; validate change outcome.

```spl
index=endpoint EventCode=1 Image="*\\bcdedit.exe"
(CommandLine="*recoveryenabled no*" OR CommandLine="*bootstatuspolicy ignoreallfailures*")
| table _time host User Image CommandLine ParentImage Hashes ProcessGuid
```

## 8. Deployment and Impact

### 8.1 SP22 — Exact published SafePay-associated and QDoor hashes

**Origin:** Repository-authored from the local hash-provenance register.

**Telemetry:** Sysmon Event 1/11 or normalized EDR hash telemetry.

**Review / tuning:** Exact matches are high-priority but identify only published artifacts.

```spl
index=endpoint (EventCode=1 OR EventCode=11)
| rex field=Hashes "(?i)SHA256=(?<sysmon_sha256>[A-Fa-f0-9]{64})"
| eval observed_sha256=lower(coalesce(SHA256,sysmon_sha256))
| where observed_sha256 IN ("0f23a313f79d54ae2102f193d3de1a6a98791c27921f28a4fab1092bcb43e5ee","12139246b8c5232d6d074df37acddc20f0bc233e42ed8eb00dfe2af5d3de3275","22df7d07369d206f8d5d02cf6d365e39dd9f3b5c454a8833d0017f4cf9c35177","241c3b02a8e7d5a2b9c99574c28200df2a0f8c8bd7ba4d262e6aa8ed1211ba1f","2f49bff45cc091a7bf52dcd061d24f9a7f2cf0ca9b3c12123bd3cf2fac56b481","327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917","625abbf876f256662f33a88c122bf787edf74b882c35adbd61562b5bd1b2ac27","654c11935448b3229434ec7d9d165a5f135ae4735d35700cffcb3b84f6a0fbc3","6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a","7f33c939f7aaf46945d58ed7fd0d1f5c7e3de1ff6a1a591ecc1992dab2a65078","921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae","94244ec2480addeaebb43aebbe48cee94f7f429231aa054f4c26f671653163b0","961346470d15d7795c5e35bc90c17d293fba7a8b811f8f5c26a3dc7c971cdc4e","a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526","b3045308a07e46c9f7dd98d352e964f242307ce30df8087dc751488118b5b959","ba1b89023581a0bc7a75f8ede9ec6115d5dda98c0145634f1b98978fbc79c956","e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346","f0127e786c9fb7bf2c8c999202d95c977af4c26cc27302a6ee352cfd62869e7b","fa74ac0e05b6209b7691511572386f97464ff5728732de99ddd6b5449ffae386","fd509df74a8d6a9e96762337efd46280ebf8d154c6c5dfbac7b3e8f7bb61f191")
| table _time host EventCode User Image CommandLine TargetFilename observed_sha256 Hashes ParentImage
```

### 8.2 SP23 — SafePay extension and ransom-note creation burst

**Origin:** Repository-authored from consistent impact artifacts.

**Telemetry:** Sysmon Event 11 or EDR file telemetry.

**Review / tuning:** Require a burst across several directories to exclude research and test files.

```spl
index=endpoint EventCode=11
(TargetFilename="*.safepay" OR TargetFilename IN ("*\\readme_safepay.txt","*\\readme_safepay_ascii.txt","*\\Decryption Instructions.txt"))
| bin _time span=5m
| eval directory=replace(TargetFilename,"\\\\[^\\\\]+$","")
| stats count as files dc(directory) as directories values(TargetFilename) as examples by _time host Image ProcessGuid Hashes
| where files>=10 OR (files>=2 AND directories>=2)
```

## 9. Multi-Stage Correlation

### 9.1 SP24 — Discovery, impairment and impact on one device

**Origin:** Repository-authored from the recurrent SafePay lifecycle.

**Telemetry:** Sysmon Event 1/11.

**Review / tuning:** Co-occurrence within one hour is a lead; confirm order, account and process continuity.

```spl
index=endpoint (EventCode=1 OR EventCode=11)
| eval stage=case(
  EventCode=1 AND (Image="*\\ShareFinder.exe" OR Image="*\\SharpShares.exe" OR CommandLine="*Invoke-ShareFinder*"),"Discovery",
  EventCode=1 AND (CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*delete shadows*" OR CommandLine="*shadowcopy delete*" OR CommandLine="*recoveryenabled no*"),"Impairment",
  EventCode=1 AND CommandLine="*-pass=*" AND (CommandLine="*-enc=*" OR CommandLine="*-enc *"),"Locker",
  EventCode=11 AND (TargetFilename="*.safepay" OR TargetFilename="*\\readme_safepay.txt"),"Impact",
  true(),"Other")
| where stage!="Other"
| bin _time span=1h
| stats dc(stage) as stage_count values(stage) as stages values(CommandLine) as commands values(TargetFilename) as files by _time host
| where stage_count>=3 AND mvfind(stages,"Impact")>=0
```

## 10. Campaign Artifact Hunts

### 10.1 SP25 — Published operator workstation names

**Origin:** Repository-authored from Huntress and DCSO case evidence.

**Telemetry:** Endpoint, identity and network logs with host fields.

**Review / tuning:** Names can collide; require stronger behavioral evidence.

```spl
(index=endpoint (host IN ("WIN-SBOE3CPNALE","WIN-3IUUOFVTQAR") OR CommandLine IN ("*WIN-SBOE3CPNALE*","*WIN-3IUUOFVTQAR*")))
OR (index=auth src_host IN ("WIN-SBOE3CPNALE","WIN-3IUUOFVTQAR"))
OR (index=network src_host IN ("WIN-SBOE3CPNALE","WIN-3IUUOFVTQAR"))
| table _time index host src src_host user Image CommandLine dest dest_port action
```

### 10.2 SP26 — Single-digit ProgramData batch or NCC temporary artifact

**Origin:** Repository-authored from NCC incident evidence.

**Telemetry:** Sysmon Event 11.

**Review / tuning:** Inspect creator, content and adjacent remote execution.

```spl
index=endpoint EventCode=11
| where match(TargetFilename,"(?i)^C:\\ProgramData\\[0-9]\.bat$") OR match(TargetFilename,"(?i)^C:\\Windows\\Temp\\RRZqKUbG\.tmp$")
| table _time host User TargetFilename Image CommandLine Hashes ProcessGuid
```

### 10.3 SP27 — QDoor component hashes and `soc.dll` registration

**Origin:** Repository-authored from NCC's QDoor analysis.

**Telemetry:** Sysmon Event 1/11.

**Review / tuning:** Filename matches need hash, hollowing or network corroboration.

```spl
index=endpoint (EventCode=1 OR EventCode=11)
(SHA256 IN ("921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae","6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a","e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346")
 OR Hashes IN ("*921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae*","*6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a*","*e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346*")
 OR TargetFilename="*\\soc.dll" OR (Image="*\\regsvr32.exe" CommandLine="*soc.dll*"))
| table _time host EventCode User Image CommandLine ParentImage TargetFilename SHA256 Hashes ProcessGuid
```

### 10.4 SP28 — SafePay discovery and script bundle

**Origin:** Repository-authored from Sygnia incident response.

**Telemetry:** Sysmon Event 1/11 or equivalent endpoint process/file events.

**Review / tuning:** The tools are dual-use. Prioritize multiple names on one host, uncommon paths and execution by a remote-access account.

```spl
index=endpoint (EventCode=1 OR EventCode=11)
| eval artifact=coalesce(Image,TargetFilename)
| where match(artifact,"(?i)(RouteCIDR\.py|p\.bat_[SW]\.bat|SWG\.ps1|check\.ps1|search\.ps1|sorted\.ps1|Snaffler\.exe|SharpShares\.exe|ShareFinder\.ps1|Advanced[_ ]IP[_ ]Scanner\.exe|netscan\.exe)$")
    OR match(CommandLine,"(?i)(RouteCIDR\.py|p\.bat_[SW]\.bat|SWG\.ps1|check\.ps1|search\.ps1|sorted\.ps1|Snaffler\.exe|SharpShares\.exe|ShareFinder\.ps1|Advanced[_ ]IP[_ ]Scanner\.exe|netscan\.exe)")
| bin _time span=1h
| stats dc(artifact) as artifact_count values(artifact) as artifacts values(CommandLine) as commands earliest(_time) as first latest(_time) as last by host
| where artifact_count>=2
```

### 10.5 SP29 — OneDrive staging to the published attacker tenant

**Origin:** Repository-authored from Sygnia incident response.

**Telemetry:** Endpoint file events plus proxy, DNS or network connection logs.

**Review / tuning:** Microsoft 365 is shared infrastructure. Require the exact tenant/path or correlate a newly observed tenant with multipart RAR creation and outbound volume.

```spl
(index=network (dest_host="*jjvq-sharepoint.com" OR dest_host="*jjvq-my-sharepoint.com" OR url="*jjvq-sharepoint.com*" OR url="*jjvq-my-sharepoint.com*"))
OR (index=endpoint EventCode=11 TargetFilename="*\OneDrive *jjvq\*")
| eval evidence=coalesce(url,dest_host,TargetFilename)
| table _time host user src dest dest_host url Image CommandLine TargetFilename evidence bytes_out
```

### 10.6 SP30 — Sygnia incident VPN and transfer IPs

**Origin:** Repository-authored from Sygnia's published IOC table.

**Telemetry:** VPN/authentication and endpoint/network connection logs.

**Review / tuning:** These are historical, case-scoped endpoints. Validate observation date, ASN and current ownership before blocking.

```spl
(index=auth src_ip IN ("185.243.96.9","23.234.70.67","68.235.46.80","155.1.191.82","208.131.130.45","208.131.130.65","23.234.70.46","23.234.68.67","23.234.90.68","192.166.225.69"))
OR (index=network (src_ip IN ("185.243.96.9","23.234.70.67","68.235.46.80","155.1.191.82","208.131.130.45","208.131.130.65","23.234.70.46","23.234.68.67","23.234.90.68","192.166.225.69") OR dest_ip IN ("185.243.96.9","23.234.70.67","68.235.46.80","155.1.191.82","208.131.130.45","208.131.130.65","23.234.70.46","23.234.68.67","23.234.90.68","192.166.225.69")))
| table _time index host user src_ip src_port dest_ip dest_port action bytes_in bytes_out process_name
```

### 10.7 SP31 — Veeam credential and virtualization focus

**Origin:** Repository-authored from Sygnia incident response.

**Telemetry:** Sysmon Event 1 or equivalent endpoint process events.

**Review / tuning:** Backup and virtualization administrators generate legitimate matches. Require an unusual account/source and surrounding discovery or archive activity.

```spl
index=endpoint EventCode=1
(Image IN ("*\powershell.exe","*\pwsh.exe","*\mstsc.exe","*\mmc.exe","*\python.exe","*\cmd.exe"))
(CommandLine="*Veeam*" OR CommandLine="*Get-VBR*" OR CommandLine="*Veeam.Backup*" OR CommandLine="*vCenter*" OR CommandLine="*virtmgmt.msc*" OR CommandLine="*Hyper-V*" OR CommandLine="*VMware.Vim*")
| table _time host User Image CommandLine ParentImage ParentCommandLine ProcessGuid Hashes
```
