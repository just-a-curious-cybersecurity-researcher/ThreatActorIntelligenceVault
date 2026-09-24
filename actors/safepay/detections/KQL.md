# SafePay — KQL Hunting Queries

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope and Requirements

Queries target Microsoft Defender XDR tables. Adjust retention, thresholds, approved RMM inventory and field normalization before production use. All SP queries are repository-authored from the behaviors and indicators documented in this dossier.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| SP01–SP06 | Authentication, credential access and discovery | Baseline help-desk, scanner and administrator behavior |
| SP07–SP12 | Persistence, RMM and QDoor/C2 | Validate signer, tenant, parent process and destination ownership |
| SP13–SP21 | Locker execution, evasion, collection and recovery inhibition | Correlate command line with outcome and maintenance windows |
| SP22–SP31 | Exact artifacts, impact, correlations and campaign pivots | Exact values are historical; sequence logic needs local thresholds |

## Interpretation Notes

A query result is an investigation lead. Exact hashes identify only the published sample. Shared tools such as ScreenConnect, WinRAR, FileZilla and `WerFault.exe` require surrounding account, process, signer, path and network evidence.

## 1. Credential Access

### 1.1 SP01 — VPN or remote-access password spray followed by success

**Origin:** Repository-authored from DCSO and NCC incident evidence.

**Telemetry:** Defender XDR IdentityLogonEvents.

**Review / tuning:** Normalize application names and exclude vulnerability scanners, health checks and known user mistakes.

```kusto
let failures = IdentityLogonEvents
| where Timestamp > ago(14d) and ActionType =~ "LogonFailed"
| where Application has_any ("VPN","RDP","Remote Desktop","Forti")
| summarize FailedUsers=dcount(AccountUpn), Users=make_set(AccountUpn,20), Failures=count(), FirstFail=min(Timestamp), LastFail=max(Timestamp)
  by IPAddress, DeviceName, bin(Timestamp,30m)
| where FailedUsers >= 5 or Failures >= 15;
let successes = IdentityLogonEvents
| where Timestamp > ago(14d) and ActionType =~ "LogonSuccess"
| where Application has_any ("VPN","RDP","Remote Desktop","Forti")
| project SuccessTime=Timestamp, IPAddress, DeviceName, AccountUpn, Application;
failures
| join kind=inner successes on IPAddress
| where SuccessTime between (FirstFail .. LastFail + 2h)
| project SuccessTime, IPAddress, DeviceName, AccountUpn, Application, Failures, FailedUsers, Users
```

### 1.2 SP02 — Mimikatz or RemoteRegDump-like activity

**Origin:** Repository-authored from Microsoft/Halcyon tooling and NCC incident evidence.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Security testing can match. Confirm file origin, signer, parent and credential-store access.

```kusto
union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where FileName =~ "mimikatz.exe" or ProcessCommandLine has_any ("sekurlsa::","lsadump::","privilege::debug","comsvcs.dll, MiniDump")
 | project Timestamp, DeviceName, AccountName, Evidence=strcat(FileName," ",ProcessCommandLine), SHA256, InitiatingProcessFileName),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where SHA1 =~ "07353237350c35d6dc2c8f143b649cd07c71f62b" or FileName =~ "RRZqKUbG.tmp"
 | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Evidence=strcat(FolderPath,"\\",FileName), SHA256, InitiatingProcessFileName)
```

### 1.3 SP03 — Administrative password or privileged-group changes near impact

**Origin:** Repository-authored from NCC's observed administrator-password changes.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Planned identity administration can match. Correlate with unusual source device and later recovery inhibition.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("net.exe","net1.exe","powershell.exe","pwsh.exe","dsmod.exe")
| where ProcessCommandLine has_any (" user ","Set-ADAccountPassword","localgroup administrators","group \"Domain Admins\"")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

## 2. Active Directory and Network Discovery

### 2.1 SP04 — ShareFinder, SharpShares or related share discovery

**Origin:** Repository-authored from Huntress and DCSO cases.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Approved red-team or inventory activity can match; validate hash and launching account.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("ShareFinder.exe","SharpShares.exe")
   or ProcessCommandLine has_any ("Invoke-ShareFinder","Find-InterestingDomainShare","SharpShares")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 2.2 SP05 — Native discovery burst

**Origin:** Repository-authored from SafePay incident-response command patterns.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Administrators frequently use individual commands; require a burst from an unusual parent or account.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("whoami.exe","ipconfig.exe","nltest.exe","net.exe","net1.exe","quser.exe","qwinsta.exe","tasklist.exe","wmic.exe")
| summarize Commands=dcount(FileName), Examples=make_set(ProcessCommandLine,20), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp,15m)
| where Commands >= 4
```

### 2.3 SP06 — SMB fan-out from one process

**Origin:** Repository-authored from SMB deployment and remote-share encryption evidence.

**Telemetry:** MDE DeviceNetworkEvents.

**Review / tuning:** Backup, software distribution and file servers can match; baseline process and source host.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemotePort == 445
| summarize Targets=dcount(RemoteIP), RemoteHosts=make_set(RemoteIP,40), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, bin(Timestamp,10m)
| where Targets >= 15
```

## 3. Persistence and Remote Administration

### 3.1 SP07 — ScreenConnect service creation or configuration

**Origin:** Repository-authored from NCC and Microsoft reporting.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Compare service path, signer and tenant with the approved ScreenConnect estate.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("sc.exe","powershell.exe","pwsh.exe","ScreenConnect.ClientService.exe")
| where ProcessCommandLine has_any ("ScreenConnect Client","ScreenConnect.ClientService","start= auto","New-Service")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 3.2 SP08 — New autorun value referencing an uncommon executable

**Origin:** Repository-authored from Microsoft-observed optional Run-key persistence.

**Telemetry:** MDE DeviceRegistryEvents.

**Review / tuning:** Software installation commonly creates Run values; verify signer, path and creation account.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has_any (@"\Software\Microsoft\Windows\CurrentVersion\Run", @"\Software\Microsoft\Windows\CurrentVersion\RunOnce")
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryValueData has_any (".exe",".dll","regsvr32","rundll32")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.3 SP09 — First-seen ScreenConnect or transfer utility

**Origin:** Repository-authored from SafePay RMM and transfer-tool evidence.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Exclude sanctioned deployment packages and managed endpoints.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("screenconnect","filezilla","fzsftp","rclone") or ProcessVersionInfoProductName has_any ("ScreenConnect","FileZilla","Rclone")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Commands=make_set(ProcessCommandLine,10), Hashes=make_set(SHA256,10)
  by DeviceId, DeviceName, AccountName, FileName, FolderPath
| where FirstSeen > ago(7d)
```

## 4. Tunneling and C2

### 4.1 SP10 — Published SafePay/QDoor C2 endpoints

**Origin:** Repository-authored from NCC, Microsoft and Halcyon indicators.

**Telemetry:** MDE DeviceNetworkEvents.

**Review / tuning:** Historical infrastructure can be reassigned. Validate destination ownership and time range.

```kusto
let SafePayIPs = dynamic(["88.119.167.239","45.91.201.247","77.37.49.40","80.78.28.63"]);
DeviceNetworkEvents
| where Timestamp > ago(90d) and RemoteIP in (SafePayIPs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessSHA256
```

### 4.2 SP11 — Imgur wallpaper resource retrieval

**Origin:** Repository-authored from Microsoft SafePay behavior.

**Telemetry:** MDE DeviceNetworkEvents.

**Review / tuning:** Imgur is legitimate shared infrastructure; require the exact path and surrounding impact activity.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has "i.imgur.com/zhCjntO.png" or (RemoteIP == "199.232.192.193" and InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

### 4.3 SP12 — QDoor-style `regsvr32` launch followed by `WerFault.exe`

**Origin:** Repository-authored from NCC reverse engineering.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Crash handling can start `WerFault.exe`; prioritize `regsvr32` ancestry, unsigned DLLs and adjacent network activity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("soc.dll","/s"))
   or (FileName =~ "WerFault.exe" and InitiatingProcessFileName =~ "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 5. Defense Evasion and Impairment

### 5.1 SP13 — SafePay locker command-line cluster

**Origin:** Repository-authored from Huntress and NCC binary/incident analysis.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** The combined switches are high-context; preserve the full command and parent process.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "-pass=" and ProcessCommandLine has_any ("-enc=","-enc ")
| where ProcessCommandLine has_any ("-path=","-network","-netdrive","-selfdelete","-uac")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 5.2 SP14 — CMSTPLUA auto-elevation sequence

**Origin:** Repository-authored from Huntress binary analysis.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Some legitimate elevation workflows involve `DllHost.exe`; correlate the CLSID, unusual parent and locker arguments.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
   or (FileName =~ "DllHost.exe" and InitiatingProcessCommandLine has_any ("-uac","-pass=","-enc="))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 5.3 SP15 — Defender impairment through command line or trusted UI flow

**Origin:** Repository-authored from Huntress and Microsoft observations.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Approved troubleshooting or security-product transitions can match; correlate Defender events 5001/5007.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe","SystemSettingsAdminFlows.exe","MpCmdRun.exe")
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring","Set-MpPreference","Add-MpPreference","WindowsDefender","VirusThreatProtection")
   or FileName =~ "SystemSettingsAdminFlows.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 5.4 SP16 — Burst of service or process termination

**Origin:** Repository-authored from SafePay locker service/process kill lists.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Patch, backup and database maintenance can stop services; require multiple targets and impact context.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sc.exe","net.exe","net1.exe","taskkill.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (" stop ","taskkill","Stop-Service","Stop-Process")
| summarize Stops=count(), Targets=make_set(ProcessCommandLine,25), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp,10m)
| where Stops >= 5
```

### 5.5 SP17 — Self-delete or delayed deletion of the executing payload

**Origin:** Repository-authored from the SafePay `-selfdelete` capability.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Installers legitimately remove temporary files; prioritize locker switches and unusual temp paths.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "-selfdelete"
   or (FileName in~ ("cmd.exe","powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("del /f /q","Remove-Item") and ProcessCommandLine has_any (".exe",".dll"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 6. Collection and Exfiltration

### 6.1 SP18 — WinRAR archiving of remote-user or share data

**Origin:** Repository-authored from Huntress and DCSO incident evidence.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Authorized archival jobs can match. Prioritize UNC paths, user-profile data, split archives and unusual accounts.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("rar.exe","winrar.exe")
| where ProcessCommandLine has_any (@"\\",@"\Users\",@"\Shares\"," -v"," a ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 6.2 SP19 — Transfer or compression utilities near a first-seen installation

**Origin:** Repository-authored from Microsoft, Huntress and FortiGuard reporting.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** FileZilla, Rclone and 7-Zip are legitimate. Validate source package, arguments, destination and data volume.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("filezilla.exe","fzsftp.exe","rclone.exe","7z.exe","7za.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

## 7. Recovery Inhibition

### 7.1 SP20 — Shadow-copy deletion

**Origin:** Repository-authored from Huntress, DCSO, NCC and Microsoft behavior.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Backup maintenance can remove snapshots; correlate with account, parent and encryption activity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
   or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
   or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Win32_ShadowCopy","Get-WmiObject Win32_Shadowcopy"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 7.2 SP21 — Boot recovery disabled

**Origin:** Repository-authored from published SafePay recovery commands.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Rare outside recovery or imaging workflows; validate change outcome and subsequent file impact.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName =~ "bcdedit.exe"
| where ProcessCommandLine has_any ("recoveryenabled no","bootstatuspolicy ignoreallfailures")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 8. Deployment and Impact

### 8.1 SP22 — Exact published SafePay-associated and QDoor hashes

**Origin:** Repository-authored from the local hash-provenance register.

**Telemetry:** MDE DeviceFileEvents and DeviceProcessEvents.

**Review / tuning:** Exact matches are high-priority but identify only the documented artifacts.

```kusto
let Hashes = dynamic(["0f23a313f79d54ae2102f193d3de1a6a98791c27921f28a4fab1092bcb43e5ee","12139246b8c5232d6d074df37acddc20f0bc233e42ed8eb00dfe2af5d3de3275","22df7d07369d206f8d5d02cf6d365e39dd9f3b5c454a8833d0017f4cf9c35177","241c3b02a8e7d5a2b9c99574c28200df2a0f8c8bd7ba4d262e6aa8ed1211ba1f","2f49bff45cc091a7bf52dcd061d24f9a7f2cf0ca9b3c12123bd3cf2fac56b481","327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917","625abbf876f256662f33a88c122bf787edf74b882c35adbd61562b5bd1b2ac27","654c11935448b3229434ec7d9d165a5f135ae4735d35700cffcb3b84f6a0fbc3","6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a","7f33c939f7aaf46945d58ed7fd0d1f5c7e3de1ff6a1a591ecc1992dab2a65078","921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae","94244ec2480addeaebb43aebbe48cee94f7f429231aa054f4c26f671653163b0","961346470d15d7795c5e35bc90c17d293fba7a8b811f8f5c26a3dc7c971cdc4e","a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526","b3045308a07e46c9f7dd98d352e964f242307ce30df8087dc751488118b5b959","ba1b89023581a0bc7a75f8ede9ec6115d5dda98c0145634f1b98978fbc79c956","e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346","f0127e786c9fb7bf2c8c999202d95c977af4c26cc27302a6ee352cfd62869e7b","fa74ac0e05b6209b7691511572386f97464ff5728732de99ddd6b5449ffae386","fd509df74a8d6a9e96762337efd46280ebf8d154c6c5dfbac7b3e8f7bb61f191"]);
union isfuzzy=true DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(180d) and SHA256 in (Hashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 8.2 SP23 — SafePay extension and ransom-note creation burst

**Origin:** Repository-authored from consistent impact artifacts.

**Telemetry:** MDE DeviceFileEvents.

**Review / tuning:** Test files and research corpora can match. Require a burst across multiple directories or shares.

```kusto
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName endswith ".safepay" or FileName in~ ("readme_safepay.txt","readme_safepay_ascii.txt","Decryption Instructions.txt")
| summarize Files=count(), Directories=dcount(FolderPath), Examples=make_set(strcat(FolderPath,"\\",FileName),20), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, bin(Timestamp,5m)
| where Files >= 10 or (Files >= 2 and Directories >= 2)
```

## 9. Multi-Stage Correlation

### 9.1 SP24 — Discovery, impairment and impact on one device

**Origin:** Repository-authored from the recurrent SafePay lifecycle.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** The query shows stage co-occurrence within one hour; inspect actual ordering and account continuity.

```kusto
let P = DeviceProcessEvents
| where Timestamp > ago(14d)
| extend Stage=case(
    FileName in~ ("ShareFinder.exe","SharpShares.exe") or ProcessCommandLine has_any ("Invoke-ShareFinder","SharpShares"), "Discovery",
    ProcessCommandLine has_any ("DisableRealtimeMonitoring","delete shadows","shadowcopy delete","recoveryenabled no"), "Impairment",
    ProcessCommandLine has "-pass=" and ProcessCommandLine has_any ("-enc=","-enc "), "Locker",
    "Other")
| where Stage != "Other"
| project Timestamp, DeviceId, DeviceName, Stage, Evidence=ProcessCommandLine;
let F = DeviceFileEvents
| where Timestamp > ago(14d) and (FileName endswith ".safepay" or FileName =~ "readme_safepay.txt")
| project Timestamp, DeviceId, DeviceName, Stage="Impact", Evidence=strcat(FolderPath,"\\",FileName);
union P,F
| summarize Stages=make_set(Stage), Evidence=make_set(Evidence,30), First=min(Timestamp), Last=max(Timestamp) by DeviceId, DeviceName, bin(Timestamp,1h)
| where array_length(Stages) >= 3 and set_has_element(Stages,"Impact")
```

## 10. Campaign Artifact Hunts

### 10.1 SP25 — Published operator workstation names

**Origin:** Repository-authored from Huntress and DCSO case evidence.

**Telemetry:** MDE DeviceProcessEvents, DeviceNetworkEvents and IdentityLogonEvents.

**Review / tuning:** Hostnames are reusable and can collide; treat them as campaign pivots requiring stronger evidence.

```kusto
let Names = dynamic(["WIN-SBOE3CPNALE","WIN-3IUUOFVTQAR"]);
union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(180d) | where DeviceName has_any (Names) or ProcessCommandLine has_any (Names) | project Timestamp, DeviceName, Evidence=ProcessCommandLine, Account=AccountName),
(DeviceNetworkEvents | where Timestamp > ago(180d) | where DeviceName has_any (Names) or RemoteUrl has_any (Names) | project Timestamp, DeviceName, Evidence=strcat(RemoteIP,":",RemotePort), Account=InitiatingProcessAccountName),
(IdentityLogonEvents | where Timestamp > ago(180d) | where DeviceName has_any (Names) | project Timestamp, DeviceName, Evidence=IPAddress, Account=AccountUpn)
```

### 10.2 SP26 — Single-digit ProgramData batch or NCC temporary artifact

**Origin:** Repository-authored from NCC incident evidence.

**Telemetry:** MDE DeviceFileEvents.

**Review / tuning:** Single-digit batch files can be legitimate but are uncommon; inspect creator, content and adjacent remote execution.

```kusto
DeviceFileEvents
| where Timestamp > ago(90d)
| where (FolderPath =~ @"C:\ProgramData" and FileName matches regex @"^[0-9]\.bat$")
   or (FolderPath =~ @"C:\Windows\Temp" and FileName =~ "RRZqKUbG.tmp")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA1, SHA256, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 10.3 SP27 — QDoor component hashes and `soc.dll` registration

**Origin:** Repository-authored from NCC's QDoor analysis.

**Telemetry:** MDE DeviceFileEvents and DeviceProcessEvents.

**Review / tuning:** The filename can collide; exact hashes or process-hollowing/network behavior raise confidence.

```kusto
let QDoor = dynamic(["921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae","6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a","e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346"]);
union isfuzzy=true DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(180d)
| where SHA256 in (QDoor) or (FileName =~ "regsvr32.exe" and ProcessCommandLine has "soc.dll") or FileName =~ "soc.dll"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 10.4 SP28 — SafePay discovery and script bundle

**Origin:** Repository-authored from Sygnia incident response.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** The tools are dual-use; prioritize multiple names on one host, uncommon paths and a remote-access account.

```kusto
let Names = dynamic(["RouteCIDR.py","p.bat_S.bat","p.bat_W.bat","SWG.ps1","check.ps1","search.ps1","sorted.ps1","Snaffler.exe","SharpShares.exe","ShareFinder.ps1","Advanced_IP_Scanner.exe","netscan.exe"]);
union isfuzzy=true DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(90d)
| where FileName in~ (Names) or InitiatingProcessCommandLine has_any (Names)
| summarize Artifacts=make_set(FileName,30), Commands=make_set(InitiatingProcessCommandLine,20), First=min(Timestamp), Last=max(Timestamp) by DeviceName
| where array_length(Artifacts) >= 2
```

### 10.5 SP29 — OneDrive staging to the published attacker tenant

**Origin:** Repository-authored from Sygnia incident response.

**Telemetry:** MDE DeviceNetworkEvents and DeviceFileEvents.

**Review / tuning:** Microsoft 365 is legitimate shared infrastructure. Require the exact tenant/path or correlate new tenant sign-in with large RAR creation and outbound volume.

```kusto
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(180d)
 | where RemoteUrl has_any ("jjvq-sharepoint.com","jjvq-my-sharepoint.com")
 | project Timestamp, DeviceName, Evidence=RemoteUrl, Account=InitiatingProcessAccountName, Process=InitiatingProcessFileName),
(DeviceFileEvents
 | where Timestamp > ago(180d)
 | where FolderPath has "OneDrive" and FolderPath has "jjvq"
 | project Timestamp, DeviceName, Evidence=strcat(FolderPath,"\\",FileName), Account=InitiatingProcessAccountName, Process=InitiatingProcessFileName)
```

### 10.6 SP30 — Sygnia incident VPN and transfer IPs

**Origin:** Repository-authored from Sygnia's published IOC table.

**Telemetry:** IdentityLogonEvents and DeviceNetworkEvents.

**Review / tuning:** These are historical, case-scoped endpoints. Validate observation date, ASN and current ownership before blocking.

```kusto
let IPs = dynamic(["185.243.96.9","23.234.70.67","68.235.46.80","155.1.191.82","208.131.130.45","208.131.130.65","23.234.70.46","23.234.68.67","23.234.90.68","192.166.225.69"]);
union isfuzzy=true
(IdentityLogonEvents | where Timestamp > ago(180d) and IPAddress in (IPs) | project Timestamp, DeviceName, Account=AccountUpn, Evidence=IPAddress, ActionType, Process="identity"),
(DeviceNetworkEvents | where Timestamp > ago(180d) and RemoteIP in (IPs) | project Timestamp, DeviceName, Account=InitiatingProcessAccountName, Evidence=strcat(RemoteIP,":",RemotePort), ActionType, Process=InitiatingProcessFileName)
```

### 10.7 SP31 — Veeam credential and virtualization focus

**Origin:** Repository-authored from Sygnia incident response.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Backup and virtualization administrators generate legitimate matches. Require an unusual account/source and surrounding discovery or archive activity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(90d)
| where ProcessCommandLine has_any ("Veeam","Get-VBR","Veeam.Backup","vCenter","virtmgmt.msc","Hyper-V","VMware.Vim")
| where FileName in~ ("powershell.exe","pwsh.exe","mstsc.exe","mmc.exe","python.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```
