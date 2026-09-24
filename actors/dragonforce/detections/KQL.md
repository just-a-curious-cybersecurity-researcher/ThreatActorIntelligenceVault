# DragonForce — KQL Hunting Queries

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope and Requirements

Queries target Microsoft Defender XDR tables unless they explicitly use `Syslog` or `CommonSecurityLog` in Sentinel/Log Analytics. Adjust retention, schemas and approved-tool lists before production use. All queries are repository-authored from published DragonForce/affiliate evidence.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| DF01–DF05 | Credentials and discovery | Distinguish authorized troubleshooting and scanners |
| DF06–DF11 | RMM, persistence and C2 | Validate approved tenant, signer, user and destination |
| DF12–DF17 | Evasion, collection and recovery | Correlate file creation with load/execution and outcome |
| DF18–DF21 | ESXi and locker impact | Separate maintenance, exact samples and customized builds |
| DF22–DF24 | Correlation and campaign pivots | Incident-specific values prioritize triage |

## Interpretation Notes

A result is a hunting lead. Hash matches identify exact artifacts; behavior queries require process ancestry, account context and adjacent events. Campaign values do not establish service-wide infrastructure.

## 1. Credential Access

### 1.1 DF01 — Credential-dumping and stored-password utilities

**Origin:** Repository-authored from Trend/Symantec tooling.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Red-team and support use can match. Verify signer, path and account.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("mimikatz.exe","lazagne.exe","WebBrowserPassView.exe","PasswordFox.exe","mspass.exe")
   or ProcessCommandLine has_any ("sekurlsa::logonpasswords","lsadump::sam","LaZagne all")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 1.2 DF02 — Registry hive export or save

**Origin:** Repository-authored from reported hive dumping.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Administrators and backup products can export hives. Inspect destination and subsequent archive/transfer.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("reg.exe","regedit.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(save|export).*(HKLM\\)?(SAM|SECURITY|SYSTEM)\b"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

## 2. Active Directory and Network Discovery

### 2.1 DF03 — AdFind, ADExplorer or NetScan execution

**Origin:** Repository-authored from Trend and Symantec cases.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Approved directory and network administration can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("adfind.exe","ADExplorer.exe","netscan.exe","netscanold.exe","advanced_ip_scanner.exe")
   or ProcessVersionInfoProductName has_any ("AdFind","Active Directory Explorer","Advanced IP Scanner")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 2.2 DF04 — Native discovery burst

**Origin:** Repository-authored from Huntress case commands.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Interactive administration can match; investigate unusual parents/RMM sessions.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("whoami.exe","qwinsta.exe","wmic.exe","nltest.exe","net.exe","net1.exe")
| summarize Commands=dcount(FileName), Examples=make_set(ProcessCommandLine,20), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp,15m)
| where Commands >= 3
```

### 2.3 DF05 — Process-attributed SMB fan-out

**Origin:** Repository-authored from Conti-derived locker ARP/TCP445/share logic.

**Telemetry:** MDE DeviceNetworkEvents.

**Review / tuning:** Backup, inventory and file-management servers can match. Baseline known software.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemotePort == 445
| summarize Targets=dcount(RemoteIP), IPs=make_set(RemoteIP,30), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, bin(Timestamp,10m)
| where Targets >= 20
```

## 3. Persistence and Remote Administration

### 3.1 DF06 — New or first-seen RMM execution

**Origin:** Repository-authored from SimpleHelp, ScreenConnect, Zoho, Atera, NetBird and AnyDesk reporting.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Compare with approved RMM inventory and tenant IDs.

```kusto
let RMM = dynamic(["simplehelp","screenconnect","connectwisecontrol","zohoassist","anydesk","atera","netbird"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName has_any (RMM) or ProcessCommandLine has_any (RMM) or ProcessVersionInfoProductName has_any (RMM)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Commands=make_set(ProcessCommandLine,10), Hashes=make_set(SHA256,10)
  by DeviceId, DeviceName, FileName, FolderPath, AccountName
| where FirstSeen > ago(7d)
```

### 3.2 DF07 — Case-linked account creation or privileged group change

**Origin:** Repository-authored from Huntress/Symantec account artifacts.

**Telemetry:** MDE DeviceProcessEvents and DeviceEvents.

**Review / tuning:** Names are case-specific; also inspect any new account near RMM installation.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("net.exe","net1.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("ctxsvc","CtxAppVCOMService"," user test ","localgroup administrators")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 3.3 DF08 — SYSTEM scheduled task launching an uncommon executable

**Origin:** Repository-authored from Conti-derived locker task behavior.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Software deployment creates SYSTEM tasks. Correlate with first-seen binary and file-impact events.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has_any ("/ru SYSTEM","/ru \"SYSTEM\"")
| where ProcessCommandLine has_any (".exe",".dll")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 4. Tunneling and C2

### 4.1 DF09 — Tunneling and proxy utilities

**Origin:** Repository-authored from Octo Tempest and DragonForce operations.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Approved development tunnels can match. Validate account and destination.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("ngrok.exe","chisel.exe","systembc.exe")
   or ProcessCommandLine has_any ("tcp://","socks5","client --url","ngrok tcp")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 4.2 DF10 — Published campaign domains and IPs

**Origin:** Exact Huntress/Symantec campaign indicators.

**Telemetry:** MDE DeviceNetworkEvents.

**Review / tuning:** Historical/compromised infrastructure; match supports case scoping, not current actor control.

```kusto
let Domains = dynamic(["projetosmecanicos.com.br","socialbizsolutions.com","professionalhomebasedbusiness.com","safefire.jo","glanz-gmbh.de","turnkeyaiagents.com","comunidadesparentais.com.br","mysimerp.net","relay.dltsolutions.top","relay.eurofin.digital","vtps.us","opa.tlsd.shop"]);
let IPs = dynamic(["192.36.27.51","62.164.177.25"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl in~ (Domains) or RemoteIP in (IPs)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

### 4.3 DF11 — TURN/Teams relay access by a non-Teams process

**Origin:** Repository-authored from Backdoor.Turn behavior.

**Telemetry:** MDE DeviceNetworkEvents with hostname visibility.

**Review / tuning:** Browsers and conferencing software can legitimately use TURN. Inspect unsigned/unfamiliar initiator and QUIC adjacency.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort in (3478, 443)
| where RemoteUrl has_any ("turn","skype","teams.microsoft")
| where InitiatingProcessFileName !in~ ("ms-teams.exe","teams.exe","skype.exe","chrome.exe","msedge.exe","firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteUrl, RemoteIP, RemotePort
```

## 5. Defense Evasion and Impairment

### 5.1 DF12 — Published vulnerable-driver filenames

**Origin:** S2W and Symantec driver reporting.

**Telemetry:** MDE DeviceFileEvents plus Sentinel `WindowsEvent` for Sysmon Event 6.

**Review / tuning:** Creation is not loading. Correlate driver/service telemetry and process termination.

```kusto
let Names = dynamic(["truesight.sys","rentdrv2.sys","HWAuidoOs2Ec.sys","wsftprm.sys","GameDriverx64.sys","K7RKScan.sys"]);
union isfuzzy=true
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FileName in~ (Names)
 | project Time=Timestamp, Device=DeviceName, Event="file", Driver=strcat(FolderPath,"\\",FileName), SHA256, Initiator=InitiatingProcessFileName),
(WindowsEvent
 | where TimeGenerated > ago(30d) and EventID == 6
 | extend Driver=tostring(EventData.ImageLoaded), SHA256=tostring(EventData.Hashes)
 | where Driver has_any (Names)
 | project Time=TimeGenerated, Device=Computer, Event="load", Driver, SHA256, Initiator=tostring(EventData.Image))
| order by Time desc
```

### 5.2 DF13 — Security or database process termination

**Origin:** Repository-authored from locker process-stop behavior.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Maintenance scripts can match. Inspect parent, driver load and subsequent encryption.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("taskkill.exe","powershell.exe","pwsh.exe","sc.exe","net.exe","net1.exe")
| where ProcessCommandLine has_any ("MsMpEng","sqlservr","oracle","veeam","backup","Sophos","CrowdStrike","Sentinel")
| where ProcessCommandLine has_any ("/f","Stop-Process"," stop ","taskkill")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 5.3 DF14 — Blank-password policy or firewall weakening

**Origin:** Repository-authored from Symantec case changes.

**Telemetry:** MDE DeviceRegistryEvents and DeviceProcessEvents.

**Review / tuning:** Troubleshooting can match; require unauthorized change and related remote access.

```kusto
union
(DeviceRegistryEvents
 | where Timestamp > ago(14d)
 | where RegistryKey has "Lsa" and RegistryValueName =~ "LimitBlankPasswordUse" and RegistryValueData == "0"
 | project Timestamp, DeviceName, Evidence=strcat(RegistryKey,"\\",RegistryValueName,"=",RegistryValueData), Initiator=InitiatingProcessFileName),
(DeviceProcessEvents
 | where Timestamp > ago(14d)
 | where FileName in~ ("netsh.exe","powershell.exe","pwsh.exe")
 | where ProcessCommandLine has_all ("firewall","allow")
 | project Timestamp, DeviceName, Evidence=ProcessCommandLine, Initiator=InitiatingProcessFileName)
```

### 5.4 DF15 — Side-loaded `vboxrt.dll` or DbgView-adjacent DLL

**Origin:** Repository-authored from Symantec Hackledorb case.

**Telemetry:** MDE DeviceImageLoadEvents.

**Review / tuning:** Validate DLL hash/signer and parent installation path; legitimate VirtualBox can load its own DLL.

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "vboxrt.dll" or InitiatingProcessFileName has_any ("vbox","dbgview")
| where FolderPath !startswith @"C:\Program Files\Oracle\VirtualBox"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, SHA256
```

## 6. Collection and Exfiltration

### 6.1 DF16 — Archive or MEGA/FTP transfer sequence

**Origin:** Repository-authored from published collection channels.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Backup and approved transfer can match. Confirm destination and data volume.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("7z.exe","7za.exe","winrar.exe","megasync.exe","mega-cmd.exe","winscp.exe","ftp.exe","sftp.exe")
| summarize Tools=make_set(FileName,20), Commands=make_set(ProcessCommandLine,30), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, AccountName, bin(Timestamp,2h)
| where array_length(Tools) >= 2 or tostring(Tools) has_any ("megasync.exe","mega-cmd.exe","winscp.exe","ftp.exe","sftp.exe")
```

## 7. Recovery Inhibition

### 7.1 DF17 — Shadow-copy, backup and boot-recovery changes

**Origin:** Repository-authored from both Windows locker lineages.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Legitimate recovery administration can match; inspect parent and outcome.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
   or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
   or (FileName =~ "wbadmin.exe" and ProcessCommandLine has_any ("delete catalog","delete systemstatebackup"))
   or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled","bootstatuspolicy","safeboot"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 8. Deployment and Impact

### 8.1 DF18 — ESXi VM inventory and power-off sequence

**Origin:** Repository-authored from Linux/ESXi binary analysis.

**Telemetry:** Sentinel/Log Analytics Syslog forwarded from ESXi.

**Review / tuning:** Planned maintenance matches. Correlate initiator, change window and datastore modifications.

```kusto
Syslog
| where TimeGenerated > ago(14d)
| where SyslogMessage contains "vim-cmd"
| where SyslogMessage has_any ("vmsvc/getallvms","vmsvc/power.off")
| summarize Commands=make_set(SyslogMessage,50), First=min(TimeGenerated), Last=max(TimeGenerated) by Computer, HostName, bin(TimeGenerated,30m)
| where tostring(Commands) has "getallvms" and tostring(Commands) has "power.off"
```

### 8.2 DF19 — LockBit-derived DragonForce argument combinations

**Origin:** Repository-authored from Trend reverse engineering.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Leaked-builder derivatives and research execution can match; add note/hash/file impact.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any (" -safe"," -wall"," -gspd"," -psex"," -gdel"," -del")
| where FileName !in~ ("cmd.exe","powershell.exe","pwsh.exe")
| summarize Switches=make_set(ProcessCommandLine,20), First=min(Timestamp), Last=max(Timestamp)
  by DeviceId, DeviceName, AccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

### 8.3 DF20 — Published DragonForce encryptor SHA-256 set

**Origin:** Exact public sample hashes.

**Telemetry:** MDE DeviceProcessEvents.

**Review / tuning:** Exact artifacts only; SHA256 can be absent in telemetry.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 in~ ("1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b","451a42db9c514514ab71218033967554507b59a60ee1fc3d88cbeb39eec99f20","410db536a57c511b0ccac2639e0eb3320f303fc5c90242379ab43364c51ef321","c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d","e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22","df903c620508011ca8eb2aaaf9712a526b31a12c800b856cd524ebb3fde854b2","55befb5de5d9bc45978efd1a960ae21ed81e4be9c6521aaeebf8d5884444e3c9","572d88c419c6ae75aeb784ceab327d040cb589903d6285bbffa77338111af14b")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
```

### 8.4 DF21 — Note or encrypted-extension burst

**Origin:** Repository-authored from documented artifacts.

**Telemetry:** MDE DeviceFileEvents.

**Review / tuning:** Research collections and legitimate `.locked` files can match; require volume and initiator context.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("readme.txt","readme.xt") or FileName endswith ".README.txt"
   or FileName endswith ".dragonforce_encrypted" or FileName endswith ".RNP" or FileName endswith ".RNP_esxi" or FileName endswith ".locked"
| summarize Files=dcount(strcat(FolderPath,"\\",FileName)), Examples=make_set(FileName,20)
  by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, bin(Timestamp,5m)
| where Files >= 10 or tostring(Examples) has_any ("readme.xt",".README.txt")
```

## 9. Multi-Stage Correlation

### 9.1 DF22 — New RMM followed by recovery inhibition or note creation

**Origin:** Repository-authored lifecycle correlation.

**Telemetry:** MDE DeviceProcessEvents and DeviceFileEvents.

**Review / tuning:** Same-host timing does not prove causality; inspect user, process tree and deployment authorization.

```kusto
let RMM = DeviceProcessEvents
| where Timestamp > ago(14d) and (FileName has_any ("screenconnect","anydesk","atera","netbird","simplehelp") or ProcessCommandLine has_any ("zohoassist","connectwisecontrol"))
| project DeviceId, DeviceName, RMMTime=Timestamp, RMMFile=FileName, RMMCommand=ProcessCommandLine;
let Impact = union
(DeviceProcessEvents
 | where Timestamp > ago(14d) and FileName in~ ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe")
 | where ProcessCommandLine has_any ("delete shadows","shadowcopy delete","recoveryenabled","delete catalog")
 | project DeviceId, ImpactTime=Timestamp, ImpactEvidence=ProcessCommandLine),
(DeviceFileEvents
 | where Timestamp > ago(14d) and (FileName =~ "readme.xt" or FileName endswith ".README.txt" or FileName endswith ".dragonforce_encrypted")
 | project DeviceId, ImpactTime=Timestamp, ImpactEvidence=strcat(FolderPath,"\\",FileName));
RMM
| join kind=inner Impact on DeviceId
| where ImpactTime between (RMMTime .. RMMTime + 72h)
| project DeviceName, RMMTime, RMMFile, RMMCommand, ImpactTime, ImpactEvidence
```

## 10. Campaign Artifact Hunts

### 10.1 DF23 — Huntress Citrix-linked filenames, accounts and hostnames

**Origin:** Exact case pivots from Huntress.

**Telemetry:** MDE process and device-name data.

**Review / tuning:** Generic names can collide. Require multiple pivots or exact hash.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName in~ ("WIN-4E0AP4JTJR9","WIN-VI960VQI4I6")
   or AccountName in~ ("ctxsvc","CtxAppVCOMService","test")
   or FileName in~ ("eng.exe","legal.exe","exsym.exe","as.exe","exp6.exe","1.exe","us.msi","SC.msi","za.msi")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 10.2 DF24 — Citrix malformed authentication flood

**Origin:** Repository-authored from Huntress CitrixBleed 2 evidence.

**Telemetry:** Sentinel `CommonSecurityLog` or normalized Citrix ADC events.

**Review / tuning:** Field mapping varies. Threshold reflects a broad hunt, not the exact 5,937-event case requirement.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor has "Citrix" or DeviceProduct has_any ("NetScaler","ADC","Gateway")
| where Activity has "AAA_LOGIN_FAILED" or Message has "AAA_LOGIN_FAILED"
| summarize Failures=count(), Samples=make_set(Message,10), First=min(TimeGenerated), Last=max(TimeGenerated)
  by DeviceAddress, SourceIP, bin(TimeGenerated,1h)
| where Failures >= 100
```

### 10.3 DF25 — Exact Backdoor.Turn campaign tools and drivers

**Origin:** Exact hashes published by Symantec for the Hackledorb-associated DragonForce case.

**Telemetry:** MDE DeviceFileEvents and DeviceProcessEvents.

**Review / tuning:** These values confirm artifacts from one campaign; classify the role from the IOC register and do not infer service-wide use.

```kusto
let CampaignSHA256 = dynamic([
"82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b","821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6",
"048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c","ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0",
"f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b","d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e",
"142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219","8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3",
"d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e","aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5",
"9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759","cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a",
"b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383","b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877",
"8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2","65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951",
"252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab","8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531",
"087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2","6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4",
"6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e"]);
union isfuzzy=true DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(90d) and SHA256 in~ (CampaignSHA256)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```
