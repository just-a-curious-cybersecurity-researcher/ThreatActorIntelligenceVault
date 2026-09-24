# DragonForce — Splunk Hunting Searches

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope and Requirements

Searches assume Sysmon/Windows event data in `index=endpoint`, network data in `index=network`, VMware logs in `index=vmware` and Citrix ADC logs in `index=citrix`. Replace indexes and field aliases with local CIM mappings.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| DF01–DF05 | Credentials and discovery | Distinguish authorized troubleshooting and scanners |
| DF06–DF11 | RMM, persistence and C2 | Validate approved tenant, signer, user and destination |
| DF12–DF17 | Evasion, collection and recovery | Correlate file creation with load/execution and outcome |
| DF18–DF21 | ESXi and locker impact | Separate maintenance, exact samples and customized builds |
| DF22–DF24 | Correlation and campaign pivots | Incident-specific values prioritize triage |

## Interpretation Notes

The searches are repository-authored. A result is a lead; exact hashes identify only published artifacts. Preserve process GUID, parent, account, signer and host/time context.

## 1. Credential Access

### 1.1 DF01 — Credential-dumping and stored-password utilities

**Origin:** Repository-authored from Trend/Symantec tooling.

**Telemetry:** Sysmon Event 1 or CIM Endpoint.Processes.

**Review / tuning:** Validate red-team/support use and binary identity.

```spl
index=endpoint EventCode=1
(Image IN ("*\\mimikatz.exe","*\\lazagne.exe","*\\WebBrowserPassView.exe","*\\PasswordFox.exe","*\\mspass.exe")
 OR CommandLine IN ("*sekurlsa::logonpasswords*","*lsadump::sam*","*LaZagne all*"))
| table _time host User Image CommandLine ParentImage Hashes
```

### 1.2 DF02 — Registry hive export or save

**Origin:** Repository-authored from reported hive dumping.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Backup/administration can match; inspect output and subsequent transfer.

```spl
index=endpoint EventCode=1 Image IN ("*\\reg.exe","*\\regedit.exe","*\\powershell.exe","*\\pwsh.exe")
| regex CommandLine="(?i)(save|export).*(HKLM\\\\)?(SAM|SECURITY|SYSTEM)\\b"
| table _time host User Image CommandLine ParentImage Hashes
```

## 2. Active Directory and Network Discovery

### 2.1 DF03 — AdFind, ADExplorer or NetScan execution

**Origin:** Repository-authored from Trend/Symantec cases.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Approved directory/network tools can match.

```spl
index=endpoint EventCode=1
Image IN ("*\\adfind.exe","*\\ADExplorer.exe","*\\netscan.exe","*\\netscanold.exe","*\\advanced_ip_scanner.exe")
| table _time host User Image CommandLine ParentImage Hashes
```

### 2.2 DF04 — Native discovery burst

**Origin:** Repository-authored from Huntress commands.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Investigate unusual parent/RMM and non-admin accounts.

```spl
index=endpoint EventCode=1 Image IN ("*\\whoami.exe","*\\qwinsta.exe","*\\wmic.exe","*\\nltest.exe","*\\net.exe","*\\net1.exe")
| bin _time span=15m
| stats dc(Image) as command_count values(CommandLine) as commands by _time host User ParentImage
| where command_count>=3
```

### 2.3 DF05 — Process-attributed SMB fan-out

**Origin:** Repository-authored from locker TCP/445/share discovery.

**Telemetry:** Sysmon Event 3.

**Review / tuning:** Baseline backup, inventory and file servers.

```spl
index=endpoint EventCode=3 DestinationPort=445
| bin _time span=10m
| stats dc(DestinationIp) as targets values(DestinationIp) as ips by _time host Image ProcessGuid
| where targets>=20
```

## 3. Persistence and Remote Administration

### 3.1 DF06 — RMM execution

**Origin:** Repository-authored from published RMM use.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Compare signer, tenant and path with approved inventory.

```spl
index=endpoint EventCode=1
(Image IN ("*simplehelp*","*screenconnect*","*connectwisecontrol*","*zohoassist*","*anydesk*","*atera*","*netbird*")
 OR CommandLine IN ("*simplehelp*","*screenconnect*","*connectwisecontrol*","*zohoassist*","*anydesk*","*atera*","*netbird*"))
| stats min(_time) as first max(_time) as last values(CommandLine) as commands values(Hashes) as hashes by host User Image
```

### 3.2 DF07 — Case-linked account creation or privileged group change

**Origin:** Repository-authored from Huntress/Symantec artifacts.

**Telemetry:** Sysmon Event 1 and Security 4720/4732.

**Review / tuning:** Generic `test` name can collide; require additional evidence.

```spl
(index=endpoint EventCode=1 Image IN ("*\\net.exe","*\\net1.exe","*\\powershell.exe","*\\pwsh.exe")
 CommandLine IN ("*ctxsvc*","*CtxAppVCOMService*","* user test *","*localgroup administrators*"))
OR (index=wineventlog EventCode IN (4720,4732) (TargetUserName IN ("ctxsvc","CtxAppVCOMService","test") OR MemberName IN ("*ctxsvc*","*CtxAppVCOMService*","*\\test")))
| table _time host EventCode SubjectUserName TargetUserName MemberName Image CommandLine
```

### 3.3 DF08 — SYSTEM scheduled task launching an executable

**Origin:** Repository-authored from Conti-derived locker.

**Telemetry:** Sysmon Event 1 or Security 4698.

**Review / tuning:** Software deployment can match; correlate first-seen executable and impact.

```spl
index=endpoint EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*"
(CommandLine="*/ru SYSTEM*" OR CommandLine="*/ru \"SYSTEM\"*") CommandLine="*.exe*"
| table _time host User Image CommandLine ParentImage Hashes
```

## 4. Tunneling and C2

### 4.1 DF09 — Tunneling and proxy utilities

**Origin:** Repository-authored from Octo Tempest/DragonForce reporting.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Approved developer tunnels can match.

```spl
index=endpoint EventCode=1
(Image IN ("*\\ngrok.exe","*\\chisel.exe","*\\systembc.exe")
 OR CommandLine IN ("*tcp://*","*socks5*","*client --url*","*ngrok tcp*"))
| table _time host User Image CommandLine ParentImage Hashes
```

### 4.2 DF10 — Published campaign domains and IPs

**Origin:** Exact Huntress/Symantec indicators.

**Telemetry:** Sysmon Event 3, proxy or DNS logs.

**Review / tuning:** Historical and possibly compromised infrastructure.

```spl
(index=endpoint EventCode=3)
OR index=network
| eval dest_host=lower(coalesce(query,DestinationHostname,url_domain,dest_host))
| where in(dest_ip,"192.36.27.51","62.164.177.25")
    OR in(dest_host,"projetosmecanicos.com.br","socialbizsolutions.com","professionalhomebasedbusiness.com","safefire.jo","glanz-gmbh.de","turnkeyaiagents.com","comunidadesparentais.com.br","mysimerp.net","relay.dltsolutions.top","relay.eurofin.digital","vtps.us","opa.tlsd.shop")
| table _time host Image dest_host dest_ip dest_port
```

### 4.3 DF11 — TURN/Teams relay access by a non-Teams process

**Origin:** Repository-authored from Backdoor.Turn.

**Telemetry:** Sysmon Event 3 or proxy with hostname enrichment.

**Review / tuning:** Browsers/conferencing software can legitimately use TURN.

```spl
index=endpoint EventCode=3 DestinationPort IN (3478,443)
(DestinationHostname="*turn*" OR DestinationHostname="*skype*" OR DestinationHostname="*teams.microsoft*")
NOT Image IN ("*\\ms-teams.exe","*\\teams.exe","*\\skype.exe","*\\chrome.exe","*\\msedge.exe","*\\firefox.exe")
| table _time host Image CommandLine DestinationHostname DestinationIp DestinationPort
```

## 5. Defense Evasion and Impairment

### 5.1 DF12 — Published vulnerable-driver filenames

**Origin:** S2W and Symantec reporting.

**Telemetry:** Sysmon Event 11 and Event 6.

**Review / tuning:** File creation is not load; Event 6 is stronger.

```spl
index=endpoint EventCode IN (6,11)
(TargetFilename IN ("*\\truesight.sys","*\\rentdrv2.sys","*\\HWAuidoOs2Ec.sys","*\\wsftprm.sys","*\\GameDriverx64.sys","*\\K7RKScan.sys")
 OR ImageLoaded IN ("*\\truesight.sys","*\\rentdrv2.sys","*\\HWAuidoOs2Ec.sys","*\\wsftprm.sys","*\\GameDriverx64.sys","*\\K7RKScan.sys"))
| table _time host EventCode Image TargetFilename ImageLoaded Hashes Signature SignatureStatus
```

### 5.2 DF13 — Security or database process termination

**Origin:** Repository-authored from locker process termination.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Maintenance can match; inspect parent, driver and later file impact.

```spl
index=endpoint EventCode=1 Image IN ("*\\taskkill.exe","*\\powershell.exe","*\\pwsh.exe","*\\sc.exe","*\\net.exe","*\\net1.exe")
CommandLine IN ("*MsMpEng*","*sqlservr*","*oracle*","*veeam*","*backup*","*Sophos*","*CrowdStrike*","*Sentinel*")
(CommandLine="*/f*" OR CommandLine="*Stop-Process*" OR CommandLine="* stop *" OR CommandLine="*taskkill*")
| table _time host User Image CommandLine ParentImage Hashes
```

### 5.3 DF14 — Blank-password policy or firewall weakening

**Origin:** Repository-authored from Symantec case.

**Telemetry:** Sysmon Events 1/13.

**Review / tuning:** Require unauthorized change and remote-access adjacency.

```spl
index=endpoint
((EventCode=13 TargetObject="*\\Lsa\\LimitBlankPasswordUse" Details="DWORD (0x00000000)")
 OR (EventCode=1 Image IN ("*\\netsh.exe","*\\powershell.exe","*\\pwsh.exe") CommandLine="*firewall*" CommandLine="*allow*"))
| table _time host EventCode User Image CommandLine TargetObject Details ParentImage
```

### 5.4 DF15 — Suspicious `vboxrt.dll` or DbgView-adjacent image load

**Origin:** Repository-authored from Symantec case.

**Telemetry:** Sysmon Event 7.

**Review / tuning:** Validate signer/hash and installation path.

```spl
index=endpoint EventCode=7
(ImageLoaded="*\\vboxrt.dll" OR Image IN ("*vbox*","*dbgview*"))
NOT ImageLoaded="C:\\Program Files\\Oracle\\VirtualBox\\*"
| table _time host Image ImageLoaded Hashes Signed Signature SignatureStatus
```

## 6. Collection and Exfiltration

### 6.1 DF16 — Archive or MEGA/FTP transfer sequence

**Origin:** Repository-authored from published collection channels.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Backups and approved transfers can match.

```spl
index=endpoint EventCode=1
Image IN ("*\\7z.exe","*\\7za.exe","*\\winrar.exe","*\\megasync.exe","*\\mega-cmd.exe","*\\winscp.exe","*\\ftp.exe","*\\sftp.exe")
| bin _time span=2h
| stats dc(Image) as tool_count values(Image) as tools values(CommandLine) as commands by _time host User
| where tool_count>=2 OR mvfind(tools,"(?i)(mega|winscp|ftp|sftp)")>=0
```

## 7. Recovery Inhibition

### 7.1 DF17 — Shadow-copy, backup and boot-recovery changes

**Origin:** Repository-authored from both Windows branches.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Validate parent, change ticket and actual outcome.

```spl
index=endpoint EventCode=1
((Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*")
 OR (Image="*\\wmic.exe" CommandLine="*shadowcopy*" CommandLine="*delete*")
 OR (Image="*\\wbadmin.exe" CommandLine IN ("*delete catalog*","*delete systemstatebackup*"))
 OR (Image="*\\bcdedit.exe" CommandLine IN ("*recoveryenabled*","*bootstatuspolicy*","*safeboot*")))
| table _time host User Image CommandLine ParentImage ParentCommandLine Hashes
```

## 8. Deployment and Impact

### 8.1 DF18 — ESXi VM inventory and power-off sequence

**Origin:** Repository-authored from Linux/ESXi analysis.

**Telemetry:** Forwarded ESXi shell/hostd logs.

**Review / tuning:** Planned maintenance matches; inspect initiating session and datastore impact.

```spl
index=vmware ("vim-cmd vmsvc/getallvms" OR "vim-cmd vmsvc/power.off")
| bin _time span=30m
| stats values(_raw) as commands by _time host user
| where match(mvjoin(commands," "),"getallvms") AND match(mvjoin(commands," "),"power\\.off")
```

### 8.2 DF19 — LockBit-derived DragonForce arguments

**Origin:** Repository-authored from Trend reverse engineering.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Other leaked-builder derivatives can match.

```spl
index=endpoint EventCode=1
CommandLine IN ("* -safe*","* -wall*","* -gspd*","* -psex*","* -gdel*","* -del*")
NOT Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe")
| table _time host User Image CommandLine ParentImage Hashes
```

### 8.3 DF20 — Published DragonForce encryptor SHA-256 set

**Origin:** Exact public samples.

**Telemetry:** Sysmon Event 1 with SHA-256.

**Review / tuning:** Exact artifacts only.

```spl
index=endpoint EventCode=1
(Hashes="*SHA256=1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b*"
 OR Hashes="*SHA256=451a42db9c514514ab71218033967554507b59a60ee1fc3d88cbeb39eec99f20*"
 OR Hashes="*SHA256=410db536a57c511b0ccac2639e0eb3320f303fc5c90242379ab43364c51ef321*"
 OR Hashes="*SHA256=c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d*"
 OR Hashes="*SHA256=e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22*"
 OR Hashes="*SHA256=df903c620508011ca8eb2aaaf9712a526b31a12c800b856cd524ebb3fde854b2*"
 OR Hashes="*SHA256=55befb5de5d9bc45978efd1a960ae21ed81e4be9c6521aaeebf8d5884444e3c9*"
 OR Hashes="*SHA256=572d88c419c6ae75aeb784ceab327d040cb589903d6285bbffa77338111af14b*")
| table _time host User Image CommandLine ParentImage Hashes
```

### 8.4 DF21 — Note or encrypted-extension burst

**Origin:** Repository-authored from documented artifacts.

**Telemetry:** Sysmon Event 11.

**Review / tuning:** Research/restored files can match; use count and initiator.

```spl
index=endpoint EventCode=11
(TargetFilename IN ("*\\readme.txt","*\\readme.xt","*.README.txt","*.dragonforce_encrypted","*.RNP","*.RNP_esxi","*.locked"))
| bin _time span=5m
| stats dc(TargetFilename) as files values(TargetFilename) as examples by _time host Image ProcessGuid
| where files>=10 OR match(mvjoin(examples," "),"(?i)(readme\\.xt|\\.README\\.txt)")
```

## 9. Multi-Stage Correlation

### 9.1 DF22 — RMM and impact activity on the same host

**Origin:** Repository-authored lifecycle correlation.

**Telemetry:** Sysmon Events 1 and 11.

**Review / tuning:** Time proximity is prioritization, not proof of causality.

```spl
index=endpoint earliest=-14d
| eval stage=case(EventCode=1 AND (match(lower(Image),"screenconnect|anydesk|atera|netbird|simplehelp") OR match(lower(CommandLine),"zohoassist|connectwisecontrol")),"rmm",
 EventCode=1 AND match(lower(Image),"vssadmin|wmic|wbadmin|bcdedit") AND match(lower(CommandLine),"delete shadows|shadowcopy delete|recoveryenabled|delete catalog"),"recovery",
 EventCode=11 AND match(lower(TargetFilename),"readme\\.xt|\\.readme\\.txt|\\.dragonforce_encrypted"),"impact")
| where isnotnull(stage)
| bin _time span=72h
| stats values(stage) as stages values(Image) as images values(CommandLine) as commands values(TargetFilename) as files by _time host
| where mvfind(stages,"rmm")>=0 AND (mvfind(stages,"recovery")>=0 OR mvfind(stages,"impact")>=0)
```

## 10. Campaign Artifact Hunts

### 10.1 DF23 — Huntress Citrix-linked pivots

**Origin:** Exact Huntress case values.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Generic filenames/accounts require corroboration.

```spl
index=endpoint EventCode=1
(host IN ("WIN-4E0AP4JTJR9","WIN-VI960VQI4I6")
 OR User IN ("*\\ctxsvc","*\\CtxAppVCOMService","*\\test")
 OR Image IN ("*\\eng.exe","*\\legal.exe","*\\exsym.exe","*\\as.exe","*\\exp6.exe","*\\1.exe","*\\us.msi","*\\SC.msi","*\\za.msi"))
| table _time host User Image CommandLine ParentImage Hashes
```

### 10.2 DF24 — Citrix malformed authentication flood

**Origin:** Repository-authored from Huntress CitrixBleed 2 evidence.

**Telemetry:** Citrix ADC authentication logs.

**Review / tuning:** Adapt field extraction; threshold is a broad hunt.

```spl
index=citrix "AAA_LOGIN_FAILED"
| bin _time span=1h
| stats count as failures values(user) as users values(_raw) as samples by _time host src
| where failures>=100
```

### 10.3 DF25 — Exact Backdoor.Turn campaign tools and drivers

**Origin:** Exact hashes published by Symantec for the Hackledorb-associated DragonForce case.

**Telemetry:** Sysmon Events 1, 6, 7 and 11 or equivalent EDR hash telemetry.

**Review / tuning:** Campaign-scoped confirmation. Use the hash-provenance register to distinguish backdoor, driver, discovery tool and archive roles.

```spl
index=endpoint earliest=-90d EventCode IN (1,6,7,11)
| eval hash_field=lower(coalesce(SHA256,Hashes))
| where match(hash_field,"82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b|821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6|048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c|ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0|f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b|d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e|142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219|8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3|d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e|aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5|9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759|cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a|b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383|b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877|8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2|65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951|252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab|8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531|087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2|6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4|6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e")
| table _time host EventCode User Image ImageLoaded TargetFilename CommandLine ParentImage hash_field
```
