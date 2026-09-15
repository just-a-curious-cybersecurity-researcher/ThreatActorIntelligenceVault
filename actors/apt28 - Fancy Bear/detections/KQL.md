# APT28 — Microsoft Defender XDR / KQL Hunting Queries

**Presentation reviewed:** 2026-09-15.

**Status:** defensive hunts requiring local validation and tuning; not actor-attribution signatures. Query execution against a connected backend has not been validated.

## Scope and Requirements

Local endpoint queries use Microsoft Defender XDR tables and a seven-day lookback unless specified. Missing sensor data is not evidence of absence. Review process ancestry, approved administration and campaign dates before escalation. Retained queries state their own prerequisites; no Defender/Sentinel backend execution was available.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 6 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 2. Active Directory and Network Discovery | 1 query | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 3. Persistence and Remote Administration | 11 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 4. Tunneling and C2 | 2 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 5. Defense Evasion and Impairment | 4 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 6. Collection and Exfiltration | 2 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 10. Campaign Artifact Hunts | 7 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |

## Interpretation Notes

H01–H24 retain their identifiers across KQL and Splunk. Their predicates translate documented procedures into local hunting hypotheses. Retained Microsoft queries keep their compatibility notes. Campaign IPs support retrospective matching; shared or reassigned infrastructure requires incident context. Sample hashes identify retained files, while the signed OneDrive loader remains excluded from the malicious-hash inventory.

## 1. Credential Access

### 1.1 Outlook: SMB authentication to the Internet

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Defender XDR DeviceNetworkEvents.

**Review / tuning:** Published Microsoft hunt. Outbound SMB can be legitimate; investigate the initiating process and message context. The original predicate considers both local and remote IP fields.

```kusto
//Hunt for SMB to the internet
let range = ago(30d);
DeviceNetworkEvents
| where Timestamp > range
//Connections have RemotePort set to 445
//NetworkSignatureInspected have LocalPort set to 445
| where RemotePort == 445 or LocalPort == 445
| where not(ipv4_is_private(RemoteIP)) or not(ipv4_is_private(LocalIP))
| extend SignatureName = tostring(parse_json(AdditionalFields).SignatureName)
| project-reorder Timestamp, DeviceName, ActionType, LocalIP,RemoteIP, LocalPort, RemotePort,SignatureName
| sort by Timestamp desc
```

### 1.2 High-risk successful or interrupted cloud sign-ins

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** AADSignInEventsBeta; requires the tenant's identity telemetry and access to this table.

**Review / tuning:** Published campaign hunt; a high-risk sign-in is not proof of DNS interception. Investigate device, location, session and MFA context.

```kusto
AADSignInEventsBeta
| where RiskLevelAggregated == 100 and (ErrorCode == 0 or ErrorCode == 50140)
| project Timestamp, Application, LogonType, AccountDisplayName, UserAgent, IPAddress
```

### 1.3 H02 — Outlook outbound SMB to a public IPv4 address

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents.

**Review / tuning:** Investigate message and NTLM context. KQL uses the sensor's Public classification; SPL excludes common non-public IPv4 ranges and needs local reserved-range tuning. IPv6 is outside the SPL search.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "outlook.exe" and RemotePort == 445 and RemoteIPType =~ "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 1.4 H15 — Browser-secret collection terms in PowerShell

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** STEELHOOK-related behavioral hypothesis. Command lines often omit script bodies; enable script-block collection for a separate content investigation. Browser migration/security tooling can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe") and (ProcessCommandLine contains "Login Data" or ProcessCommandLine contains "Local State") and (ProcessCommandLine contains "Unprotect" or ProcessCommandLine contains "ProtectedData" or ProcessCommandLine contains "Invoke-RestMethod")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 1.5 H16 — Credential prompt with password extraction and file output

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** HEADLACE credential-dialog hypothesis. Requires visible script content; review approved scripts and obtain the script file for YARA triage.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine contains "Get-Credential" and ProcessCommandLine contains "GetNetworkCredential" and ProcessCommandLine contains "Add-Content"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 1.6 H17 — Registry hive export associated with credential collection

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** GooseEgg follow-on credential collection context. Backup and incident-response activity can match; correlate with the task, writer and account.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "reg.exe" and ProcessCommandLine has "save" and (ProcessCommandLine contains @"HKLM\SAM" or ProcessCommandLine contains @"HKLM\SYSTEM" or ProcessCommandLine contains @"HKLM\SECURITY")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## 2. Active Directory and Network Discovery

### 2.1 H21 — Native discovery command burst

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Locally chosen threshold: at least three different native discovery tools in ten minutes per host/account. This is a triage threshold, not a published APT28 constant. Inventory and support scripts commonly match; fixed windows can split a burst.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe", "net1.exe", "nltest.exe", "quser.exe")
| extend Tool = tolower(FileName)
| summarize Tools=make_set(Tool), Commands=make_set(ProcessCommandLine, 30), Events=count() by DeviceId, DeviceName, AccountName, bin(Timestamp, 10m)
| where array_length(Tools) >= 3
| order by Timestamp desc
```

## 3. Persistence and Remote Administration

### 3.1 GooseEgg: payload execution and scheduled tasks

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Defender XDR DeviceProcessEvents.

**Review / tuning:** Published predicates; Timestamp and verbatim Windows strings normalized for Defender XDR. Task command lines are detection strings, not procedures to execute.

```kusto
DeviceProcessEvents
| where Timestamp > ago(60d) // change the duration according to your requirement
| where InitiatingProcessSHA256 == "6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f" or SHA256 == "6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f" //hash value of justice.exe
or InitiatingProcessSHA256 == "c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5" or SHA256 == "c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5" //hash value of DefragmentSrv.exe
or ProcessCommandLine contains @"schtasks /Create /RU SYSTEM /TN \Microsoft\Windows\WinSrv /TR C:\ProgramData\servtask.bat /SC MINUTE" or
   ProcessCommandLine contains @"schtasks /Create /RU SYSTEM /TN \Microsoft\Windows\WinSrv /TR C:\ProgramData\execute.bat /SC MINUTE" or
   ProcessCommandLine contains @"schtasks /Create /RU SYSTEM /TN \Microsoft\Windows\WinSrv /TR C:\ProgramData\doit.bat /SC MINUTE" or
   ProcessCommandLine contains @"schtasks /DELETE /F /TN \Microsoft\Windows\WinSrv" or
   InitiatingProcessCommandLine contains @"schtasks /Create /RU SYSTEM /TN \Microsoft\Windows\WinSrv /TR C:\ProgramData\servtask.bat /SC MINUTE" or
   InitiatingProcessCommandLine contains @"schtasks /Create /RU SYSTEM /TN \Microsoft\Windows\WinSrv /TR C:\ProgramData\execute.bat /SC MINUTE" or
   InitiatingProcessCommandLine contains @"schtasks /Create /RU SYSTEM /TN \Microsoft\Windows\WinSrv /TR C:\ProgramData\doit.bat /SC MINUTE" or
   InitiatingProcessCommandLine contains @"schtasks /DELETE /F /TN \Microsoft\Windows\WinSrv"
| project Timestamp, AccountName,AccountUpn,ActionType, DeviceId, DeviceName,FolderPath, FileName
```

### 3.2 GooseEgg: COM server registration

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Defender XDR DeviceRegistryEvents.

**Review / tuning:** Published predicates with Timestamp and verbatim path strings. Correlate with payload provenance; registry changes alone do not establish execution.

```kusto
DeviceRegistryEvents
  | where Timestamp > ago(60d) // change the duration according to your requirement
  | where ActionType == "RegistryValueSet"
  | where RegistryKey contains @"HKEY_CURRENT_USER\Software\Classes\CLSID\{026CC6D7-34B2-33D5-B551-CA31EB6CE345}\Server"
  | where RegistryValueName has "(Default)"
  | where RegistryValueData has "wayzgoose.dll" or RegistryValueData contains ".dll"
```

### 3.3 GooseEgg: protocol registration

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Defender XDR DeviceRegistryEvents.

**Review / tuning:** Published predicates with Timestamp and verbatim path strings; correlate with the COM server and file evidence.

```kusto
DeviceRegistryEvents
  | where Timestamp > ago(60d) // change the duration according to your requirement
  | where ActionType == "RegistryValueSet"
  | where RegistryKey contains @"HKEY_CURRENT_USER\Software\Classes\PROTOCOLS\Handler\rogue"
  | where RegistryValueName has "CLSID"
  | where RegistryValueData contains "{026CC6D7-34B2-33D5-B551-CA31EB6CE345}"
```

### 3.4 H05 — GooseEgg-associated scheduled task

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Task creation, modification and removal are all retained. Inspect task XML and the referenced script; generic batch names alone have weak specificity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe" and (ProcessCommandLine contains @"\Microsoft\Windows\WinSrv" or ProcessCommandLine has_any ("servtask.bat", "execute.bat", "doit.bat"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3.5 H06 — GooseEgg-associated COM registration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents.

**Review / tuning:** Includes HKCU and HKU representations. Registry evidence is an artifact match, not proof that the DLL executed.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet" and RegistryKey contains "{026CC6D7-34B2-33D5-B551-CA31EB6CE345}" and RegistryValueData contains ".dll"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3.6 H07 — GooseEgg-associated protocol handler

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents.

**Review / tuning:** The handler name is a prefix because observed variants include a numeric suffix. Correlate with H06 and H08.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet" and RegistryKey contains @"\Classes\PROTOCOLS\Handler\rogue" and RegistryValueData contains "{026CC6D7-34B2-33D5-B551-CA31EB6CE345}"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3.7 H09 — Outlook macro project written by another process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents.

**Review / tuning:** Software deployment and macro backup restoration can match. Inspect the actual project; file name alone cannot separate NotDoor from MiniDoor or approved macros.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified") and FileName =~ "VbaProject.OTM" and FolderPath contains @"\Microsoft\Outlook\" and InitiatingProcessFileName !~ "outlook.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3.8 H10 — Outlook macro security lowered

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents.

**Review / tuning:** Registry data encodings vary by collector. Baseline administrative policy changes and correlate with a macro write.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet" and RegistryKey contains @"\Outlook\Security" and RegistryValueName =~ "Level" and RegistryValueData in~ ("1", "0x00000001", "DWORD (0x00000001)")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3.9 H11 — Outlook macro provider enabled at startup

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents.

**Review / tuning:** Legitimate macro configuration can match. Confirm writer identity and the macro project contents.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet" and RegistryKey contains @"\Outlook\" and RegistryValueName =~ "LoadMacroProviderOnBoot" and RegistryValueData in~ ("1", "0x00000001", "DWORD (0x00000001)")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3.10 H14 — Outlook spawning a command or script interpreter

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Macro execution investigation; user-launched attachments and add-ins can also match. Correlate H09–H12 before assigning priority.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "outlook.exe" and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3.11 H18 — Remote-service command execution through PSEXESVC

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Generic remote execution observed in the actor lifecycle. Approved remote administration is common; renamed service binaries are outside this predicate.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "PSEXESVC.exe" and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## 4. Tunneling and C2

### 4.1 H20 — Mail protocol connection from a scripting process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents.

**Review / tuning:** A narrow mail-channel hunting hypothesis informed by OCEANMAP and mail-based operations, not an OCEANMAP signature. Excludes native implants without a script host; approved mail automation is a likely false positive.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "python.exe", "pythonw.exe", "wscript.exe", "cscript.exe") and RemotePort in (143, 993, 465, 587)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 4.2 H24 — Scripting or browser context contacting webhook service

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents.

**Review / tuning:** Service abuse hypothesis, not a malicious-domain verdict. Exact host/subdomain boundary matching excludes lookalike suffixes. KQL measures a network event with URL/hostname visibility; SPL measures DNS resolution, which does not prove a connection. Approved integrations and browser automation can match.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "msedge.exe")
| extend Host = tolower(trim_end(@"\.", tostring(parse_url(iff(RemoteUrl contains "://", RemoteUrl, strcat("https://", RemoteUrl))).Host)))
| where Host == "webhook.site" or Host endswith ".webhook.site"
| project Timestamp, DeviceName, Host, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## 5. Defense Evasion and Impairment

### 5.1 GooseEgg: driver-store JavaScript modification

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Defender XDR DeviceFileEvents.

**Review / tuning:** Published predicates with Timestamp and verbatim path strings. Approved printer servicing can match.

```kusto
DeviceFileEvents
  | where Timestamp > ago(60d) // change the duration according to your requirement
  | where ActionType == "FileCreated"
  | where FolderPath startswith @"C:\Windows\System32\DriverStore\FileRepository\"
  | where FileName endswith ".js" or FileName == "MPDW-constraints.js"
```

### 5.2 H08 — GooseEgg copied printer constraint file in ProgramData

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents.

**Review / tuning:** Targets the copied driver-store artifact. Sysmon 11 covers creation/overwrite, not every modification. Approved driver staging may match.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified") and FolderPath startswith @"C:\ProgramData\" and FileName =~ "MPDW-constraints.js"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 5.3 H12 — Outlook dialog settings changed by another process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents.

**Review / tuning:** This detects a setting change, not necessarily disabled dialogs. Interpret the value and compare with local policy.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet" and RegistryKey contains @"\Outlook\Options\General" and RegistryValueName =~ "PONT_STRING" and InitiatingProcessFileName !~ "outlook.exe"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 5.4 H13 — OneDrive loading SSPICLI from a user or staging directory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceImageLoadEvents.

**Review / tuning:** Requires image-load collection. Check the loaded DLL's signature and hash and the loader directory; the signed OneDrive executable is not a malware indicator.

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "onedrive.exe" and FileName =~ "SSPICLI.dll" and (FolderPath startswith @"C:\Users\" or FolderPath startswith @"C:\ProgramData\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## 6. Collection and Exfiltration

### 6.1 Exchange: NTLM-authenticated EWS activity

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** EWSLogging custom ingestion with AuthenticationType, ClientIpAddress, DateTime, SoapAction, UserAgent and AuthenticatedUser.

**Review / tuning:** Published Microsoft query for ingested EWS logs, not a built-in MDE table. Its colon split is IPv4-oriented; preserve full raw IP data when investigating IPv6.

```kusto
EWSLogging
| where AuthenticationType == 'NTLM'
| extend IpAddress = tostring(split(ClientIpAddress,":")[0])
| summarize count(), min(['DateTime']),max(['DateTime']),
    make_set(SoapAction), make_set(UserAgent) by AuthenticatedUser, IpAddress
```

### 6.2 Cloud mailbox search and item access

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** CloudAppEvents and a known suspicious AccountObjectId.

**Review / tuning:** Replace the single-space account placeholder with the investigated account's object ID before running. Microsoft publishes this scoped investigation query; access does not itself prove exfiltration.

```kusto
CloudAppEvents
| where AccountObjectId == " " // limit results to specific suspicious user accounts by adding the user here
| where ActionType has_any ("Search", "MailItemsAccessed")
```

## 10. Campaign Artifact Hunts

### 10.1 GooseEgg: staged scripts and payload files

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Defender XDR DeviceFileEvents.

**Review / tuning:** Timestamp and verbatim strings normalized. FolderPath equality is changed to startswith because Defender file-event paths include the filename. This explicit compatibility correction broadens the published folder filter to descendants; validate against approved staging.

```kusto
let filenames = dynamic(["execute.bat","doit.bat","servtask.bat"]);
DeviceFileEvents
  | where Timestamp > ago(60d) // change the duration according to your requirement
  | where ActionType == "FileCreated"
  | where FolderPath startswith @"C:\ProgramData\"
  | where FileName in~ (filenames) or FileName endswith ".save" or FileName endswith ".zip" or ( FileName startswith "wayzgoose" and FileName endswith ".dll") or SHA256 == "7d51e5cc51c43da5deae5fbc2dce9b85c0656c465bb25ab6bd063a503c1806a9" // hash value of execute.bat/doit.bat/servtask.bat
  | project Timestamp, DeviceId, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessAccountName,InitiatingProcessAccountUpn
```

### 10.2 H01 — Office spawning a script interpreter or proxy execution binary

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Phishing and document execution triage. Office add-ins and automation can match; this does not identify an exploit or CVE.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe") and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 10.3 H03 — HEADLACE-style headless browser launched by a script

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Headless browser automation can be legitimate. Inspect browser arguments, script origin and subsequent network activity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "msedge.exe" and ProcessCommandLine contains "--headless" and InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 10.4 H04 — Script command renaming an image or stylesheet into a batch file

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Command-line co-occurrence only: confirm the source and destination in the complete event. It does not prove a rename succeeded; routine packaging can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe") and (ProcessCommandLine has "ren" or ProcessCommandLine has "rename" or ProcessCommandLine contains "Rename-Item") and (ProcessCommandLine contains ".jpg" or ProcessCommandLine contains ".css") and (ProcessCommandLine contains ".cmd" or ProcessCommandLine contains ".bat")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 10.5 H19 — Neusploit staging artifact creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents.

**Review / tuning:** Filename-based triage with low standalone specificity. Confirm hashes and the delivery chain; a match does not prove CVE-2026-21509 exploitation.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified") and FolderPath startswith @"C:\ProgramData\" and FileName in~ ("office.xml", "EhStoreShell.dll", "SplashScreen.png", "testtemp.ini")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 10.6 H22 — Connections to the retained router-campaign IP inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents.

**Review / tuning:** Embeds 182 deduplicated IPs from this dossier. Retrospective campaign matching only: these may be shared, reassigned or remediated. Review the inventory's campaign dates; do not classify all matches as current C2. KQL covers all initiating processes; Sysmon requires network collection.

```kusto
let CampaignIPs = dynamic(["5.226.137.151","5.226.137.230","5.226.137.231","5.226.137.232","5.226.137.234","5.226.137.235","5.226.137.242","5.226.137.243","5.226.137.244","5.226.137.245","23.106.120.119","37.221.64.77","37.221.64.78","37.221.64.93","37.221.64.101","37.221.64.116","37.221.64.131","37.221.64.148","37.221.64.149","37.221.64.150","37.221.64.151","37.221.64.163","37.221.64.173","37.221.64.199","37.221.64.208","37.221.64.224","37.221.64.254","64.120.31.96","64.120.31.97","64.120.31.98","64.120.31.99","64.120.31.100","77.83.197.37","77.83.197.38","77.83.197.39","77.83.197.40","77.83.197.41","77.83.197.42","77.83.197.43","77.83.197.44","77.83.197.45","77.83.197.46","77.83.197.47","77.83.197.48","77.83.197.49","77.83.197.50","77.83.197.51","77.83.197.52","77.83.197.53","77.83.197.54","77.83.197.55","77.83.197.56","77.83.197.57","77.83.197.58","77.83.197.59","77.83.197.60","79.141.160.78","79.141.161.66","79.141.161.67","79.141.161.68","79.141.161.69","79.141.161.70","79.141.161.71","79.141.161.72","79.141.161.73","79.141.161.74","79.141.161.75","79.141.161.76","79.141.161.77","79.141.161.78","79.141.161.79","79.141.161.80","79.141.161.81","79.141.161.82","79.141.161.83","79.141.161.84","79.141.161.85","79.141.173.70","79.141.173.96","79.141.173.97","79.141.173.98","79.141.173.103","79.141.173.119","79.141.173.120","79.141.173.121","79.141.173.122","79.141.173.211","79.141.173.231","79.141.173.232","79.141.173.233","185.117.88.22","185.117.88.28","185.117.88.29","185.117.88.30","185.117.88.31","185.117.88.50","185.117.88.60","185.117.88.61","185.117.88.62","185.117.89.32","185.117.89.46","185.117.89.47","185.237.166.55","185.237.166.56","185.237.166.57","185.237.166.58","185.237.166.59","185.237.166.60","185.237.166.61","185.237.166.62","185.237.166.63","185.237.166.64","185.237.166.65","185.237.166.66","185.237.166.67","185.237.166.68","185.237.166.69","185.237.166.70","185.237.166.71","185.237.166.72","185.237.166.73","185.237.166.74","185.237.166.75","185.237.166.224","185.237.166.225","185.237.166.226","185.237.166.227","185.237.166.228","185.237.166.229","185.237.166.230","185.237.166.231","185.237.166.232","185.237.166.233","185.237.166.234","185.237.166.235","185.237.166.236","185.237.166.237","185.237.166.238","185.237.166.239","185.237.166.240","185.237.166.241","185.237.166.242","185.237.166.243","185.237.166.244","185.237.166.245","185.237.166.246","185.237.166.247","185.237.166.248","185.237.166.249","64.44.154.227","64.44.154.237","64.44.154.238","64.44.154.239","64.44.154.240","77.83.198.39","79.141.173.123","79.141.173.200","79.141.173.210","79.141.173.246","79.141.173.247","79.141.173.248","79.141.173.249","79.141.173.250","79.141.173.251","79.141.173.252","79.141.173.253","79.141.173.254","79.143.87.229","79.143.87.232","79.143.87.240","79.143.87.243","79.143.87.249","88.80.148.49","88.80.148.53","89.150.40.43","89.150.40.86","103.140.186.148","103.140.186.149","103.140.186.155","185.234.73.58","185.234.73.61","185.234.73.62"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (CampaignIPs)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### 10.7 H23 — Retained malicious sample hashes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents / DeviceProcessEvents / DeviceImageLoadEvents.

**Review / tuning:** Embeds 14 SHA-256 and 2 SHA-1 values from the dossier; excludes the legitimate OneDrive loader. Exact matches only. KQL SHA256 is frequently absent; SHA1 coverage depends on available indicators. SPL requires Sysmon hashing configuration and scans process/image-load hashes, not arbitrary file creation.

```kusto
let SHA256s = dynamic(["0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e","1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50","2822c72a59b58c00fc088aa551cdeeb92ca10fd23e23745610ff207f53118db9","3f446d316efe2514efd70c975d0c87e12357db9fca54a25834d60b28192c6a69","5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705","6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f","7d51e5cc51c43da5deae5fbc2dce9b85c0656c465bb25ab6bd063a503c1806a9","8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901","9f4672c1374034ac4556264f0d4bf96ee242c0b5a9edaa4715b5e61fe8d55cc8","a876f648991711e44a8dcf888a271880c6c930e5138f284cd6ca6128eca56ba1","a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee","b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546","bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e","c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5"]);
let SHA1s = dynamic(["5603e99151f8803c13d48d83b8a64d071542f01b","6d39f49aa11ce0574d581f10db0f9bae423ce3d5"]);
union withsource=Telemetry DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where SHA256 in~ (SHA256s) or SHA1 in~ (SHA1s)
| project Timestamp, Telemetry, DeviceName, FileName, FolderPath, SHA256, SHA1, InitiatingProcessFileName
| order by Timestamp desc
```
