# APT28 — Splunk Hunting Queries

**Presentation reviewed:** 2026-09-15.

**Status:** defensive hunts requiring local validation and tuning; not actor-attribution signatures. Query execution against a connected backend has not been validated.

## Scope and Requirements

Local searches use raw Sysmon events with extracted fields, `index=windows` and `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. Adapt these two selectors and field aliases to ingestion. Required fields are EventCode, Computer, User, Image, ParentImage, CommandLine, ProcessGuid, TargetFilename, TargetObject, Details, ImageLoaded, Hashes, DestinationIp, DestinationPort, QueryName and QueryResults as applicable. Enable relevant event collection: 1 process; 3 network; 7 image load; 11 file creation/overwrite; 13 registry value; 22 DNS. Local searches need no CIM model, external lookup or macros. Retained published searches have separate CIM/macro prerequisites. No Splunk backend execution was available.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 4 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 2. Active Directory and Network Discovery | 1 query | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 3. Persistence and Remote Administration | 12 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 4. Tunneling and C2 | 2 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 5. Defense Evasion and Impairment | 3 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 10. Campaign Artifact Hunts | 6 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |

## Interpretation Notes

Copy the searches below into Splunk with the Endpoint CIM model and referenced macros available.

## 1. Credential Access

### 1.1 H02 — Outlook outbound SMB to a public IPv4 address

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 3.

**Review / tuning:** Investigate message and NTLM context. KQL uses the sensor's Public classification; SPL excludes common non-public IPv4 ranges and needs local reserved-range tuning. IPv6 is outside the SPL search.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-7d
| where like(lower(Image),"%\\outlook.exe") AND DestinationPort=445 AND isnotnull(DestinationIp) AND match(DestinationIp,"^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$") AND NOT (cidrmatch("10.0.0.0/8",DestinationIp) OR cidrmatch("172.16.0.0/12",DestinationIp) OR cidrmatch("192.168.0.0/16",DestinationIp) OR cidrmatch("127.0.0.0/8",DestinationIp) OR cidrmatch("169.254.0.0/16",DestinationIp) OR cidrmatch("100.64.0.0/10",DestinationIp) OR cidrmatch("224.0.0.0/4",DestinationIp) OR cidrmatch("0.0.0.0/8",DestinationIp))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 1.2 H15 — Browser-secret collection terms in PowerShell

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** STEELHOOK-related behavioral hypothesis. Command lines often omit script bodies; enable script-block collection for a separate content investigation. Browser migration/security tooling can match.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(Image),"%\\powershell.exe%") OR like(lower(Image),"%\\pwsh.exe%")) AND (like(lower(CommandLine),"%login data%") OR like(lower(CommandLine),"%local state%")) AND (like(lower(CommandLine),"%unprotect%") OR like(lower(CommandLine),"%protecteddata%") OR like(lower(CommandLine),"%invoke-restmethod%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 1.3 H16 — Credential prompt with password extraction and file output

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** HEADLACE credential-dialog hypothesis. Requires visible script content; review approved scripts and obtain the script file for YARA triage.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(Image),"%\\powershell.exe%") OR like(lower(Image),"%\\pwsh.exe%")) AND like(lower(CommandLine),"%get-credential%") AND like(lower(CommandLine),"%getnetworkcredential%") AND like(lower(CommandLine),"%add-content%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 1.4 H17 — Registry hive export associated with credential collection

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** GooseEgg follow-on credential collection context. Backup and incident-response activity can match; correlate with the task, writer and account.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(Image),"%\\reg.exe%")) AND match(lower(CommandLine),"(^|[ ])save[ ]") AND (like(lower(CommandLine),"%hklm\\sam%") OR like(lower(CommandLine),"%hklm\\system%") OR like(lower(CommandLine),"%hklm\\security%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

## 2. Active Directory and Network Discovery

### 2.1 H21 — Native discovery command burst

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Locally chosen threshold: at least three different native discovery tools in ten minutes per host/account. This is a triage threshold, not a published APT28 constant. Inventory and support scripts commonly match; fixed windows can split a burst.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval Tool=lower(mvindex(split(Image,"\\"),-1))
| where Tool IN ("whoami.exe","ipconfig.exe","systeminfo.exe","net.exe","net1.exe","nltest.exe","quser.exe")
| bin _time span=10m
| stats dc(Tool) as ToolCount values(Tool) as Tools values(CommandLine) as Commands count by _time Computer User
| where ToolCount >= 3
| sort - _time
```

## 3. Persistence and Remote Administration

### 3.1 Outlook macro security modified

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Endpoint.Registry CIM; registry changes such as Sysmon Event 13.

**Review / tuning:** **Search name:** `windows_outlook_macro_security_modified`. Preserve the publisher macros and tune their filters to local administration.

Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Compatibility corrections and upstream limits are documented below.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry WHERE Registry.registry_path="*\\Outlook\\Security*" Registry.registry_value_name="Level" Registry.registry_value_data="0x00000001" by Registry.action Registry.dest Registry.process_guid Registry.process_id Registry.registry_hive Registry.registry_path Registry.registry_key_name Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type Registry.status Registry.user Registry.vendor_product
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_outlook_macro_security_modified_filter`
```

### 3.2 Outlook macro created by suspicious process

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Endpoint.Filesystem CIM; file creation such as Sysmon Event 11.

**Review / tuning:** **Search name:** `windows_outlook_macro_created_by_suspicious_process`. Preserve the publisher macros and tune their filters to local administration.

Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Upstream limitations are retained below.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_create_time) as file_create_time from datamodel=Endpoint.Filesystem where Filesystem.file_path="*Appdata\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM" by Filesystem.action Filesystem.dest Filesystem.file_access_time Filesystem.file_create_time Filesystem.file_hash Filesystem.file_modify_time Filesystem.file_name Filesystem.file_path Filesystem.file_acl Filesystem.file_size Filesystem.process_guid Filesystem.process_id Filesystem.user Filesystem.vendor_product
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_outlook_macro_created_by_suspicious_process_filter`
```

### 3.3 Outlook loadmacroprovideronboot persistence

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Endpoint.Registry CIM; registry changes such as Sysmon Event 13.

**Review / tuning:** **Search name:** `windows_outlook_loadmacroprovideronboot_persistence`. Preserve the publisher macros and tune their filters to local administration.

Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Upstream limitations are retained below.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry WHERE Registry.registry_path="*\\Outlook\\*" Registry.registry_value_name="LoadMacroProviderOnBoot" Registry.registry_value_data="0x00000001" by Registry.action Registry.dest Registry.process_guid Registry.process_id Registry.registry_hive Registry.registry_path Registry.registry_key_name Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type Registry.status Registry.user Registry.vendor_product
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_outlook_loadmacroprovideronboot_persistence_filter`
```

### 3.4 Outlook dialogs disabled from unusual process

**Origin:** Published search with repository compatibility adjustments.

**Telemetry:** Endpoint.Registry CIM; registry changes such as Sysmon Event 13.

**Review / tuning:** **Search name:** `windows_outlook_dialogs_disabled_from_unusual_process`. Preserve the publisher macros and tune their filters to local administration.

Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Upstream limitations are retained below.



**Compatibility corrections and upstream limits:** `min(_time) as firstTime` and `max(_time) as lastTime` are added to tstats aggregations that formatted absent time fields. The dialogs search retains firstTime/lastTime through its fields projection. Pipelines are split over lines for copying. Selection predicates remain published. The macro-created search does not filter process ancestry despite its title; investigate the creating process separately. The dialogs search retains the publisher's join behavior and its limits. These are locally normalized published searches, not vendor-validated revisions.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry WHERE Registry.registry_path="*\\Outlook\\Options\\General*" Registry.registry_value_name="PONT_STRING" by Registry.action Registry.dest Registry.process_guid Registry.process_id Registry.registry_hive Registry.registry_path Registry.registry_key_name Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type Registry.status Registry.user Registry.vendor_product
| `drop_dm_object_name(Registry)`
| join process_guid [
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE NOT (Processes.process_name = "Outlook.exe") by _time span=1h Processes.action Processes.dest Processes.original_file_name Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path Processes.process Processes.process_exec Processes.process_guid Processes.process_hash Processes.process_id Processes.process_integrity_level Processes.process_name Processes.process_path Processes.user Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`]
| fields _time firstTime lastTime parent_process_name parent_process process_name process_path process process_guid registry_path registry_value_name registry_value_data registry_key_name action dest user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_outlook_dialogs_disabled_from_unusual_process_filter`
```

### 3.5 H05 — GooseEgg-associated scheduled task

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Task creation, modification and removal are all retained. Inspect task XML and the referenced script; generic batch names alone have weak specificity.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(Image),"%\\schtasks.exe%")) AND (like(lower(CommandLine),"%\\microsoft\\windows\\winsrv%") OR like(lower(CommandLine),"%servtask.bat%") OR like(lower(CommandLine),"%execute.bat%") OR like(lower(CommandLine),"%doit.bat%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 3.6 H06 — GooseEgg-associated COM registration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13.

**Review / tuning:** Includes HKCU and HKU representations. Registry evidence is an artifact match, not proof that the DLL executed.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| where like(lower(TargetObject),"%{026cc6d7-34b2-33d5-b551-ca31eb6ce345}%") AND like(lower(Details),"%.dll%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 3.7 H07 — GooseEgg-associated protocol handler

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13.

**Review / tuning:** The handler name is a prefix because observed variants include a numeric suffix. Correlate with H06 and H08.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| where like(lower(TargetObject),"%\\classes\\protocols\\handler\\rogue%") AND like(lower(Details),"%{026cc6d7-34b2-33d5-b551-ca31eb6ce345}%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 3.8 H09 — Outlook macro project written by another process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11.

**Review / tuning:** Software deployment and macro backup restoration can match. Inspect the actual project; file name alone cannot separate NotDoor from MiniDoor or approved macros.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| where like(lower(TargetFilename),"%\\microsoft\\outlook\\vbaproject.otm%") AND NOT like(lower(Image),"%\\outlook.exe%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 3.9 H10 — Outlook macro security lowered

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13.

**Review / tuning:** Registry data encodings vary by collector. Baseline administrative policy changes and correlate with a macro write.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| where like(lower(TargetObject),"%\\outlook\\security\\level%") AND lower(Details) IN ("1","0x00000001","dword (0x00000001)")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 3.10 H11 — Outlook macro provider enabled at startup

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13.

**Review / tuning:** Legitimate macro configuration can match. Confirm writer identity and the macro project contents.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| where like(lower(TargetObject),"%\\outlook\\%") AND like(lower(TargetObject),"%\\loadmacroprovideronboot%") AND lower(Details) IN ("1","0x00000001","dword (0x00000001)")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 3.11 H14 — Outlook spawning a command or script interpreter

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Macro execution investigation; user-launched attachments and add-ins can also match. Correlate H09–H12 before assigning priority.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(ParentImage),"%\\outlook.exe%")) AND (like(lower(Image),"%\\cmd.exe%") OR like(lower(Image),"%\\powershell.exe%") OR like(lower(Image),"%\\pwsh.exe%") OR like(lower(Image),"%\\mshta.exe%") OR like(lower(Image),"%\\rundll32.exe%") OR like(lower(Image),"%\\wscript.exe%") OR like(lower(Image),"%\\cscript.exe%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 3.12 H18 — Remote-service command execution through PSEXESVC

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Generic remote execution observed in the actor lifecycle. Approved remote administration is common; renamed service binaries are outside this predicate.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(ParentImage),"%\\psexesvc.exe%")) AND (like(lower(Image),"%\\cmd.exe%") OR like(lower(Image),"%\\powershell.exe%") OR like(lower(Image),"%\\pwsh.exe%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

## 4. Tunneling and C2

### 4.1 H20 — Mail protocol connection from a scripting process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 3.

**Review / tuning:** A narrow mail-channel hunting hypothesis informed by OCEANMAP and mail-based operations, not an OCEANMAP signature. Excludes native implants without a script host; approved mail automation is a likely false positive.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-7d
| where (like(lower(Image),"%\\powershell.exe%") OR like(lower(Image),"%\\pwsh.exe%") OR like(lower(Image),"%\\python.exe%") OR like(lower(Image),"%\\pythonw.exe%") OR like(lower(Image),"%\\wscript.exe%") OR like(lower(Image),"%\\cscript.exe%")) AND DestinationPort IN (143,993,465,587)
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 4.2 H24 — Scripting or browser context contacting webhook service

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 22.

**Review / tuning:** Service abuse hypothesis, not a malicious-domain verdict. Exact host/subdomain boundary matching excludes lookalike suffixes. KQL measures a network event with URL/hostname visibility; SPL measures DNS resolution, which does not prove a connection. Approved integrations and browser automation can match.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 earliest=-7d
| eval ProcessName=lower(mvindex(split(Image,"\\"),-1)), QueriedHost=lower(rtrim(QueryName,"."))
| where ProcessName IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","msedge.exe")
| where QueriedHost="webhook.site" OR like(QueriedHost,"%.webhook.site")
| table _time Computer User Image ProcessGuid QueryName QueryResults
| sort - _time
```

## 5. Defense Evasion and Impairment

### 5.1 H08 — GooseEgg copied printer constraint file in ProgramData

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11.

**Review / tuning:** Targets the copied driver-store artifact. Sysmon 11 covers creation/overwrite, not every modification. Approved driver staging may match.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| where like(lower(TargetFilename),"%c:\\programdata\\%") AND like(lower(TargetFilename),"%\\mpdw-constraints.js%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 5.2 H12 — Outlook dialog settings changed by another process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13.

**Review / tuning:** This detects a setting change, not necessarily disabled dialogs. Interpret the value and compare with local policy.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| where like(lower(TargetObject),"%\\outlook\\options\\general\\pont_string%") AND NOT like(lower(Image),"%\\outlook.exe%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 5.3 H13 — OneDrive loading SSPICLI from a user or staging directory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 7.

**Review / tuning:** Requires image-load collection. Check the loaded DLL's signature and hash and the loader directory; the signed OneDrive executable is not a malware indicator.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7 earliest=-7d
| where (like(lower(Image),"%\\onedrive.exe%")) AND (like(lower(ImageLoaded),"%c:\\users\\%") OR like(lower(ImageLoaded),"%c:\\programdata\\%")) AND like(lower(ImageLoaded),"%\\sspicli.dll%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

## 10. Campaign Artifact Hunts

### 10.1 H01 — Office spawning a script interpreter or proxy execution binary

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Phishing and document execution triage. Office add-ins and automation can match; this does not identify an exploit or CVE.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(ParentImage),"%\\winword.exe%") OR like(lower(ParentImage),"%\\excel.exe%") OR like(lower(ParentImage),"%\\powerpnt.exe%")) AND (like(lower(Image),"%\\cmd.exe%") OR like(lower(Image),"%\\powershell.exe%") OR like(lower(Image),"%\\pwsh.exe%") OR like(lower(Image),"%\\mshta.exe%") OR like(lower(Image),"%\\rundll32.exe%") OR like(lower(Image),"%\\wscript.exe%") OR like(lower(Image),"%\\cscript.exe%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 10.2 H03 — HEADLACE-style headless browser launched by a script

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Headless browser automation can be legitimate. Inspect browser arguments, script origin and subsequent network activity.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(Image),"%\\msedge.exe%")) AND like(lower(CommandLine),"%--headless%") AND (like(lower(ParentImage),"%\\cmd.exe%") OR like(lower(ParentImage),"%\\powershell.exe%") OR like(lower(ParentImage),"%\\wscript.exe%") OR like(lower(ParentImage),"%\\cscript.exe%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 10.3 H04 — Script command renaming an image or stylesheet into a batch file

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1.

**Review / tuning:** Command-line co-occurrence only: confirm the source and destination in the complete event. It does not prove a rename succeeded; routine packaging can match.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| where (like(lower(Image),"%\\cmd.exe%") OR like(lower(Image),"%\\powershell.exe%") OR like(lower(Image),"%\\pwsh.exe%")) AND (match(lower(CommandLine),"(^|[ ;])ren(ame)?[ ]") OR like(lower(CommandLine),"%rename-item%")) AND (like(lower(CommandLine),"%.jpg%") OR like(lower(CommandLine),"%.css%")) AND (like(lower(CommandLine),"%.cmd%") OR like(lower(CommandLine),"%.bat%"))
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 10.4 H19 — Neusploit staging artifact creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11.

**Review / tuning:** Filename-based triage with low standalone specificity. Confirm hashes and the delivery chain; a match does not prove CVE-2026-21509 exploitation.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| where (like(lower(TargetFilename),"%\\office.xml%") OR like(lower(TargetFilename),"%\\ehstoreshell.dll%") OR like(lower(TargetFilename),"%\\splashscreen.png%") OR like(lower(TargetFilename),"%\\testtemp.ini%")) AND like(lower(TargetFilename),"%c:\\programdata\\%")
| table _time Computer User Image ParentImage CommandLine ProcessGuid TargetFilename TargetObject Details ImageLoaded DestinationIp DestinationPort
| sort - _time
```

### 10.5 H22 — Connections to the retained router-campaign IP inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 3.

**Review / tuning:** Embeds 182 deduplicated IPs from this dossier. Retrospective campaign matching only: these may be shared, reassigned or remediated. Review the inventory's campaign dates; do not classify all matches as current C2. KQL covers all initiating processes; Sysmon requires network collection.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-30d
| where DestinationIp IN ("5.226.137.151","5.226.137.230","5.226.137.231","5.226.137.232","5.226.137.234","5.226.137.235","5.226.137.242","5.226.137.243","5.226.137.244","5.226.137.245","23.106.120.119","37.221.64.77","37.221.64.78","37.221.64.93","37.221.64.101","37.221.64.116","37.221.64.131","37.221.64.148","37.221.64.149","37.221.64.150","37.221.64.151","37.221.64.163","37.221.64.173","37.221.64.199","37.221.64.208","37.221.64.224","37.221.64.254","64.120.31.96","64.120.31.97","64.120.31.98","64.120.31.99","64.120.31.100","77.83.197.37","77.83.197.38","77.83.197.39","77.83.197.40","77.83.197.41","77.83.197.42","77.83.197.43","77.83.197.44","77.83.197.45","77.83.197.46","77.83.197.47","77.83.197.48","77.83.197.49","77.83.197.50","77.83.197.51","77.83.197.52","77.83.197.53","77.83.197.54","77.83.197.55","77.83.197.56","77.83.197.57","77.83.197.58","77.83.197.59","77.83.197.60","79.141.160.78","79.141.161.66","79.141.161.67","79.141.161.68","79.141.161.69","79.141.161.70","79.141.161.71","79.141.161.72","79.141.161.73","79.141.161.74","79.141.161.75","79.141.161.76","79.141.161.77","79.141.161.78","79.141.161.79","79.141.161.80","79.141.161.81","79.141.161.82","79.141.161.83","79.141.161.84","79.141.161.85","79.141.173.70","79.141.173.96","79.141.173.97","79.141.173.98","79.141.173.103","79.141.173.119","79.141.173.120","79.141.173.121","79.141.173.122","79.141.173.211","79.141.173.231","79.141.173.232","79.141.173.233","185.117.88.22","185.117.88.28","185.117.88.29","185.117.88.30","185.117.88.31","185.117.88.50","185.117.88.60","185.117.88.61","185.117.88.62","185.117.89.32","185.117.89.46","185.117.89.47","185.237.166.55","185.237.166.56","185.237.166.57","185.237.166.58","185.237.166.59","185.237.166.60","185.237.166.61","185.237.166.62","185.237.166.63","185.237.166.64","185.237.166.65","185.237.166.66","185.237.166.67","185.237.166.68","185.237.166.69","185.237.166.70","185.237.166.71","185.237.166.72","185.237.166.73","185.237.166.74","185.237.166.75","185.237.166.224","185.237.166.225","185.237.166.226","185.237.166.227","185.237.166.228","185.237.166.229","185.237.166.230","185.237.166.231","185.237.166.232","185.237.166.233","185.237.166.234","185.237.166.235","185.237.166.236","185.237.166.237","185.237.166.238","185.237.166.239","185.237.166.240","185.237.166.241","185.237.166.242","185.237.166.243","185.237.166.244","185.237.166.245","185.237.166.246","185.237.166.247","185.237.166.248","185.237.166.249","64.44.154.227","64.44.154.237","64.44.154.238","64.44.154.239","64.44.154.240","77.83.198.39","79.141.173.123","79.141.173.200","79.141.173.210","79.141.173.246","79.141.173.247","79.141.173.248","79.141.173.249","79.141.173.250","79.141.173.251","79.141.173.252","79.141.173.253","79.141.173.254","79.143.87.229","79.143.87.232","79.143.87.240","79.143.87.243","79.143.87.249","88.80.148.49","88.80.148.53","89.150.40.43","89.150.40.86","103.140.186.148","103.140.186.149","103.140.186.155","185.234.73.58","185.234.73.61","185.234.73.62")
| table _time Computer User Image ProcessGuid DestinationIp DestinationPort
| sort - _time
```

### 10.6 H23 — Retained malicious sample hashes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Events 1 and 7.

**Review / tuning:** Embeds 14 SHA-256 and 2 SHA-1 values from the dossier; excludes the legitimate OneDrive loader. Exact matches only. KQL SHA256 is frequently absent; SHA1 coverage depends on available indicators. SPL requires Sysmon hashing configuration and scans process/image-load hashes, not arbitrary file creation.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=7) earliest=-30d
| rex field=Hashes "(?i)(?:^|,)SHA256=(?<SampleSHA256>[a-f0-9]{64})(?:,|$)"
| rex field=Hashes "(?i)(?:^|,)SHA1=(?<SampleSHA1>[a-f0-9]{40})(?:,|$)"
| eval SampleSHA256=lower(SampleSHA256), SampleSHA1=lower(SampleSHA1)
| where SampleSHA256 IN ("0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e","1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50","2822c72a59b58c00fc088aa551cdeeb92ca10fd23e23745610ff207f53118db9","3f446d316efe2514efd70c975d0c87e12357db9fca54a25834d60b28192c6a69","5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705","6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f","7d51e5cc51c43da5deae5fbc2dce9b85c0656c465bb25ab6bd063a503c1806a9","8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901","9f4672c1374034ac4556264f0d4bf96ee242c0b5a9edaa4715b5e61fe8d55cc8","a876f648991711e44a8dcf888a271880c6c930e5138f284cd6ca6128eca56ba1","a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee","b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546","bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e","c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5") OR SampleSHA1 IN ("5603e99151f8803c13d48d83b8a64d071542f01b","6d39f49aa11ce0574d581f10db0f9bae423ce3d5")
| table _time Computer User Image ImageLoaded ProcessGuid SampleSHA256 SampleSHA1
| sort - _time
```
