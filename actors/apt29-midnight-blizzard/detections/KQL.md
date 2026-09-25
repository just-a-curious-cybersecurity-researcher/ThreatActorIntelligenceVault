# APT29 — Microsoft Defender XDR / KQL Hunting Queries

**Presentation reviewed:** 2026-09-25.

**Status:** defensive hunts requiring local validation and tuning; not actor-attribution signatures. Query execution against a connected backend has not been validated.

## Scope and Requirements

Queries use Microsoft Sentinel and Defender XDR tables. Availability varies by license, connector and audit configuration. Use a 30-day identity lookback and a 14-day endpoint lookback unless the query states otherwise. Preserve application IDs, correlation IDs, device IDs and raw audit records during investigation.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 6 queries | Identity and application changes require tenant baselines and privileged-workflow allowlists |
| 2. Active Directory and Network Discovery | 1 query | Administrative PowerShell and inventory can match |
| 3. Persistence and Remote Administration | 6 queries | Inspect host role, signer, path, initiator and corresponding identity events |
| 4. Tunneling and C2 | 2 queries | Campaign IoCs are dated and shared infrastructure can be reassigned |
| 5. Defense Evasion and Impairment | 1 query | Approved audit-policy administration can match |
| 6. Collection and Exfiltration | 1 query | Baseline Graph/EWS application and mailbox scope |
| 9. Multi-Stage Correlation | 1 query | Repository window is a triage threshold, not an actor constant |
| 10. Campaign Artifact Hunts | 10 queries | Exact artifacts and campaign-scoped cloud behaviors support retrospective investigation |

## Interpretation Notes

`H01`–`H28` retain identifiers across KQL and Splunk. A device-code login, service-principal change or CornFlake string bundle can justify investigation; attribution requires the wider campaign. Google UNC6293/UNC7005 indicators remain in a qualified tier, and UNC5976 indicators are excluded. The 2026 indicators are the most current exact artifacts in this collection, while GoldMax, WellMess and Operation Ghost indicators are historical.

## 1. Credential Access

### 1.1 H01 — Distributed password spray with successful follow-on

**Origin:** Repository-authored defensive hunt based on government and Microsoft reporting.

**Telemetry:** Microsoft Sentinel `SigninLogs`.

**Review / tuning:** Thresholds are local triage choices. Exclude authorized testing and corporate egress; inspect conditional access, authentication details and later access for each account.

```kusto
let failures = SigninLogs
| where TimeGenerated > ago(30d) and ResultType != 0
| summarize FailedUsers=dcount(UserPrincipalName), Users=make_set(UserPrincipalName, 100), FailureCount=count() by IPAddress, bin(TimeGenerated, 15m)
| where FailedUsers >= 8;
let successes = SigninLogs
| where TimeGenerated > ago(30d) and ResultType == 0
| project SuccessTime=TimeGenerated, IPAddress, UserPrincipalName, AppDisplayName, ClientAppUsed, ConditionalAccessStatus;
failures
| join kind=inner successes on IPAddress
| where SuccessTime between (TimeGenerated .. TimeGenerated + 2h)
| project TimeGenerated, SuccessTime, IPAddress, FailedUsers, FailureCount, UserPrincipalName, AppDisplayName, ClientAppUsed, ConditionalAccessStatus
```

### 1.2 H02 — Device-code authentication followed by Microsoft 365 access

**Origin:** Repository-authored defensive hunt based on Storm-2372 and CaptiveCrunch.

**Telemetry:** Sentinel `SigninLogs`; verify the tenant populates `AuthenticationProtocol`.

**Review / tuning:** Legitimate CLI, television and constrained-device workflows can use device code. Review user initiation, IP, resource, device registration and messaging context.

```kusto
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProtocol =~ "deviceCode" or ClientAppUsed has "Device Code"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName, ClientAppUsed, AuthenticationProtocol, DeviceDetail, LocationDetails, CorrelationId
| order by TimeGenerated desc
```

### 1.3 H03 — New device registration after unusual sign-in

**Origin:** Repository-authored defensive hunt based on SVR cloud guidance.

**Telemetry:** Sentinel `AuditLogs` and `SigninLogs`.

**Review / tuning:** Enrollment and help-desk activity can match. Validate the initiating identity, device owner, source IP and whether registration followed password or device-code authentication.

```kusto
let registrations = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in~ ("Add device", "Add registered owner to device", "Register device")
| extend Initiator=tostring(InitiatedBy.user.userPrincipalName), InitiatorIP=tostring(InitiatedBy.user.ipAddress)
| project RegistrationTime=TimeGenerated, Initiator, InitiatorIP, OperationName, TargetResources, CorrelationId;
let signins = SigninLogs
| where TimeGenerated > ago(30d) and ResultType == 0
| project SigninTime=TimeGenerated, UserPrincipalName, IPAddress, AuthenticationProtocol, AppDisplayName;
registrations
| join kind=leftouter signins on $left.Initiator == $right.UserPrincipalName
| where SigninTime between (RegistrationTime - 2h .. RegistrationTime + 15m)
| project RegistrationTime, Initiator, InitiatorIP, OperationName, SigninTime, IPAddress, AuthenticationProtocol, AppDisplayName, TargetResources, CorrelationId
```

### 1.4 H04 — Credential added to application or service principal

**Origin:** Repository-authored defensive hunt based on NOBELIUM and MITRE cloud persistence evidence.

**Telemetry:** Sentinel `AuditLogs`.

**Review / tuning:** CI/CD and certificate rotation produce legitimate events. Compare the initiator, application owner, credential lifetime and change ticket.

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Update application", "Update service principal", "Add service principal credentials", "Add application credentials")
| extend Initiator=coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), InitiatorIP=tostring(InitiatedBy.user.ipAddress)
| where tostring(TargetResources) has_any ("KeyDescription", "PasswordCredentials", "KeyCredentials")
| project TimeGenerated, OperationName, Initiator, InitiatorIP, TargetResources, AdditionalDetails, CorrelationId
```

### 1.5 H05 — OAuth consent or high-value application permission grant

**Origin:** Repository-authored defensive hunt based on Microsoft corporate-intrusion guidance.

**Telemetry:** Sentinel `AuditLogs`.

**Review / tuning:** Approved application onboarding can match. Review publisher, tenant verification, resource, initiator and granted scopes.

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Consent to application", "Add delegated permission grant", "Add app role assignment to service principal", "Add OAuth2PermissionGrant")
| extend Initiator=coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| where tostring(TargetResources) has_any ("Mail.Read", "Mail.ReadWrite", "full_access_as_app", "EWS.AccessAsUser.All", "Directory.ReadWrite.All")
| project TimeGenerated, OperationName, Initiator, TargetResources, AdditionalDetails, CorrelationId
```

### 1.6 H06 — Mailbox delegation or application-impersonation change

**Origin:** Repository-authored defensive hunt based on APT29 cloud collection cases.

**Telemetry:** Sentinel `OfficeActivity`.

**Review / tuning:** Mail administrators perform similar changes. Confirm the actor identity, target mailbox, role assignment and approved request.

```kusto
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload =~ "Exchange"
| where Operation in~ ("Add-MailboxPermission", "Set-Mailbox", "New-ManagementRoleAssignment", "Set-CASMailbox")
| where Parameters has_any ("ApplicationImpersonation", "FullAccess", "Mail.Read", "ActiveSyncAllowedDeviceIDs")
| project TimeGenerated, UserId, ClientIP, Operation, ObjectId, Parameters, ResultStatus, ExternalAccess
```

## 2. Active Directory and Network Discovery

### 2.1 H07 — AD, federation and Exchange discovery burst

**Origin:** Repository-authored defensive hunt based on SolarWinds and Windows Credential Roaming cases.

**Telemetry:** Defender XDR `DeviceProcessEvents`.

**Review / tuning:** Identity administrators and assessment tools can match. Threshold of three distinct utilities/cmdlets in 15 minutes is a local triage choice.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("Get-ADUser", "Get-ADGroupMember", "Get-AcceptedDomain", "Get-MsolDomainFederationSettings", "adfind.exe", "dsquery", "nltest")
| extend DiscoveryTerm=case(ProcessCommandLine has "Get-ADUser", "Get-ADUser", ProcessCommandLine has "Get-ADGroupMember", "Get-ADGroupMember", ProcessCommandLine has "Get-AcceptedDomain", "Get-AcceptedDomain", ProcessCommandLine has "Get-MsolDomainFederationSettings", "Federation", FileName)
| summarize Terms=make_set(DiscoveryTerm), Commands=make_set(ProcessCommandLine, 30), Events=count() by DeviceId, DeviceName, AccountName, bin(Timestamp, 15m)
| where array_length(Terms) >= 3
```

## 3. Persistence and Remote Administration

### 3.1 H08 — Suspicious RDP attachment or RDP client launch from user content

**Origin:** Repository-authored defensive hunt based on the October 2024 campaign.

**Telemetry:** Defender XDR `EmailAttachmentInfo`, `DeviceProcessEvents`.

**Review / tuning:** Legitimate RDP files are common. Inspect sender, attachment, Mark-of-the-Web, destination and resource-redirection configuration.

```kusto
let rdpMail = EmailAttachmentInfo
| where Timestamp > ago(30d) and FileName endswith ".rdp"
| project NetworkMessageId, RecipientEmailAddress, AttachmentName=FileName, SHA256;
let launches = DeviceProcessEvents
| where Timestamp > ago(30d) and FileName =~ "mstsc.exe"
| where ProcessCommandLine has ".rdp"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
rdpMail
| join kind=fullouter launches on $left.RecipientEmailAddress == $right.AccountName
```

### 3.2 H09 — CornFlake executable path

**Origin:** Microsoft-published hunt normalized for literal environment paths.

**Telemetry:** Defender XDR `DeviceProcessEvents`.

**Review / tuning:** `svchost32.exe` is not a standard Windows path; still validate hash and related persistence.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath endswith @"\svchost32\svchost32.exe"
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```

### 3.3 H10 — CornFlake service registration bundle

**Origin:** Microsoft-published CaptiveCrunch hunt.

**Telemetry:** Defender XDR `DeviceRegistryEvents`.

**Review / tuning:** Correlate key, image path, signer/hash and nearby Run/task persistence.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\SYSTEM\CurrentControlSet\Services\svchost32"
| where ActionType == "RegistryValueSet"
| where (RegistryValueName == "DisplayName" and RegistryValueData == "Cloud Sync Service")
    or (RegistryValueName == "Description" and RegistryValueData == "Synchronizes files with the cloud storage provider")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId
```

### 3.4 H11 — Unexpected FoggyWeb files on AD FS servers

**Origin:** Repository-authored defensive hunt based on Microsoft FoggyWeb analysis.

**Telemetry:** Defender XDR `DeviceFileEvents`; scope to the AD FS server inventory.

**Review / tuning:** The filenames mimic system resources. Validate device role, signer, hash, creation source and baseline.

```kusto
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath endswith @"\ADFS\version.dll" or FolderPath endswith @"\SystemResources\Windows.Data.TimeZones\pris\Windows.Data.TimeZones.zh-PH.pri"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

### 3.5 H12 — MAGICWEB DLL or AD FS configuration change

**Origin:** Repository-authored defensive hunt based on Microsoft MAGICWEB analysis.

**Telemetry:** Defender XDR `DeviceFileEvents` and `DeviceRegistryEvents` via union.

**Review / tuning:** Scope to federation servers. Confirm file signature/GAC provenance and authorized AD FS maintenance.

```kusto
union isfuzzy=true
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FileName =~ "Microsoft.IdentityServer.Diagnostics.dll" or FolderPath endswith @"\Microsoft.IdentityServer.Servicehost.exe.config"
 | project Timestamp, DeviceName, Evidence=FolderPath, ActionType, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceRegistryEvents
 | where Timestamp > ago(30d)
 | where RegistryKey has "ADFS" and RegistryValueData has "Microsoft.IdentityServer.Diagnostics"
 | project Timestamp, DeviceName, Evidence=strcat(RegistryKey, " | ", RegistryValueData), ActionType, SHA256="", InitiatingProcessFileName, InitiatingProcessCommandLine)
```

### 3.6 H13 — WINELOADER certutil and tar staging sequence

**Origin:** Repository-authored defensive hunt based on Mandiant's published ROOTSAW script.

**Telemetry:** Defender XDR `DeviceProcessEvents`.

**Review / tuning:** Administrators can use certutil and tar. Require the Tasks path, archive relationship or later `SqlDumper.exe` launch.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_all ("-decode", @"C:\Windows\Tasks\invite.txt", @"C:\Windows\Tasks\invite.zip"))
    or (FileName =~ "tar.exe" and ProcessCommandLine has_all ("-xf", @"C:\Windows\Tasks\invite.zip"))
    or (FileName =~ "SqlDumper.exe" and FolderPath startswith @"C:\Windows\Tasks\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by DeviceName, Timestamp asc
```

## 4. Tunneling and C2

### 4.1 H14 — WINELOADER DLL loaded by SqlDumper from staging path

**Origin:** Repository-authored defensive hunt based on Mandiant WINELOADER analysis.

**Telemetry:** Defender XDR `DeviceImageLoadEvents`.

**Review / tuning:** `SqlDumper.exe` is legitimate. Escalate an adjacent unsigned/untrusted `vcruntime140.dll`, especially from Tasks or user-writable paths.

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "SqlDumper.exe" and FileName =~ "vcruntime140.dll"
| where FolderPath has @"\Windows\Tasks\" or FolderPath has @"\Users\" or FolderPath has @"\ProgramData\"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, SHA256, Signer, IsSigned
```

### 4.2 H15 — CaptiveCrunch network indicators

**Origin:** Microsoft-published CaptiveCrunch hunt.

**Telemetry:** Defender XDR `DeviceNetworkEvents`.

**Review / tuning:** Dated campaign IoCs. Confirm DNS, TLS, process and travel/captive-portal context before attribution.

```kusto
let target_domains = dynamic(["ms365-device.com", "ms365-live.com", "m365-owa.com", "owa-ms365.com"]);
let target_ips = dynamic(["31.57.243.154", "38.146.28.75", "38.146.28.132", "104.194.159.150", "107.189.26.194", "213.145.86.112"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (target_domains) or RemoteIP in (target_ips)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId
```

## 5. Defense Evasion and Impairment

### 5.1 H16 — Audit policy or PowerShell logging impairment

**Origin:** Repository-authored defensive hunt based on SolarWinds-era defense evasion.

**Telemetry:** Defender XDR `DeviceProcessEvents`.

**Review / tuning:** Group Policy and security engineering can perform similar changes. Review account, change ticket and surrounding collection activity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "auditpol.exe" and ProcessCommandLine has_any ("/clear", "/set", "disable"))
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("ScriptBlockLogging", "ModuleLogging", "Disable-AzContextAutosave"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 6. Collection and Exfiltration

### 6.1 H17 — Unusual high-volume mailbox access by an application

**Origin:** Repository-authored defensive hunt based on Graph/EWS email collection.

**Telemetry:** Sentinel `OfficeActivity`.

**Review / tuning:** Backup, eDiscovery and security applications can match. Baseline application/user, mailbox count and operations; thresholds are local.

```kusto
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload =~ "Exchange" and Operation in~ ("MailItemsAccessed", "SearchQueryInitiatedExchange", "New-MailboxExportRequest", "Get-MailboxExportRequest")
| summarize Events=count(), Mailboxes=dcount(ObjectId), Objects=make_set(ObjectId, 100), Operations=make_set(Operation) by UserId, ClientIP, bin(TimeGenerated, 30m)
| where Events >= 100 or Mailboxes >= 5
```

## 9. Multi-Stage Correlation

### 9.1 H18 — Suspicious device-code sign-in followed by cloud persistence

**Origin:** Repository-authored correlation based on Storm-2372 and NOBELIUM cloud procedures.

**Telemetry:** Sentinel `SigninLogs` and `AuditLogs`.

**Review / tuning:** Four-hour window is a triage threshold. Legitimate developers can authenticate by device code and later update an app; require initiator, IP and application review.

```kusto
let dc = SigninLogs
| where TimeGenerated > ago(30d) and ResultType == 0
| where AuthenticationProtocol =~ "deviceCode" or ClientAppUsed has "Device Code"
| project SigninTime=TimeGenerated, UserPrincipalName, SigninIP=IPAddress, SigninCorrelation=CorrelationId;
let changes = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Add device", "Consent to application", "Add delegated permission grant", "Add app role assignment", "Update service principal", "Add service principal credentials")
| extend Initiator=tostring(InitiatedBy.user.userPrincipalName), ChangeIP=tostring(InitiatedBy.user.ipAddress)
| project ChangeTime=TimeGenerated, Initiator, ChangeIP, OperationName, TargetResources, ChangeCorrelation=CorrelationId;
dc
| join kind=inner changes on $left.UserPrincipalName == $right.Initiator
| where ChangeTime between (SigninTime .. SigninTime + 4h)
| project SigninTime, ChangeTime, UserPrincipalName, SigninIP, ChangeIP, OperationName, TargetResources, SigninCorrelation, ChangeCorrelation
```

## 10. Campaign Artifact Hunts

### 10.1 H19 — Retained APT29 sample hashes

**Origin:** Repository-authored exact match from the source-verified IOC corpus.

**Telemetry:** Defender XDR `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceImageLoadEvents`.

**Review / tuning:** Exact match identifies a retained sample. Preserve file, signer, origin and campaign chronology; do not infer current actor access from an old quarantined file.

```kusto
let hashes = dynamic(["918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593","be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c","2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41","8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8","83014ab5b3f63b0253cdab6d715f5988ac9014570fa4ab2b267c7cf9ba237d18","0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494","70d93035b0693b0e4ef65eb7f8529e6385d698759cc5b8666a394b2136cc06eb","0e1f9d4d0884c68ec25dec355140ea1bab434f5ea0f86f2aade34178ff3a7d91","247a733048b6d5361162957f53910ad6653cdef128eb5c87c46f14e7e3e46983","0affab34d950321e3031864ec2b6c00e4edafb54f4b327717cb5b042c38a33c9","7e05ff08e32a64da75ec48b5e738181afb3e24a9f1da7f5514c5a11bb067cbfb","acc74c920d19ea0a5e6007f929ef30b079eb2836b5b28e5ffcc20e68fa707e66","653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358","420d20cddfaada4e96824a9184ac695800764961bad7654a6a6c3fe9b1b74b9a","85484716a369b0bc2391b5f20cf11e4bd65497a34e7a275532b729573d6ef15e","78a810e47e288a6aff7ffbaf1f20144d2b317a1618bba840d42405cddc4cff41","d931078b63d94726d4be5dc1a00324275b53b935b77d3eed1712461f0c180164","24c079b24851a5cc8f61565176bbf1157b9d5559c642e31139ab8d76bbb320f8","adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8"]);
union isfuzzy=true DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where Timestamp > ago(365d) and SHA256 in (hashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 10.2 H20 — ChocoShell-style VSS access for locked browser data

**Origin:** Repository-authored defensive hunt based on Microsoft CaptiveCrunch analysis.

**Telemetry:** Defender XDR `DeviceProcessEvents`; PowerShell command-line visibility may be incomplete.

**Review / tuning:** Backup, forensic and browser-migration tooling can match. This hunt is credential collection; it must not be classified automatically as recovery inhibition.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "wmic.exe")
| where ProcessCommandLine has_any ("Win32_ShadowCopy", "shadowcopy", "GLOBALROOT\\Device\\HarddiskVolumeShadowCopy")
| where ProcessCommandLine has_any ("Login Data", "Cookies", "Local State", "User Data", "Web Data")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 10.3 H21 — Suspicious process launched by a Windows TeamCity server

**Origin:** Repository-authored defensive hunt based on joint government reporting of CVE-2023-42793 exploitation.

**Telemetry:** Defender XDR `DeviceProcessEvents`; scope to known TeamCity servers.

**Review / tuning:** Build steps can legitimately launch shells and utilities. Require an unexpected build context, account, command, network destination or persistence follow-on before escalation.

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe")
| where InitiatingProcessFolderPath has "TeamCity" or InitiatingProcessCommandLine has "teamcity"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "net.exe", "net1.exe", "whoami.exe", "certutil.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
```

### 10.4 H22 — Anthropic GTG-20006 published indicators

**Origin:** Repository-authored exact-indicator hunt using Anthropic's September 2026 public corpus.

**Telemetry:** Defender XDR `DeviceNetworkEvents`, `DeviceFileEvents` and `EmailEvents`.

**Review / tuning:** The campaign attribution is qualified and infrastructure can age or be reassigned. Preserve the matched artifact, signer, parent process, URL, message headers and adjacent identity activity.

```kusto
let domains = dynamic(["ms365-live.com","teams.ms365-live.com","m365-owa.com","owa-ms365.com","ms365-device.com","mslivetest.duckdns.org","my-invite.org","chamber-ua.org","chathamhouse.eu","ukrinform-share.net","statistic-ms.live","static-ms.live","ad-g.org","docs-viewer.org","wa-connect.eu","mygreatmarket.org","mygreatmarket.com","cdncounter.net","static.cdncounter.net","stuseamandesilt.org","api.stuseamandesilt.org","cdn.stuseamandesilt.org","update.stuseamandesilt.org","itechx.tel","pdfviewer2024.b-cdn.net","meridian-protocol.org","meridiangroup-corp.com","projectnightcrawler.dev","metricwave.org","mgsend.org","wa-meeting.com","russianearabroad.com","russianearabroad.org","russianearabroad.net"]);
let ips = dynamic(["104.145.210.184","31.57.243.154","104.194.151.133","104.194.159.55","144.172.114.192","213.145.86.112","2.26.53.194","148.135.195.111","185.198.234.26","185.198.234.101","149.54.42.106","104.194.149.228","38.146.28.132","38.146.28.75"]);
let files = dynamic(["msedgeupdate_v3.exe","msedgeupdate.exe","version.dll","WUEngine.exe","DiagHost.exe","client_20260507093021_4286d211_x64.exe","fix_network.apk"]);
let emails = dynamic(["anna.manager@russianearabroad.net","events@embassy-protocol.int"]);
union
    (DeviceNetworkEvents
    | where Timestamp > ago(180d)
    | where RemoteUrl in~ (domains) or RemoteIP in (ips)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceType="Network", Evidence=coalesce(RemoteUrl, RemoteIP), FileName=InitiatingProcessFileName, SHA256=InitiatingProcessSHA256, Context=InitiatingProcessCommandLine),
    (DeviceFileEvents
    | where Timestamp > ago(180d) and FileName in~ (files)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceType="File", Evidence=strcat(FolderPath, "\\", FileName), FileName, SHA256, Context=InitiatingProcessCommandLine),
    (EmailEvents
    | where Timestamp > ago(180d) and SenderFromAddress in~ (emails)
    | project Timestamp, DeviceName="", AccountName=RecipientEmailAddress, EvidenceType="Email", Evidence=SenderFromAddress, FileName="", SHA256="", Context=Subject)
| order by Timestamp desc
```

### 10.5 H23 — AWS watering-hole indicators

**Origin:** Repository-authored exact-indicator hunt from AWS's 2025 disruption report.

**Telemetry:** Defender XDR `DeviceNetworkEvents`.

**Review / tuning:** The domains are dated and may be reassigned. A network match establishes contact with published campaign infrastructure, not successful device authorization.

```kusto
let domains = dynamic(["findcloudflare.com","cloudflare.redirectpartners.com"]);
DeviceNetworkEvents
| where Timestamp > ago(365d)
| where RemoteUrl in~ (domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

### 10.6 H24 — GRAPELOADER persistence bundle

**Origin:** Repository-authored behavioral hunt from Check Point's 2025 GRAPELOADER analysis.

**Telemetry:** Defender XDR `DeviceFileEvents` and `DeviceRegistryEvents`.

**Review / tuning:** `wine.exe` is a legitimate PowerPoint binary. Require the `POWERPNT` path or Run value, adjacent DLLs, exact hashes, or campaign network evidence.

```kusto
let files = DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has @"\POWERPNT\" and FileName in~ ("wine.exe","AppvIsvSubsystems64.dll","ppcore.dll")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceType="File", Evidence=strcat(FolderPath,"\",FileName), InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256;
let runkeys = DeviceRegistryEvents
| where Timestamp > ago(90d)
| where RegistryKey endswith @"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "POWERPNT" and RegistryValueData has @"\POWERPNT\wine.exe"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceType="Registry", Evidence=strcat(RegistryKey,"\",RegistryValueName,"=",RegistryValueData), InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256=InitiatingProcessSHA256;
union files, runkeys
| order by Timestamp desc
```

### 10.7 H25 — Cross-tenant delegated administration

**Origin:** Repository-authored hunt based on Microsoft's NOBELIUM service-provider campaign.

**Telemetry:** Microsoft Sentinel `SigninLogs`; cross-tenant fields vary by connector generation.

**Review / tuning:** Legitimate MSP and B2B administration is common. Baseline approved home tenants, applications, accounts and customer scopes before escalation.

```kusto
SigninLogs
| where TimeGenerated > ago(30d) and ResultType == 0
| extend HomeTenant=tostring(column_ifexists("HomeTenantId","")), ResourceTenant=tostring(column_ifexists("ResourceTenantId","")), AccessType=tostring(column_ifexists("CrossTenantAccessType",""))
| where HomeTenant != "" and ResourceTenant != "" and HomeTenant != ResourceTenant
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Events=count(), SourceIPs=make_set(IPAddress,20), Apps=make_set(AppDisplayName,20), AccessTypes=make_set(AccessType,10) by UserPrincipalName, HomeTenant, ResourceTenant
| where Events >= 3
```

### 10.8 H26 — Azure Run Command after cloud sign-in

**Origin:** Repository-authored correlation based on Microsoft's observed Run Command plus admin-on-behalf-of pivot.

**Telemetry:** Microsoft Sentinel `AzureActivity` and `SigninLogs`.

**Review / tuning:** Automation and incident response use Run Command legitimately. Validate caller, subscription, target VM, script contents, ticket and source IP.

```kusto
let runcommands = AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has "Microsoft.Compute/virtualMachines/runCommand/action"
| where ActivityStatusValue =~ "Success"
| project RunTime=TimeGenerated, Caller=tostring(Caller), RunIP=tostring(CallerIpAddress), SubscriptionId, ResourceGroup, ResourceId, CorrelationId;
let signins = SigninLogs
| where TimeGenerated > ago(30d) and ResultType == 0
| project SigninTime=TimeGenerated, Caller=UserPrincipalName, SigninIP=IPAddress, AppDisplayName, HomeTenantId, ResourceTenantId;
runcommands
| join kind=leftouter signins on Caller
| where isnull(SigninTime) or RunTime between (SigninTime .. SigninTime + 4h)
| project RunTime, Caller, RunIP, SigninTime, SigninIP, AppDisplayName, HomeTenantId, ResourceTenantId, SubscriptionId, ResourceGroup, ResourceId, CorrelationId
```

### 10.9 H27 — Qualified UNC6293 / UNC7005 published indicators

**Origin:** Repository-authored exact-indicator hunt from Google's 2025–2026 reporting.

**Telemetry:** Defender XDR `DeviceNetworkEvents` and `DeviceFileEvents`.

**Review / tuning:** Google relates these clusters to an ICE RELIC initial-access subcluster with moderate confidence. Preserve that boundary; commodity stealer and landing-page matches do not prove core APT29 tooling. UNC5976/HEADRUSH indicators are excluded.

```kusto
let domains = dynamic(["rediruri.app","dosportal.app","foreignrelations.us","fewfwfwfwfwf.info","miov2iaiaoubqosiqoiajwowiwjso.online","mioisiskwowiwjowuwjwolab.club","chamber-ua.org","wa-connect.eu","wa-connect.net","wa-invite.com","wa-device.com","wa-meeting.com","shopinvite.org","my-invite.org","globsec.net","statistic-ms.live","owa-ms365.com","m365-owa.com","ms365-device.com","ms365-live.com","finishoperations.com","finishoperations.org","foc-share.com","share-foc.com","internal-share.com","foc-share.org"]);
let ips = dynamic(["91.190.191.117","107.189.18.7","196.251.107.171","31.57.243.154","38.146.28.75","104.194.159.150"]);
let hashes = dynamic(["329fda9939930e504f47d30834d769b30ebeaced7d73f3c1aadd0e48320d6b39","5b8d50c2e8cc3038b7c6e6dbf1219f6e814930a1e3c0053143a1191ae67f8ffc","a06a8fd1b6fa1924199a4540cf16d089217ce8f78c617739946f145fd1fc88c1","1d9299799a7b8da67c44ebec064d64542c27645f8e84de4a22ca3f6cbc843e3c","c5826032207d623a7f6caec8465af7364eccc355f9a48897da2a54f3e4420265","125752ad7c20d715920a3b2fb0fdde660f07b3f2b053665cf38c2d6d9de86e1e","403b624e35777cbc07dbe66398b21bba70396a20b859c880732338ce1dd1f41f","28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3","be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c","1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916","6f7090895c1c3dee30de6b3f098ca3a788dc198646e5293a8b1210430b0add97","20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38","ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25"]);
union
    (DeviceNetworkEvents
    | where Timestamp > ago(365d) and (RemoteUrl in~ (domains) or RemoteIP in (ips))
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceType="Network", Evidence=coalesce(RemoteUrl,RemoteIP), SHA256=InitiatingProcessSHA256, Context=InitiatingProcessCommandLine),
    (DeviceFileEvents
    | where Timestamp > ago(365d) and SHA256 in (hashes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceType="File", Evidence=strcat(FolderPath,"\",FileName), SHA256, Context=InitiatingProcessCommandLine)
| order by Timestamp desc
```

### 10.10 H28 — WINELOADER Windows 7 / Edge 119 user agent

**Origin:** Repository-authored network hunt from Check Point's 2025 WINELOADER analysis.

**Telemetry:** Microsoft Sentinel `CommonSecurityLog` or a normalized web-proxy connector exposing the user agent.

**Review / tuning:** The impossible OS/browser combination is more durable than a domain but may be copied. Correlate destination, TLS, process, host and exact sample evidence.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(90d)
| extend UserAgent=tostring(column_ifexists("RequestClientApplication","")), Host=tostring(column_ifexists("DestinationHostName","")), Url=tostring(column_ifexists("RequestURL",""))
| where UserAgent has "Windows NT 6.1; Win64; x64" and UserAgent has "Edg/119.0.2151.25"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Host, Url, UserAgent, DeviceName, Activity
```
