# APT29 — Splunk Hunting Queries

**Presentation reviewed:** 2026-09-25.

**Status:** defensive hunts requiring local field mapping and tuning; not actor-attribution signatures. Searches have not been executed against a connected Splunk deployment.

## Scope and Requirements

Identity searches assume Microsoft Entra sign-in and audit events; endpoint searches assume Sysmon or EDR-normalized process, file, registry, image-load and network fields. Replace index and sourcetype constraints with local values. Preserve raw events, correlation IDs and object identifiers during triage.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 6 searches | Map Entra and Exchange fields; baseline administrative changes |
| 2. Active Directory and Network Discovery | 1 search | Inventory and identity administration can match |
| 3. Persistence and Remote Administration | 6 searches | Validate host role, path, signer and parent process |
| 4. Tunneling and C2 | 2 searches | Campaign infrastructure is dated and may be reassigned |
| 5. Defense Evasion and Impairment | 1 search | Approved security administration can match |
| 6. Collection and Exfiltration | 1 search | Baseline mailbox and application behavior |
| 9. Multi-Stage Correlation | 1 search | Four-hour window is a repository threshold |
| 10. Campaign Artifact Hunts | 10 searches | Exact artifacts and campaign-scoped cloud behaviors |

## Interpretation Notes

`H01`–`H28` pair with the KQL document. Field names such as `user`, `src`, `operation`, `object`, `process_name`, `process`, `file_path`, `file_hash`, `registry_path` and `dest` are representative. Normalize case and hash format during ingestion. Google UNC6293/UNC7005 indicators remain qualified and UNC5976 indicators are excluded.

## 1. Credential Access

### 1.1 H01 — Distributed password spray with successful follow-on

**Origin:** Repository-authored defensive hunt based on government and Microsoft reporting.

**Telemetry:** Entra sign-in events with result, user and source IP.

**Review / tuning:** Eight users in 15 minutes is a local threshold. Exclude authorized testing and shared corporate egress.

```spl
index=identity sourcetype="azure:monitor:aad" earliest=-30d
| eval success=if(resultType="0" OR result="success",1,0), failed_user=if(success=0,user,null())
| bin _time span=15m
| stats dc(failed_user) as failed_users count(eval(success=0)) as failure_count max(success) as had_success values(user) as users values(app) as apps by src _time
| where failed_users>=8 AND had_success=1
```

### 1.2 H02 — Device-code authentication followed by Microsoft 365 access

**Origin:** Repository-authored defensive hunt based on Storm-2372 and CaptiveCrunch.

**Telemetry:** Entra sign-in events with authentication protocol.

**Review / tuning:** Legitimate CLI and constrained devices can use the flow. Confirm user initiation, application, IP and device registration.

```spl
index=identity sourcetype="azure:monitor:aad" earliest=-30d (authenticationProtocol="deviceCode" OR clientAppUsed="*Device Code*") (resultType="0" OR result="success")
| table _time user src app resource clientAppUsed authenticationProtocol deviceId correlationId
```

### 1.3 H03 — New device registration after unusual sign-in

**Origin:** Repository-authored defensive hunt based on SVR cloud guidance.

**Telemetry:** Entra audit events.

**Review / tuning:** Enrollment teams can produce expected events. Review initiator, owner, source IP and preceding sign-in.

```spl
index=identity sourcetype="azure:aad:audit" earliest=-30d operation IN ("Add device","Add registered owner to device","Register device")
| table _time initiator src operation targetResources correlationId
| sort 0 - _time
```

### 1.4 H04 — Credential added to application or service principal

**Origin:** Repository-authored defensive hunt based on NOBELIUM cloud persistence evidence.

**Telemetry:** Entra audit events.

**Review / tuning:** Certificate rotation and CI/CD can match. Verify initiator, target app, lifetime and ticket.

```spl
index=identity sourcetype="azure:aad:audit" earliest=-30d operation IN ("Update application","Update service principal","Add service principal credentials","Add application credentials")
| search targetResources IN ("*KeyDescription*","*PasswordCredentials*","*KeyCredentials*")
| table _time initiator src operation targetResources additionalDetails correlationId
```

### 1.5 H05 — OAuth consent or high-value application permission grant

**Origin:** Repository-authored defensive hunt based on Microsoft response guidance.

**Telemetry:** Entra audit events.

**Review / tuning:** Approved application onboarding can match. Review publisher, tenant verification and resource scope.

```spl
index=identity sourcetype="azure:aad:audit" earliest=-30d operation IN ("Consent to application","Add delegated permission grant","Add app role assignment to service principal","Add OAuth2PermissionGrant")
| search targetResources IN ("*Mail.Read*","*Mail.ReadWrite*","*full_access_as_app*","*EWS.AccessAsUser.All*","*Directory.ReadWrite.All*")
| table _time initiator src operation targetResources additionalDetails correlationId
```

### 1.6 H06 — Mailbox delegation or application-impersonation change

**Origin:** Repository-authored defensive hunt based on APT29 cloud collection cases.

**Telemetry:** Microsoft 365 Unified Audit Log / Exchange audit.

**Review / tuning:** Mail administrators perform similar changes. Confirm actor, target and approved request.

```spl
index=o365 sourcetype="o365:management:activity" earliest=-30d Workload="Exchange" Operation IN ("Add-MailboxPermission","Set-Mailbox","New-ManagementRoleAssignment","Set-CASMailbox")
| search Parameters IN ("*ApplicationImpersonation*","*FullAccess*","*Mail.Read*","*ActiveSyncAllowedDeviceIDs*")
| table _time UserId ClientIP Operation ObjectId Parameters ResultStatus ExternalAccess
```

## 2. Active Directory and Network Discovery

### 2.1 H07 — AD, federation and Exchange discovery burst

**Origin:** Repository-authored defensive hunt based on SolarWinds and credential-roaming cases.

**Telemetry:** Sysmon Event ID 1 or normalized EDR process events.

**Review / tuning:** Identity administrators and assessment tools can match. Three distinct discovery terms in 15 minutes is a local threshold.

```spl
index=endpoint earliest=-14d (process="*Get-ADUser*" OR process="*Get-ADGroupMember*" OR process="*Get-AcceptedDomain*" OR process="*Get-MsolDomainFederationSettings*" OR process="*adfind*" OR process="*dsquery*" OR process="*nltest*")
| eval term=case(match(process,"Get-ADUser"),"Get-ADUser",match(process,"Get-ADGroupMember"),"Get-ADGroupMember",match(process,"Get-AcceptedDomain"),"Get-AcceptedDomain",match(process,"Get-MsolDomainFederationSettings"),"Federation",true(),lower(process_name))
| bin _time span=15m
| stats dc(term) as distinct_terms values(term) as terms values(process) as commands count by host user _time
| where distinct_terms>=3
```

## 3. Persistence and Remote Administration

### 3.1 H08 — Suspicious RDP attachment or RDP client launch from user content

**Origin:** Repository-authored defensive hunt based on the October 2024 campaign.

**Telemetry:** Email attachment logs and endpoint process creation.

**Review / tuning:** Legitimate RDP administration is common. Inspect sender, destination and redirection settings.

```spl
(index=email earliest=-30d attachment_name="*.rdp") OR (index=endpoint earliest=-30d process_name="mstsc.exe" process="*.rdp*")
| eval evidence=coalesce(attachment_name,process), identity=coalesce(recipient,user)
| table _time host identity src sender parent_process process_name evidence file_hash
```

### 3.2 H09 — CornFlake executable path

**Origin:** Microsoft-published hunt translated to representative Splunk fields.

**Telemetry:** EDR/Sysmon process creation.

**Review / tuning:** Validate exact path, hash and related persistence.

```spl
index=endpoint earliest=-30d process_name="svchost32.exe" file_path="*\\svchost32\\svchost32.exe"
| table _time host user process_name file_path file_hash process parent_process parent_process_path
```

### 3.3 H10 — CornFlake service registration bundle

**Origin:** Microsoft-published CaptiveCrunch hunt translated to Splunk.

**Telemetry:** Sysmon Event ID 13, Windows service events or EDR registry data.

**Review / tuning:** Require the service key and published display/description values; correlate image path and hash.

```spl
index=endpoint earliest=-30d registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\svchost32*" (registry_value_data="Cloud Sync Service" OR registry_value_data="Synchronizes files with the cloud storage provider")
| table _time host user registry_path registry_value_name registry_value_data process_name process parent_process
```

### 3.4 H11 — Unexpected FoggyWeb files on AD FS servers

**Origin:** Repository-authored defensive hunt based on Microsoft FoggyWeb analysis.

**Telemetry:** File creation/modify events; scope to federation servers.

**Review / tuning:** Validate signer, hash, host role and baseline because names mimic Windows resources.

```spl
index=endpoint earliest=-30d (file_path="*\\ADFS\\version.dll" OR file_path="*\\SystemResources\\Windows.Data.TimeZones\\pris\\Windows.Data.TimeZones.zh-PH.pri")
| table _time host user action file_name file_path file_hash process_name process parent_process
```

### 3.5 H12 — MAGICWEB DLL or AD FS configuration change

**Origin:** Repository-authored defensive hunt based on Microsoft MAGICWEB analysis.

**Telemetry:** File and registry change events on AD FS servers.

**Review / tuning:** Confirm GAC/signature provenance and authorized maintenance.

```spl
index=endpoint earliest=-30d (file_name="Microsoft.IdentityServer.Diagnostics.dll" OR file_path="*\\Microsoft.IdentityServer.Servicehost.exe.config" OR (registry_path="*ADFS*" registry_value_data="*Microsoft.IdentityServer.Diagnostics*"))
| table _time host user action file_name file_path file_hash registry_path registry_value_data process_name process
```

### 3.6 H13 — WINELOADER certutil and tar staging sequence

**Origin:** Repository-authored defensive hunt based on Mandiant's ROOTSAW script.

**Telemetry:** Process creation.

**Review / tuning:** Require the Windows Tasks path and sequence; generic certutil/tar use is not enough.

```spl
index=endpoint earliest=-30d ((process_name="certutil.exe" process="*-decode*\\Windows\\Tasks\\invite.txt*\\Windows\\Tasks\\invite.zip*") OR (process_name="tar.exe" process="*-xf*\\Windows\\Tasks\\invite.zip*") OR (process_name="SqlDumper.exe" file_path="C:\\Windows\\Tasks\\*"))
| sort 0 host _time
| table _time host user process_name file_path file_hash process parent_process parent_process_path
```

## 4. Tunneling and C2

### 4.1 H14 — WINELOADER DLL loaded by SqlDumper from staging path

**Origin:** Repository-authored defensive hunt based on Mandiant WINELOADER analysis.

**Telemetry:** Sysmon Event ID 7 or EDR image-load data.

**Review / tuning:** `SqlDumper.exe` is legitimate. Validate adjacent DLL signature and path.

```spl
index=endpoint earliest=-30d event_id=7 process_name="SqlDumper.exe" image_loaded="*\\vcruntime140.dll" (image_loaded="*\\Windows\\Tasks\\*" OR image_loaded="*\\Users\\*" OR image_loaded="*\\ProgramData\\*")
| table _time host user process_name process_path image_loaded file_hash signature signed
```

### 4.2 H15 — CaptiveCrunch network indicators

**Origin:** Microsoft-published CaptiveCrunch hunt translated to Splunk.

**Telemetry:** Proxy, DNS, firewall or EDR network events.

**Review / tuning:** Indicators are dated. Confirm process, TLS, URI and travel/captive-portal context.

```spl
index=network earliest=-90d (dest_domain IN ("ms365-device.com","ms365-live.com","m365-owa.com","owa-ms365.com") OR dest IN ("31.57.243.154","38.146.28.75","38.146.28.132","104.194.159.150","107.189.26.194","213.145.86.112"))
| table _time src dest dest_port dest_domain url host user process_name process
```

## 5. Defense Evasion and Impairment

### 5.1 H16 — Audit policy or PowerShell logging impairment

**Origin:** Repository-authored defensive hunt based on SolarWinds-era defense evasion.

**Telemetry:** Process creation.

**Review / tuning:** Validate change tickets and surrounding behavior.

```spl
index=endpoint earliest=-14d ((process_name="auditpol.exe" (process="*/clear*" OR process="*/set*" OR process="*disable*")) OR (process_name IN ("powershell.exe","pwsh.exe") (process="*ScriptBlockLogging*" OR process="*ModuleLogging*" OR process="*Disable-AzContextAutosave*")))
| table _time host user process_name process parent_process parent_process_path
```

## 6. Collection and Exfiltration

### 6.1 H17 — Unusual high-volume mailbox access by an application

**Origin:** Repository-authored defensive hunt based on Graph/EWS email collection.

**Telemetry:** Microsoft 365 Unified Audit Log.

**Review / tuning:** eDiscovery, backup and security applications can match. Baseline application and mailbox scope.

```spl
index=o365 sourcetype="o365:management:activity" earliest=-30d Workload="Exchange" Operation IN ("MailItemsAccessed","SearchQueryInitiatedExchange","New-MailboxExportRequest","Get-MailboxExportRequest")
| bin _time span=30m
| stats count as events dc(ObjectId) as mailboxes values(ObjectId) as objects values(Operation) as operations by UserId ClientIP _time
| where events>=100 OR mailboxes>=5
```

## 9. Multi-Stage Correlation

### 9.1 H18 — Suspicious device-code sign-in followed by cloud persistence

**Origin:** Repository-authored correlation based on Storm-2372 and NOBELIUM cloud procedures.

**Telemetry:** Entra sign-in and audit events.

**Review / tuning:** Four-hour transaction window is a triage threshold; compare initiator and IP.

```spl
index=identity earliest=-30d ((sourcetype="azure:monitor:aad" (authenticationProtocol="deviceCode" OR clientAppUsed="*Device Code*") (resultType="0" OR result="success")) OR (sourcetype="azure:aad:audit" operation IN ("Add device","Consent to application","Add delegated permission grant","Add app role assignment","Update service principal","Add service principal credentials")))
| transaction user maxspan=4h startswith=eval(authenticationProtocol="deviceCode" OR like(clientAppUsed,"%Device Code%")) endswith=eval(isnotnull(operation))
| table _time duration user src app operation targetResources correlationId
```

## 10. Campaign Artifact Hunts

### 10.1 H19 — Retained APT29 sample hashes

**Origin:** Repository-authored exact match from the source-verified IOC corpus.

**Telemetry:** Endpoint file, process and image-load hash events.

**Review / tuning:** Exact match identifies a retained artifact; preserve file and chronology.

```spl
index=endpoint earliest=-365d file_hash IN ("918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593","be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c","2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41","8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8","83014ab5b3f63b0253cdab6d715f5988ac9014570fa4ab2b267c7cf9ba237d18","0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494","70d93035b0693b0e4ef65eb7f8529e6385d698759cc5b8666a394b2136cc06eb","0e1f9d4d0884c68ec25dec355140ea1bab434f5ea0f86f2aade34178ff3a7d91","247a733048b6d5361162957f53910ad6653cdef128eb5c87c46f14e7e3e46983","0affab34d950321e3031864ec2b6c00e4edafb54f4b327717cb5b042c38a33c9","7e05ff08e32a64da75ec48b5e738181afb3e24a9f1da7f5514c5a11bb067cbfb","acc74c920d19ea0a5e6007f929ef30b079eb2836b5b28e5ffcc20e68fa707e66","653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358","420d20cddfaada4e96824a9184ac695800764961bad7654a6a6c3fe9b1b74b9a","85484716a369b0bc2391b5f20cf11e4bd65497a34e7a275532b729573d6ef15e","78a810e47e288a6aff7ffbaf1f20144d2b317a1618bba840d42405cddc4cff41","d931078b63d94726d4be5dc1a00324275b53b935b77d3eed1712461f0c180164","24c079b24851a5cc8f61565176bbf1157b9d5559c642e31139ab8d76bbb320f8","adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8")
| table _time host user action file_name file_path file_hash process_name process parent_process
```

### 10.2 H20 — ChocoShell-style VSS access for locked browser data

**Origin:** Repository-authored defensive hunt based on Microsoft CaptiveCrunch analysis.

**Telemetry:** Process creation and PowerShell logging.

**Review / tuning:** Backup and forensics can match. Classify as credential collection unless destructive recovery impact is separately demonstrated.

```spl
index=endpoint earliest=-30d process_name IN ("powershell.exe","pwsh.exe","wmic.exe") (process="*Win32_ShadowCopy*" OR process="*shadowcopy*" OR process="*GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*") (process="*Login Data*" OR process="*Cookies*" OR process="*Local State*" OR process="*User Data*" OR process="*Web Data*")
| table _time host user process_name process parent_process parent_process_path
```

### 10.3 H21 — Suspicious process launched by a Windows TeamCity server

**Origin:** Repository-authored defensive hunt based on joint government reporting of CVE-2023-42793 exploitation.

**Telemetry:** EDR/Sysmon process creation; scope to known TeamCity servers.

**Review / tuning:** Build steps can legitimately launch shells and utilities. Require an unexpected build context, account, command, network destination or persistence follow-on before escalation.

```spl
index=endpoint earliest=-30d parent_process_name IN ("java.exe","javaw.exe") (parent_process_path="*TeamCity*" OR parent_process="*teamcity*") process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","wmic.exe","net.exe","net1.exe","whoami.exe","certutil.exe")
| table _time host user process_name process_path file_hash process parent_process_name parent_process_path parent_process
```

### 10.4 H22 — Anthropic GTG-20006 published indicators

**Origin:** Repository-authored exact-indicator hunt using Anthropic's September 2026 public corpus.

**Telemetry:** Network, endpoint/file and email security indexes using representative fields.

**Review / tuning:** The campaign attribution is qualified and infrastructure can age or be reassigned. Preserve the matched artifact, signer, parent process, URL, message headers and adjacent identity activity.

```spl
(index=network earliest=-180d (dest_domain IN ("ms365-live.com","teams.ms365-live.com","m365-owa.com","owa-ms365.com","ms365-device.com","mslivetest.duckdns.org","my-invite.org","chamber-ua.org","chathamhouse.eu","ukrinform-share.net","statistic-ms.live","static-ms.live","ad-g.org","docs-viewer.org","wa-connect.eu","mygreatmarket.org","mygreatmarket.com","cdncounter.net","static.cdncounter.net","stuseamandesilt.org","api.stuseamandesilt.org","cdn.stuseamandesilt.org","update.stuseamandesilt.org","itechx.tel","pdfviewer2024.b-cdn.net","meridian-protocol.org","meridiangroup-corp.com","projectnightcrawler.dev","metricwave.org","mgsend.org","wa-meeting.com","russianearabroad.com","russianearabroad.org","russianearabroad.net") OR dest IN ("104.145.210.184","31.57.243.154","104.194.151.133","104.194.159.55","144.172.114.192","213.145.86.112","2.26.53.194","148.135.195.111","185.198.234.26","185.198.234.101","149.54.42.106","104.194.149.228","38.146.28.132","38.146.28.75"))) OR (index=endpoint earliest=-180d file_name IN ("msedgeupdate_v3.exe","msedgeupdate.exe","version.dll","WUEngine.exe","DiagHost.exe","client_20260507093021_4286d211_x64.exe","fix_network.apk")) OR (index=email earliest=-180d sender IN ("anna.manager@russianearabroad.net","events@embassy-protocol.int"))
| eval evidence=coalesce(dest_domain,dest,file_path,file_name,sender)
| table _time host user evidence dest dest_domain url file_name file_path file_hash process_name process parent_process sender recipient subject
```

### 10.5 H23 — AWS watering-hole indicators

**Origin:** Repository-authored exact-indicator hunt from AWS's 2025 disruption report.

**Telemetry:** DNS, proxy, firewall or EDR network events.

**Review / tuning:** A match establishes contact with dated infrastructure, not successful device authorization. Preserve URL, referrer, user agent and process.

```spl
index=network earliest=-365d dest_domain IN ("findcloudflare.com","cloudflare.redirectpartners.com")
| table _time host user src dest dest_port dest_domain url http_referrer user_agent process_name process
```

### 10.6 H24 — GRAPELOADER persistence bundle

**Origin:** Repository-authored behavioral hunt from Check Point's 2025 GRAPELOADER analysis.

**Telemetry:** EDR/Sysmon file and registry events.

**Review / tuning:** `wine.exe` is legitimate. Require the `POWERPNT` directory or Run value, adjacent DLLs, exact hashes, or campaign network evidence.

```spl
index=endpoint earliest=-90d ((file_path="*\POWERPNT\*" file_name IN ("wine.exe","AppvIsvSubsystems64.dll","ppcore.dll")) OR (registry_path="*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*" registry_value_name="POWERPNT" registry_value_data="*\POWERPNT\wine.exe*"))
| eval evidence=coalesce(file_path,registry_path."\\".registry_value_name."=".registry_value_data)
| table _time host user action evidence file_name file_hash registry_path registry_value_name registry_value_data process_name process parent_process
```

### 10.7 H25 — Cross-tenant delegated administration

**Origin:** Repository-authored hunt based on Microsoft's NOBELIUM service-provider campaign.

**Telemetry:** Normalized Entra sign-in data with home/resource tenant and cross-tenant type.

**Review / tuning:** Approved MSP and B2B access is common. Baseline authorized partner tenants, applications, accounts and customer scope.

```spl
index=identity earliest=-30d sourcetype="azure:monitor:aad" (resultType="0" OR result="success") homeTenantId=* resourceTenantId=*
| where homeTenantId!=resourceTenantId
| bin _time span=1h
| stats count as events values(src) as source_ips values(appDisplayName) as apps values(crossTenantAccessType) as access_types by user homeTenantId resourceTenantId _time
| where events>=3
```

### 10.8 H26 — Azure Run Command after cloud sign-in

**Origin:** Repository-authored correlation based on Microsoft's Run Command plus admin-on-behalf-of pivot.

**Telemetry:** Azure activity and Entra sign-in events.

**Review / tuning:** Automation and incident response use Run Command legitimately. Validate caller, VM, command contents, ticket and source IP.

```spl
(index=azure earliest=-30d operationNameValue="*Microsoft.Compute/virtualMachines/runCommand/action*" activityStatusValue="Success") OR (index=identity earliest=-30d sourcetype="azure:monitor:aad" (resultType="0" OR result="success"))
| eval identity=coalesce(caller,user), event_type=if(like(operationNameValue,"%runCommand/action%"),"RunCommand","Signin")
| transaction identity maxspan=4h startswith=eval(event_type="Signin") endswith=eval(event_type="RunCommand")
| table _time duration identity src callerIpAddress operationNameValue subscriptionId resourceGroup resourceId correlationId
```

### 10.9 H27 — Qualified UNC6293 / UNC7005 published indicators

**Origin:** Repository-authored exact-indicator hunt from Google's 2025–2026 reporting.

**Telemetry:** Network and endpoint/file events with normalized domains, IPs and SHA-256.

**Review / tuning:** Google assigns a moderate-confidence ICE RELIC initial-access relationship. Commodity stealer and landing-page matches remain campaign evidence; UNC5976/HEADRUSH indicators are excluded.

```spl
(index=network earliest=-365d (dest_domain IN ("rediruri.app","dosportal.app","foreignrelations.us","fewfwfwfwfwf.info","miov2iaiaoubqosiqoiajwowiwjso.online","mioisiskwowiwjowuwjwolab.club","chamber-ua.org","wa-connect.eu","wa-connect.net","wa-invite.com","wa-device.com","wa-meeting.com","shopinvite.org","my-invite.org","globsec.net","statistic-ms.live","owa-ms365.com","m365-owa.com","ms365-device.com","ms365-live.com","finishoperations.com","finishoperations.org","foc-share.com","share-foc.com","internal-share.com","foc-share.org") OR dest IN ("91.190.191.117","107.189.18.7","196.251.107.171","31.57.243.154","38.146.28.75","104.194.159.150"))) OR (index=endpoint earliest=-365d file_hash IN ("329fda9939930e504f47d30834d769b30ebeaced7d73f3c1aadd0e48320d6b39","5b8d50c2e8cc3038b7c6e6dbf1219f6e814930a1e3c0053143a1191ae67f8ffc","a06a8fd1b6fa1924199a4540cf16d089217ce8f78c617739946f145fd1fc88c1","1d9299799a7b8da67c44ebec064d64542c27645f8e84de4a22ca3f6cbc843e3c","c5826032207d623a7f6caec8465af7364eccc355f9a48897da2a54f3e4420265","125752ad7c20d715920a3b2fb0fdde660f07b3f2b053665cf38c2d6d9de86e1e","403b624e35777cbc07dbe66398b21bba70396a20b859c880732338ce1dd1f41f","28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3","be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c","1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916","6f7090895c1c3dee30de6b3f098ca3a788dc198646e5293a8b1210430b0add97","20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38","ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25"))
| eval evidence=coalesce(dest_domain,dest,file_path,file_name,file_hash)
| table _time host user evidence dest dest_domain url file_name file_path file_hash process_name process parent_process
```

### 10.10 H28 — WINELOADER Windows 7 / Edge 119 user agent

**Origin:** Repository-authored network hunt from Check Point's 2025 WINELOADER analysis.

**Telemetry:** Web proxy or secure web gateway logs with user-agent visibility.

**Review / tuning:** The impossible OS/browser combination may be copied. Correlate destination, TLS, process, host and exact sample evidence.

```spl
index=network earliest=-90d user_agent="*Windows NT 6.1; Win64; x64*" user_agent="*Edg/119.0.2151.25*"
| table _time host user src dest dest_port dest_domain url user_agent process_name process
```
