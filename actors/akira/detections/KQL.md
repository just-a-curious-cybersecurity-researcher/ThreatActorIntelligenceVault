# Akira — Microsoft Defender XDR / KQL Hunting Queries

**Presentation reviewed:** 2026-09-15.

**Status:** defensive hunts requiring local validation and tuning; not actor-attribution signatures. Query execution against a connected backend has not been validated.

## Scope and Requirements

These queries are designed as **hunting and detection starting points** for Microsoft Defender XDR Advanced Hunting. They are not intended to be copied into production without review and tuning.

> **Environment-specific tuning is mandatory.** Many Akira-associated utilities are legitimate. AnyDesk, TeamViewer, Rclone, WinSCP, PowerShell, `nltest`, `net.exe`, PsExec and similar tools can be normal in some organizations. Review approved software, admin accounts, jump hosts, software-distribution servers, backup systems, red-team activity and other expected usage before turning these hunts into alerts.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 6 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 2. Active Directory and Network Discovery | 5 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 3. Persistence and Remote Administration | 3 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 4. Tunneling and C2 | 3 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 5. Defense Evasion and Impairment | 5 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 6. Collection and Exfiltration | 3 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 7. Recovery Inhibition | 2 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 8. Deployment and Impact | 4 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 9. Multi-Stage Correlation | 1 query | Review the telemetry and tuning notes on each entry; correlate with incident context |
| 10. Campaign Artifact Hunts | 6 queries | Review the telemetry and tuning notes on each entry; correlate with incident context |

## Interpretation Notes

This register applies to **every numbered query** in this file. These are hunts; no KQL/SPL backend was available for execution. Source attribution describes campaign evidence, not rule specificity. The [current ATT&CK table](../technical/mitre-attack.md) contains supported mappings.

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1.x credential access |  | DFIR, backup exports and authorized assessments match. MiniDump typically receives a **numeric PID**, so no literal `lsass` requirement; verify the target PID and output. Command strings do not prove the dump succeeded. |
| 2.x discovery |  | Inventory, vulnerability scanning and helpdesk activity match. Connection fan-out may be an application server; `dcount` is approximate and thresholds are starting values. |
| 3.x RMM/C2 |  | Authorized support is common; frequency is not authorization. SystemBC-like filenames are low-confidence heuristics, not family signatures. |
| 4.x tunnels |  | Developers, VPNs and remote administrators match. SSH uppercase forwarding flags differ from lowercase `-l` login name. Correlate listener/destination and process identity. |
| 5.x impairment / DLL |  | Troubleshooting/updates can match. A DLL in a writable directory is not proof of side-loading or a signed loader. Collect image loads and verify the **created** process's signer separately from its parent. |
| 6.x archive / transfer |  | Backups, data engineering and routine transfers match. Tool execution is not proof of theft. Fixed buckets are co-occurrence and can miss boundary-spanning activity; ordered examples state their interval explicitly. |
| 7.x recovery inhibition |  | Authorized maintenance can delete shadows. Verify the executing identity, target scope, backups affected and subsequent impact. |
| 8.x deployment / impact |  | PsExec is dual-use. Note/extension matches also occur in research folders and restores; `.arika` is verified in note text, not independently as emitted extension. Generic `fn.txt` is intentionally omitted from standalone alerts. |
| 9.x multi-stage | Same sources above | Co-occurrence within the lookback is not temporal ordering or actor attribution. Category assignment can select the first matching category only. Baseline admin/IR automation. |
| 10.x campaign-specific | Source and telemetry stated per query | Each query has its own review note; adapt time, thresholds and missing-field behavior. |

For MDE, enable each required sensor/table and preserve process IDs plus creation time or unique IDs in pivots; PID reuse and empty SHA256 are normal limitations. For Splunk, select an explicit time range and configure Sysmon Events 1, 3, 7, 11, 13 as required; image-load events are not collected by every deployment. Windows Security/System queries use their own channels. Exclusions should combine owner, signer/hash, path, purpose and time rather than blanket allowlisting a tool name.



## 1. Credential Access

### 1.1 LSASS dump through `comsvcs.dll` MiniDump

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** legitimate troubleshooting is possible but uncommon. Prioritize interactive users, unusual paths, remote sessions and subsequent archive/lateral-movement activity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine contains "comsvcs.dll" and ProcessCommandLine contains "MiniDump"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### 1.2 Known credential-dumping tooling

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** filenames can be renamed and strings may appear in security tooling. Use prevalence and signer/path context.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any (
    "mimikatz", "lazagne", "donpapi", "netexec", "crackmapexec",
    "veeamhax", "ticketdumper"
)
   or ProcessCommandLine has_any (
    "sekurlsa::", "lsadump::", "kerberos::", "DonPAPI", "LaZagne",
    "Veeam-Get-Creds", "SharpDomainSpray"
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 1.3 SAM / SECURITY / SYSTEM hive dumping

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** registry backup and forensic workflows may legitimately export these hives.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("reg.exe", "regedit.exe")
| where ProcessCommandLine has "save"
| where ProcessCommandLine has_any ("HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM", "HKEY_LOCAL_MACHINE\\SAM", "HKEY_LOCAL_MACHINE\\SECURITY", "HKEY_LOCAL_MACHINE\\SYSTEM")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 1.4 NTDS.dit / domain credential database access

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** domain-controller maintenance and backup products can generate related activity. Restrict or baseline expected DC administration.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("ntds.dit", "ntdsutil", "IFM", "create full")
   or (FileName =~ "esentutl.exe" and ProcessCommandLine has "ntds")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 1.5 Browser credential-store copying with `esentutl.exe`

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "esentutl.exe"
| where ProcessCommandLine has_any ("Login Data", "key4.db", "logins.json", "Cookies")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 1.6 Credential-access activity concentrated on one host

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
let CredentialTools = dynamic(["mimikatz", "lazagne", "donpapi", "netexec", "veeamhax", "ticketdumper"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| extend Cmd = tolower(ProcessCommandLine), Proc = tolower(FileName)
| where Proc has_any (CredentialTools)
    or Cmd has_any ("comsvcs.dll", "minidump", "ntds.dit", "hklm\\sam", "sekurlsa::", "veeam-get-creds")
| summarize Events=count, Tools=make_set(FileName), Commands=make_set(ProcessCommandLine, 20),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, AccountName
| order by Events desc
```

## 2. Active Directory and Network Discovery

### 2.1 Multiple AD/share discovery tools on one system

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** this is deliberately a correlation rule. It is higher-signal but may miss single-tool use.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName has_any ("sharphound", "bloodhound", "adfind", "ldapdomaindump", "sharpshares", "snaffler")
   or ProcessCommandLine has_any ("Invoke-ShareFinder", "ldapdomaindump", "SharpHound", "BloodHound", "AdFind")
| summarize ToolsSeen=make_set(FileName), Commands=make_set(ProcessCommandLine, 20),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, AccountName
| where array_length(ToolsSeen) >= 2
```

### 2.2 Atomic SharpHound / BloodHound / AdFind / LDAP discovery

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("sharphound", "bloodhound", "adfind", "ldapdomaindump")
   or ProcessCommandLine has_any ("SharpHound", "BloodHound", "AdFind", "ldapdomaindump")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 2.3 Native domain discovery (`nltest`, `net group`, `net localgroup`)

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** these are legitimate administrative commands. Alerting solely on them can be noisy. Higher-value conditions include unusual workstations, non-admin users, execution immediately after suspicious remote access, or several discovery commands in a short period.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where
    (FileName =~ "nltest.exe" and ProcessCommandLine has_any ("/dclist", "/domain_trusts"))
    or (FileName =~ "net.exe" and ProcessCommandLine has_all ("group", "domain admins"))
    or (FileName =~ "net.exe" and ProcessCommandLine has_all ("localgroup", "administrators"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.4 Network scanning tools

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("advanced_ip_scanner", "advanced port scanner", "netscan", "masscan", "softperfect")
   or ProcessCommandLine has_any ("Advanced IP Scanner", "SoftPerfect", "masscan", "netscan.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 2.5 Burst of outbound internal connections from one endpoint

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents.

**Review / tuning:** vulnerability scanners, management platforms and IT discovery systems commonly trigger this pattern. Maintain allowlists for sanctioned scanners.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Private"
| summarize DistinctHosts=dcount(RemoteIP), DistinctPorts=dcount(RemotePort),
            RemoteHosts=make_set(RemoteIP, 50), Ports=make_set(RemotePort, 30)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where DistinctHosts >= 25 or DistinctPorts >= 20
| order by DistinctHosts desc
```

## 3. Persistence and Remote Administration

### 3.1 Execution of Akira-associated RMM products

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** these products are frequently legitimate. The most useful approach is often **approved-vs-unapproved RMM**, not simply "RMM = malicious".

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any (
    "anydesk", "rustdesk", "radmin", "teamviewer", "logmein",
    "screenconnect", "meshagent", "level"
)
   or ProcessCommandLine has_any (
    "AnyDesk", "RustDesk", "Radmin", "TeamViewer", "LogMeIn",
    "ScreenConnect", "MeshAgent", "Level.io"
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 3.2 Rare RMM execution in the environment

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
let RMM = dynamic(["anydesk.exe", "rustdesk.exe", "radmin.exe", "teamviewer.exe", "meshagent.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (RMM)
| summarize Hosts=dcount(DeviceName), Users=dcount(AccountName), Executions=count,
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by FileName, SHA256
| where Hosts <= 3
| order by Executions asc
```

### 3.3 SystemBC / suspicious proxy-RAT artifact names

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("systembc") or ProcessCommandLine has "SystemBC"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

## 4. Tunneling and C2

### 4.1 Ngrok or Cloudflared execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ngrok.exe", "cloudflared.exe", "ngrok", "cloudflared")
   or ProcessCommandLine has_any ("ngrok tcp", "ngrok http", "cloudflared tunnel", "cloudflare tunnel")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 4.2 SSH port forwarding

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ssh.exe", "plink.exe", "putty.exe")
| where ProcessCommandLine matches regex @"(^|\s)-[LRD](?:\s+|[0-9*:])"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 4.3 Rare tunneling binaries with network activity

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceNetworkEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
let TunnelBins = dynamic(["ngrok.exe", "cloudflared.exe", "plink.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (TunnelBins)
| summarize Connections=count, Destinations=make_set(RemoteUrl, 20),
            IPs=make_set(RemoteIP, 20), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessSHA256
| order by Connections desc
```

## 5. Defense Evasion and Impairment

### 5.1 Defender / AV disabling commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "Set-MpPreference", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
    "sc stop WinDefend", "sc config WinDefend", "net stop WinDefend"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.2 Firewall disabling/modification

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "netsh.exe" and ProcessCommandLine has_all ("advfirewall", "state", "off"))
   or ProcessCommandLine has_any ("Set-NetFirewallProfile", "Disable-NetFirewallRule")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
```

### 5.3 Safe Mode abuse

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Safe Mode is legitimate during troubleshooting. Prioritize remote sessions, non-IT accounts and execution after security-tool tampering.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bcdedit.exe"
| where ProcessCommandLine has "safeboot" and ProcessCommandLine contains "/set"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.4 Known Akira-associated defense-evasion tooling

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("powertool", "poortry", "stonestop", "killav", "heartcrypt")
   or ProcessCommandLine has_any ("PowerTool", "POORTRY", "STONESTOP", "KillAV", "HeartCrypt")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 5.5 Suspicious DLL side-loading through signed binaries

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceImageLoadEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("consent.exe", "icardagt.exe", "mfpmp.exe")
| where FileName in~ ("msimg32.dll", "wmsgapi.dll", "version.dll", "rtworkq.dll")
| where FolderPath !startswith @"C:\Windows\System32"
  and FolderPath !startswith @"C:\Windows\SysWOW64"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, SideloadedDll=FileName,
          FolderPath, InitiatingProcessAccountName, SHA256
```

## 6. Collection and Exfiltration

### 6.1 Exfiltration utilities

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("rclone", "winscp", "filezilla", "pscp", "mega")
   or ProcessCommandLine has_any ("rclone copy", "rclone sync", "winscp.com", "pscp.exe", "temp.sh")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 6.2 Archive utilities with potentially suspicious command lines

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** backup, packaging and development workflows may legitimately create archives. Correlate with unusual data locations and outbound transfer.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("rar.exe", "winrar.exe", "7z.exe", "7za.exe")
| where ProcessCommandLine has_any (" a ", " -p", " -v", " -mx", " -mhe", "\\Users\\", "\\Temp\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 6.3 Archive followed by transfer utility on same device/account

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
let Archives = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("rar.exe", "winrar.exe", "7z.exe", "7za.exe")
| where isnotempty(AccountSid)
| project DeviceId, AccountSid, DeviceName, AccountName, ArchiveTime=Timestamp, ArchiveProcess=FileName, ArchiveCmd=ProcessCommandLine;
let Exfil = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName has_any ("rclone", "winscp", "filezilla", "pscp", "s5cmd")
| where isnotempty(AccountSid)
| project DeviceId, AccountSid, ExfilTime=Timestamp, ExfilProcess=FileName, ExfilCmd=ProcessCommandLine;
Archives
| join kind=inner Exfil on DeviceId, AccountSid
| where ExfilTime between (ArchiveTime.. ArchiveTime + 2h)
| project DeviceName, AccountName, ArchiveTime, ArchiveProcess, ArchiveCmd,
          ExfilTime, ExfilProcess, ExfilCmd
```

## 7. Recovery Inhibition

### 7.1 Shadow-copy deletion

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where
    (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete", "shadows"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy", "delete"))
    or ProcessCommandLine has_all ("Win32_Shadowcopy", "Remove-WmiObject")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 7.2 Recovery/boot configuration tampering

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bcdedit.exe"
| where ProcessCommandLine has_any ("recoveryenabled no", "bootstatuspolicy ignoreallfailures", "safeboot")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
```

## 8. Deployment and Impact

### 8.1 PsExec / PSEXESVC remote execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** PsExec is legitimate and widely used. Prioritize execution from unusual hosts/users, remote-service creation, lateral fan-out and proximity to ransomware artifacts.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe", "psexec64.exe", "psexesvc.exe")
   or ProcessCommandLine has_any ("PSEXESVC", "psexec.exe", "psexec64.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, SHA256
```

### 8.2 Akira-associated encrypted extensions

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName endswith ".akira"
    or FileName endswith ".arika"
    or FileName endswith ".powerranges"
    or FileName endswith ".akiranew"
    or FileName endswith ".aki"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
```

### 8.3 Akira ransom-note artifact

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("akira_readme.txt", "akira.readme.txt", "powerranges.txt", "akiranew.txt")
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
```

### 8.4 Fan-out of ransomware-like file creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceFileEvents.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName endswith ".akira"
    or FileName endswith ".arika"
    or FileName endswith ".powerranges"
    or FileName endswith ".akiranew"
    or FileName endswith ".aki"
| summarize Files=count, Paths=dcount(FolderPath),
            Examples=make_set(strcat(FolderPath, "\\", FileName), 20)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256,
       InitiatingProcessAccountName, bin(Timestamp, 5m)
| where Files >= 10
| order by Files desc
```

## 9. Multi-Stage Correlation

### 9.1 Multi-Stage Correlation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** This hunt assigns broad stages and identifies devices where several stages appear within the same day. Thresholds must be tuned to the environment.



**Use:** triage and threat hunting. This is intentionally broad and should not be used as a high-severity production alert without extensive tuning.

```kusto
let Proc = DeviceProcessEvents
| where Timestamp > ago(1d)
| extend Cmd=tolower(ProcessCommandLine), ProcName=tolower(FileName)
| extend Stage = case(
    Cmd has_any ("comsvcs.dll", "sekurlsa::", "ntds.dit", "hklm\\sam", "veeam-get-creds"), "CredentialAccess",
    Cmd has_any ("sharphound", "bloodhound", "adfind", "ldapdomaindump", "/domain_trusts", "domain admins"), "Discovery",
    ProcName has_any ("anydesk", "rustdesk", "teamviewer", "meshagent", "ngrok", "cloudflared"), "RemoteAccess_C2",
    Cmd has_any ("disablerealtimemonitoring", "advfirewall", "safeboot", "powertool", "poortry", "stonestop"), "DefenseEvasion",
    ProcName has_any ("rclone", "winscp", "filezilla", "pscp", "winrar", "7z"), "Collection_Exfil",
    Cmd has_all ("delete", "shadows") or Cmd has_all ("win32_shadowcopy", "remove-wmiobject"), "RecoveryInhibition",
    ProcName has_any ("psexec", "psexesvc"), "RemoteDeployment",
    "Other")
| where Stage != "Other"
| project Timestamp, DeviceName, AccountName, Stage, FileName, ProcessCommandLine;
Proc
| summarize Stages=make_set(Stage), Events=count, FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Examples=make_set(strcat(FileName, ":: ", ProcessCommandLine), 30)
    by DeviceName, AccountName
| extend StageCount=array_length(Stages)
| where StageCount >= 3
| order by StageCount desc, Events desc
```

## 10. Campaign Artifact Hunts

### 10.1 AnyDesk allowed in Safe Mode, followed by reboot tooling

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceRegistryEvents, DeviceProcessEvents.

**Review / tuning:** **Basis:** Huntress August 4, 2026 case. **Telemetry:** registry changes and process creation from MDE. **Review:** approved recovery work can produce the same sequence. `msconfig.exe` is a configuration clue, not proof a reboot occurred; verify Kernel-Boot/System events. A missing EDR event after reboot does not prove no encryption occurred.

```kusto
let SafeBoot = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\Control\SafeBoot\Network\AnyDesk"
| where RegistryValueData =~ "Service"
| project DeviceId, DeviceName, SetTime=Timestamp, RegistryKey,
          Setter=InitiatingProcessFileName, SetterCmd=InitiatingProcessCommandLine;
let BootTools = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("msconfig.exe", "shutdown.exe", "bcdedit.exe")
| project DeviceId, BootTime=Timestamp, FileName, ProcessCommandLine;
SafeBoot
| join kind=inner BootTools on DeviceId
| where BootTime between (SetTime.. SetTime + 1h)
| project DeviceName, SetTime, Setter, SetterCmd, BootTime, FileName, ProcessCommandLine
```

### 10.2 Bulk AD export files under ProgramData

**Origin:** Repository-authored defensive hunt.

**Telemetry:** file creation. **Review:** inventory scripts are a common false positive. Filenames are case insensitive, mutable and not sufficient attribution. Pivot to PowerShell script-block logging and the initiating account; an export may use methods absent from command-line telemetry.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath startswith @"C:\ProgramData\"
| where FileName in~ ("AdUsers.txt", "AdComp.txt")
| summarize Kinds=dcount(FileName), Files=make_set(FileName),
            Commands=make_set(InitiatingProcessCommandLine, 10)
    by DeviceId, DeviceName, InitiatingProcessAccountSid, bin(Timestamp, 30m)
| where Kinds == 2
```

### 10.3 s5cmd upload command with S3 destination

**Origin:** Repository-authored defensive hunt.

**Telemetry:** process command line; cloud audit/proxy bytes needed to confirm transfer. **Review:** exclude approved storage jobs by principal, executable provenance, bucket and schedule; a bucket name alone is weak. This is an execution hunt, not proof of upload completion. Shell wrappers/renamed executables can escape filename matching.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "s5cmd.exe" or ProcessVersionInfoOriginalFileName =~ "s5cmd.exe"
| where ProcessCommandLine contains "s3://"
| where ProcessCommandLine has_any ("cp", "sync", "run")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, SHA1, SHA256
```

### 10.4 Native WinRM and Impacket-like remote execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** DeviceProcessEvents.

**Review / tuning:** **Basis:** `wmiexec` in, Ruby WinRM in. **Telemetry:** endpoint process ancestry; network `/wsman` user-agent evidence is separately required for the Ruby client. **Review:** administrative WMI/WinRM is common. Prioritize new source hosts and remote identities. Parent names alone do not identify Impacket or Akira.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wsmprovhost.exe", "wmiprvse.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, ProcessId, InitiatingProcessId
```

### 10.5 ESX Admins group creation or membership activity

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Identity events in `IdentityDirectoryEvents`, **not endpoint-only MDE**. Confirm available ActionType values in the tenant. **Review:** an authorized ESX Admins group can be normal. Correlate creation/recreation with new members, domain-joined ESXi access and hypervisor version; this hunt does not itself prove CVE-2024-37085 exploitation.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where tostring(AdditionalFields) contains "ESX Admins"
| project Timestamp, ActionType, AccountName, AccountDomain,
          TargetAccountDisplayName, AdditionalFields
```

### 10.6 Credential extraction plus Veeam context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** process arguments; SQL/audit access needed for silent DB queries. **Review:** backup migration/support and security assessments can match. Do not confuse database reads with an unauthenticated exploit or assume every credential-access tool uses a CVE.

**Review / tuning:** Review approved administration, sensor coverage and the investigation context described in the coverage register.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine contains "Veeam-Get-Creds"
    or ProcessCommandLine contains "VeeamHax"
    or (ProcessCommandLine contains "Veeam" and ProcessCommandLine contains "Credentials"
        and FileName in~ ("powershell.exe", "pwsh.exe", "sqlcmd.exe"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
