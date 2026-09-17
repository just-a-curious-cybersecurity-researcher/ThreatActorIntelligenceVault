# The Gentlemen — KQL Hunting Queries

**Presentation reviewed:** 2026-09-17.

## Scope and Requirements

H01–H46 and H49–H54 require Defender for Endpoint advanced-hunting tables and collected event types. H47–H48 instead run in Microsoft Sentinel/Azure Monitor against forwarded ESXi Syslog records; they do not run in Defender XDR. Queries use explicit time bounds; SHA-256 is often unpopulated.

All entries are repository-authored defensive hunts. H01, H03 and H14 refine the supplied tracker queries; tool-inventory entries are further supported by the reviewed chat analysis. Tool mentions are not per-victim execution proof. They are not Microsoft-published rules or proof of actor identity.

## Coverage, Telemetry and Tuning Register

| Query family | Coverage | Review / tuning |
|---|---|---|
| 1. Credential Access | 3 queries | Read each query's telemetry and tuning notes |
| 2. Active Directory and Network Discovery | 9 queries | Read each query's telemetry and tuning notes |
| 3. Persistence and Remote Administration | 14 queries | Read each query's telemetry and tuning notes |
| 4. Tunneling and C2 | 4 queries | Read each query's telemetry and tuning notes |
| 5. Defense Evasion and Impairment | 9 queries | Read each query's telemetry and tuning notes |
| 6. Collection and Exfiltration | 3 queries | Read each query's telemetry and tuning notes |
| 7. Recovery Inhibition | 3 queries | Read each query's telemetry and tuning notes |
| 8. Deployment and Impact | 5 queries | Read each query's telemetry and tuning notes |
| 9. Multi-Stage Correlation | 2 queries | Read each query's telemetry and tuning notes |
| 10. Campaign Artifact Hunts | 2 queries | Read each query's telemetry and tuning notes |

## Interpretation Notes

Published procedures support the hypotheses; actual detection depends on your sensors. Allowed administration and security research can match. No connected Defender backend was used for runtime validation. Queries do not execute the attack commands they search for.

## 1. Credential Access

### 1.1 H01 — Authentication coercion and relay tool names

**Origin:** Repository-authored defensive hunt, adapted from the supplied tracker hypothesis.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Tool-inventory hypothesis from the supplied notes; authorized assessments match. A name does not establish successful relay or stolen credentials.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where ProcessCommandLine contains "PetitPotam" or ProcessCommandLine contains "ntlmrelayx" or ProcessCommandLine contains "Responder.py" or ProcessCommandLine contains "RelayKing"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 1.2 H15 — Credential-recovery tools from the shared inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Tool-name hypothesis from the supplied corpus and chat analysis. Validate binary identity and approval; renaming defeats this filter, and execution does not prove successful dumping.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (ProcessCommandLine contains "KslDump" or ProcessCommandLine contains "KslKatz" or ProcessCommandLine contains "DumpBrowserSecrets" or ProcessCommandLine contains "XenAllPasswordPro")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 1.3 H16 — NetExec invocation with credential-access options

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Local hypothesis combining a documented shared tool with credential-oriented options. Confirm tool version, arguments and the remote response; sanctioned assessments match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (((FileName =~ "nxc.exe" or FileName =~ "netexec.exe" or FileName =~ "nxc" or FileName =~ "netexec") or (ProcessCommandLine contains "netexec.py")) and (ProcessCommandLine contains "--sam" or ProcessCommandLine contains "--lsa" or ProcessCommandLine contains "--ntds"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 2. Active Directory and Network Discovery

### 2.1 H02 — Domain user and privileged-group enumeration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Compare with administrative baselines; repeated account queries and the initiating script strengthen relevance.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("net.exe", "net1.exe") and (ProcessCommandLine contains "/dom") and (ProcessCommandLine has "user" or ProcessCommandLine has "group")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.2 H03 — MANSPIDER share-crawler invocation

**Origin:** Repository-authored defensive hunt, adapted from the supplied tracker hypothesis.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Supplied inventory lead, not proof of observed execution in the 2025 case. Authorized security review can match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName contains "manspider" or ProcessCommandLine contains "manspider"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.3 H17 — Network scanners in endpoint process telemetry

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Approved network inventory and security assessments match. Compare executing account, scan targets and subsequent access; scan execution does not prove exploitation.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "advanced_ip_scanner.exe" or FileName =~ "nmap.exe" or FileName =~ "nmap" or FileName =~ "gogo.exe") or (ProcessCommandLine contains "nmap-7.97-setup.exe"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.4 H18 — Directory and cloud discovery tool inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Shared-inventory hypothesis. Inspect command parameters and process identity; a text reference or installation can match without collection.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (ProcessCommandLine contains "ADFind" or ProcessCommandLine contains "SharpHound" or ProcessCommandLine contains "BloodHound" or ProcessCommandLine contains "ldapdomaindump" or ProcessCommandLine contains "PowerZure")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.5 H19 — Certificate and privilege-path tooling

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Chat-documented tool inventory, not proof of certificate abuse or privilege escalation. Validate the executed module and resulting directory/service events.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (ProcessCommandLine contains "CertiHound" or ProcessCommandLine contains "PrivHound" or ProcessCommandLine contains "TaskHound" or ProcessCommandLine contains "RegPwn")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.6 H20 — Volume and cluster-storage enumeration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Cluster administrators and backup jobs commonly match. Retain parent process and following file activity; failures can simply indicate a non-cluster host.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "powershell.exe" or FileName =~ "pwsh.exe") and ((ProcessCommandLine contains "Get-ClusterSharedVolume") or ((ProcessCommandLine contains "Get-WmiObject" or ProcessCommandLine contains "Get-CimInstance") and (ProcessCommandLine contains "Win32_Volume"))))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.7 H21 — Network-discovery services and firewall group changes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Service starts and rule queries are not automatically malicious or successful. Inspect the operation and actual firewall value; localized group names need local adaptation.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (((FileName =~ "sc.exe" or FileName =~ "net.exe" or FileName =~ "net1.exe") and (ProcessCommandLine contains "fdrespub" or ProcessCommandLine contains "fdPHost" or ProcessCommandLine contains "SSDPSRV" or ProcessCommandLine contains "upnphost") and (ProcessCommandLine contains "start" or ProcessCommandLine contains "config")) or ((FileName =~ "netsh.exe") and (ProcessCommandLine contains "Network Discovery")))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.8 H50 — Primary-domain-controller discovery

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Includes fragments of the two published UTF-16LE encoded commands as well as decoded text. Encoding/spacing changes evade fragments; script-block logs provide better semantic coverage.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "powershell.exe" or FileName =~ "pwsh.exe" or FileName =~ "cmd.exe") and (((ProcessCommandLine contains "Get-ADDomain") and (ProcessCommandLine contains "PDCEmulator")) or (ProcessCommandLine contains "IAAoAEcAZQ" or ProcessCommandLine contains "IABHAGUAdAAtAEEARABEAG8AbQBhAGkAbg")))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 2.9 H52 — Native packet capture through netsh

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process creation with command lines.

**Review / tuning:** Native packet collection is documented by Kaspersky. Troubleshooting matches; validate the collector's account, output path and capture authorization. A start command does not prove credentials were captured.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where FileName =~ "netsh.exe"
| where ProcessCommandLine has_all ("trace","start") and ProcessCommandLine contains "capture=yes"
| project Timestamp, DeviceId, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## 3. Persistence and Remote Administration

### 3.1 H04 — Locker-related scheduled-task commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Generic UpdateSystem/UpdateUser/TaskSystem names need action-path and creator validation. Includes query/delete operations; inspect the verb.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName =~ "schtasks.exe" and (ProcessCommandLine contains "gentlemen_system" or ProcessCommandLine contains "UpdateSystem" or ProcessCommandLine contains "UpdateUser" or ProcessCommandLine contains "TaskSystem")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.2 H05 — Locker-associated autorun value writes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE registry events.

**Review / tuning:** GupdateS/GupdateU are sample-associated strings. Validate the destination image; this is a registry write, not proof of a later logon execution.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName in~ ("GupdateS", "GupdateU")
| project Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.3 H22 — Propagation-specific task names

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Short DefU/DefS strings can occur inside longer text. Verify exact task name, /S target, action and principal. Do not equate registration with execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "schtasks.exe") and (ProcessCommandLine contains "DefU" or ProcessCommandLine contains "DefS" or ProcessCommandLine contains "UpdateGU" or ProcessCommandLine contains "UpdateGU2" or ProcessCommandLine contains "UpdateGS" or ProcessCommandLine contains "UpdateGS2") and (ProcessCommandLine contains "/create" or ProcessCommandLine contains "/run"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.4 H23 — Propagation service creation and start commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Verify exact service name and ImagePath. Generic update services and incident-response recreations can match; collect destination service events.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "sc.exe") and (ProcessCommandLine contains "DefSvc" or ProcessCommandLine contains "UpdateSvc" or ProcessCommandLine contains "UpdateSvc2") and (ProcessCommandLine contains "create" or ProcessCommandLine contains "start"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.5 H24 — Payload paths written into propagation services

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE registry value writes.

**Review / tuning:** A value write is evidence of configuration, not service start. Inspect quoted ImagePath, remote-origin logon and service creation events.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d) and ActionType == "RegistryValueSet"
| where RegistryValueName =~ "ImagePath"
| where RegistryKey endswith @"\Services\DefSvc"
    or RegistryKey endswith @"\Services\UpdateSvc"
    or RegistryKey endswith @"\Services\UpdateSvc2"
| project Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.6 H25 — PsExec with staging or locker context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** PsExec is legitimate administration software. Hunt for unapproved target/account combinations; the presence of a password argument does not recover it or establish successful propagation.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "psexec.exe" or FileName =~ "psexec64.exe") and (ProcessCommandLine contains "C:\\Temp" or ProcessCommandLine contains "\\share$" or ProcessCommandLine contains "\\NETLOGON" or ProcessCommandLine contains "--password" or ProcessCommandLine contains "--spread"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.7 H26 — Remote WMI process creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Generic remote administration hunt. Link the command with target WmiPrvSE child processes and logons; local command success alone is insufficient.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "wmic.exe") and (ProcessCommandLine contains "/node:") and (ProcessCommandLine contains "process") and (ProcessCommandLine contains "create"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.8 H27 — PowerShell remoting or WMI with deployment context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Generic administrative automation can match. Script-block telemetry is needed for encoded or in-memory scripts; distinguish WinRM from WMI on the target.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "powershell.exe" or FileName =~ "pwsh.exe") and (ProcessCommandLine contains "Invoke-Command" or ProcessCommandLine contains "Win32_Process" or ProcessCommandLine contains "Invoke-WmiMethod") and (ProcessCommandLine contains "\\share$" or ProcessCommandLine contains "C:\\Temp" or ProcessCommandLine contains "--password" or ProcessCommandLine contains "Set-MpPreference"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.9 H28 — AnyDesk installation or persistent service setup

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Local persistence hypothesis for the documented RMM. Confirm approved software deployment, remote client identity and configuration; signed software can be authorized.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "AnyDesk.exe") and (ProcessCommandLine contains "--install" or ProcessCommandLine contains "--start-with-win" or ProcessCommandLine contains "--start"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.10 H42 — Hidden distribution share staging

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Require the actual net share operation and inspect resulting share permissions; quoted investigation text can match. share$ is a published artifact, not a uniquely malicious name.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "net.exe" or FileName =~ "net1.exe" or FileName =~ "cmd.exe" or FileName =~ "powershell.exe" or FileName =~ "pwsh.exe") and (ProcessCommandLine contains "share$") and (ProcessCommandLine contains "C:\\Temp") and (ProcessCommandLine contains "share"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.11 H48 — ESXi boot artifact and autostart changes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sentinel/Azure Monitor Syslog with forwarded ESXi command records; not Defender XDR.

**Review / tuning:** A log reference is not file-integrity proof. Inspect recovered boot/cron files and exact autostart verb/value. Queries and legitimate startup customization also match.

```kusto
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage contains "/bin/.vmware-authd"
    or (SyslogMessage contains "/etc/rc.local.d/local.sh" and SyslogMessage contains "sleep")
    or (SyslogMessage contains "vim-cmd" and SyslogMessage contains "autostartmanager")
| project TimeGenerated, Computer, HostName, ProcessName, SyslogMessage
```

### 3.12 H49 — Group Policy consoles with policy-editing context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Console execution alone does not prove a GPO change. Correlate directory auditing, SYSVOL/NETLOGON writes and subsequent client-side policy application.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "mmc.exe") and (ProcessCommandLine contains "gpmc.msc" or ProcessCommandLine contains "gpme.msc"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 3.13 H51 — PowerShell Web Access configuration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process creation with command lines.

**Review / tuning:** Group-IB documents this access configuration. Inspect the allowed users/computers, certificate, IIS exposure and approval; installation is not by itself malicious.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine contains "WindowsPowerShellWebAccess"
    or ProcessCommandLine contains "Install-PswaWebApplication"
    or ProcessCommandLine contains "Add-PswaAuthorizationRule"
| project Timestamp, DeviceId, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

### 3.14 H53 — Locker-associated GPO script and policy-task files

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE file events on hosts with visibility into SYSVOL/script writes.

**Review / tuning:** The script filename is published; ScheduledTasks.xml is also normal Group Policy content. Verify the task action, GPO change owner and directory audit trail. Sysmon creation/overwrite coverage is not all MDE modification coverage.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "deploy_gpo.ps1"
    or (FileName =~ "ScheduledTasks.xml" and FolderPath contains @"\SYSVOL\")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 4. Tunneling and C2

### 4.1 H06 — Historical affiliate C2 connections

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE network events; includes attempts where reported.

**Review / tuning:** Historical Check Point, Huntress and Kaspersky case IPs; revalidate ownership and the connection date. A match is not proof of a current SystemBC implant.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("91.107.247.163", "45.86.230.112", "193.233.202.17", "77.110.122.137", "81.177.215.15")
| project Timestamp, DeviceId, DeviceName, RemoteIP, RemotePort, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 4.2 H29 — Case-associated SystemBC file identity

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process/file hash fields; SHA-256 may be absent.

**Review / tuning:** Identifies the published companion sample, not every SystemBC version. SystemBC is shared across actors; file presence is not execution.

```kusto
union withsource=SourceTable DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 =~ "992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5"
| project Timestamp, DeviceId, DeviceName, SourceTable, ActionType, FileName, FolderPath, SHA256
```

### 4.3 H30 — Tunnel and proxy clients from the toolset

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Cloudflare and VPN software have legitimate uses. Review tunnel owner/configuration, destination, parent and change approval. Process names alone do not prove covert C2.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "cloudflared.exe" or FileName =~ "cloudflared" or FileName =~ "chisel.exe" or FileName =~ "chisel" or FileName =~ "chisel-ng.exe" or FileName =~ "openconnect.exe" or FileName =~ "openconnect" or FileName =~ "proxychains" or FileName =~ "proxychains4") or (ProcessCommandLine contains "chisel-ng"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 4.4 H54 — Disguised proxy and WindowsConnSvc task

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process creation with command lines.

**Review / tuning:** Huntress case artifacts; svchost32.exe is distinct from the normal svchost.exe name. The reported task also produced repeated failures. Confirm actual launch and network connection instead of assuming persistence succeeded.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (FileName =~ "svchost32.exe" and ProcessCommandLine contains "socks")
    or (FileName =~ "schtasks.exe" and ProcessCommandLine contains "WindowsConnSvc")
| project Timestamp, DeviceId, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## 5. Defense Evasion and Impairment

### 5.1 H07 — Case process killers and privileged launcher

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Generic names, legitimate PowerRun use and approved kavrmvr maintenance create false positives. Inspect hash, driver load and service events; filename match does not prove kernel impairment.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("All.exe", "Allpatch2.exe", "PowerRun.exe", "kavrmvr.exe")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.2 H08 — Defender preference impairment

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Approved maintenance and other malware match. Inspect argument values, protection outcomes and process ancestry; encoded or indirect commands require script telemetry.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("powershell.exe", "pwsh.exe") and ((ProcessCommandLine contains "Set-MpPreference" and ProcessCommandLine has_any ("DisableRealtimeMonitoring","EnableControlledFolderAccess")) or (ProcessCommandLine contains "Add-MpPreference" and ProcessCommandLine has_any ("ExclusionPath", "ExclusionProcess")))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.3 H31 — ThrottleBlood driver staging or load

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE file creation/rename only; this does not establish a driver load.

**Review / tuning:** ThrottleStop can be legitimate. Inspect driver identity, loading service, co-occurring All/Allpatch2 process and EDR health. Do not treat a rename as a kernel exploit.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType in ("FileCreated", "FileRenamed")
| where FileName in~ ("ThrottleBlood.sys", "ThrottleStop.sys")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.4 H34 — Authentication and RDP policy weakening

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE registry writes; adapt to locally observed DWORD rendering.

**Review / tuning:** Restricted Admin enabled is not universally a weakened setting. Assess the intrusion context and baseline. SecurityLayer=1 is negotiation, not proof that NLA is disabled.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d) and ActionType == "RegistryValueSet"
| extend Value = tolower(tostring(RegistryValueData))
| where
    (RegistryKey endswith @"\Control\Lsa\MSV1_0" and RegistryValueName =~ "RestrictSendingNTLMTraffic" and Value in ("0","0x0","0x00000000"))
    or (RegistryKey endswith @"\Control\Lsa" and RegistryValueName =~ "DisableRestrictedAdmin" and Value in ("0","0x0","0x00000000"))
    or (RegistryKey endswith @"\WinStations\RDP-Tcp" and RegistryValueName =~ "SecurityLayer" and Value in ("1","0x1","0x00000001"))
| project Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.5 H35 — Anonymous-share registry configuration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE registry value writes.

**Review / tuning:** Value-agnostic configuration hunt: verify EveryoneIncludesAnonymous=1, RestrictAnonymous=0 or share$ in NullSessionShares before interpreting permissive changes. Hardening can also match.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(7d) and ActionType == "RegistryValueSet"
| where (RegistryKey endswith @"\Control\Lsa" and RegistryValueName in~ ("EveryoneIncludesAnonymous","RestrictAnonymous"))
    or (RegistryKey endswith @"\Services\LanmanServer\Parameters" and RegistryValueName =~ "NullSessionShares")
| project Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.6 H36 — Firewall or SMB1 configuration commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Inspect resulting values: Set-NetFirewallProfile also enables protection. Separate RDP exception changes from disabling all profiles. Authorized legacy support may match.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (((FileName =~ "netsh.exe") and (ProcessCommandLine contains "advfirewall" or ProcessCommandLine contains "firewall") and (ProcessCommandLine contains "off" or ProcessCommandLine contains "remotedesktop")) or ((FileName =~ "powershell.exe" or FileName =~ "pwsh.exe") and ((ProcessCommandLine contains "Set-NetFirewallProfile") or ((ProcessCommandLine contains "Enable-WindowsOptionalFeature") and (ProcessCommandLine contains "SMB1Protocol")))))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.7 H37 — Deletion of execution and security-support artifacts

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE file deletion coverage varies by path and sensor.

**Review / tuning:** Maintenance and retention policies generate many matches. Group by initiating process/time; deletion telemetry is more specific than finding a deletion command, but is not exhaustive.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType == "FileDeleted"
| where FolderPath contains @"\Windows\Prefetch\"
    or FolderPath contains @"\Windows Defender\Support\"
    or FolderPath contains @"\System32\LogFiles\RDP"
    or FolderPath contains @"\$Recycle.Bin\"
| project Timestamp, DeviceId, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.8 H38 — PSReadLine history deletion

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE file deletion events.

**Review / tuning:** User privacy cleanup and profile maintenance match. Look for deletion across multiple profiles and preceding administrative activity; retained central script logs may survive.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType == "FileDeleted"
| where FileName =~ "ConsoleHost_history.txt" and FolderPath contains @"\PSReadLine\"
| project Timestamp, DeviceId, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 5.9 H44 — Executable-named cleanup batch files

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE file creation; content inspection is separate.

**Review / tuning:** Generic filename heuristic. Inspect script content for image/self deletion and delay; installers can legitimately use similar helpers. Do not execute the recovered script.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType == "FileCreated"
| where FileName endswith ".exe.bat"
| project Timestamp, DeviceId, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 6. Collection and Exfiltration

### 6.1 H09 — Transfer utility execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Execution alone does not prove exfiltration. Correlate authorized jobs, destination, direction, file list and transferred bytes.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("winscp.exe", "winscp.com", "rclone.exe")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 6.2 H40 — Transfer utilities with data-movement arguments

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Local behavioral refinement of the documented transfer tools. Scheduled transfers are common; correlate direction, destination, transferred bytes and approval.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where (((FileName =~ "rclone.exe" or FileName =~ "rclone") and (ProcessCommandLine contains " copy " or ProcessCommandLine contains " sync " or ProcessCommandLine contains " move ")) or ((FileName =~ "WinSCP.exe" or FileName =~ "WinSCP.com") and (ProcessCommandLine contains "/script" or ProcessCommandLine contains "/command")))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 6.3 H41 — WebDAV client activity in the collection context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Trend Micro assessed this as possible collection and explicitly retained legitimate explanations. A WebDAV initialization is not proof of exfiltration or C2.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "rundll32.exe") and (ProcessCommandLine contains "davclnt.dll") and (ProcessCommandLine contains "DavSetCookie"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 7. Recovery Inhibition

### 7.1 H10 — Shadow deletion and event-log clearing

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Backup maintenance and log administration can match. Validate resulting deletion and scope; these commands are not unique to the actor.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete", "shadows")) or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy", "delete")) or (FileName =~ "wevtutil.exe" and (ProcessCommandLine has "cl" or ProcessCommandLine contains "clear-log"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 7.2 H32 — Backup and database service impairment commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Inspect stop versus config verbs and requested startup value. Backup upgrades and maintenance match; source lists contain targets, not malicious service names.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((((FileName =~ "sc.exe") and (ProcessCommandLine contains "stop" or ProcessCommandLine contains "config")) or ((FileName =~ "net.exe" or FileName =~ "net1.exe") and (ProcessCommandLine contains "stop"))) and (ProcessCommandLine contains "Veeam" or ProcessCommandLine contains "BackupExec" or ProcessCommandLine contains "Acronis" or ProcessCommandLine contains "MSSQL" or ProcessCommandLine contains "SQLSERVERAGENT" or ProcessCommandLine contains " vss" or ProcessCommandLine contains "Sophos" or ProcessCommandLine contains "DefWatch"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 7.3 H33 — Targeted process termination before file impact

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** A requested termination may fail. Correlate resulting process exit, workload downtime and the initiating image; administrators may use the same command.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "taskkill.exe") and (ProcessCommandLine contains "sqlservr" or ProcessCommandLine contains "sqlwriter" or ProcessCommandLine contains "mysqld" or ProcessCommandLine contains "postgres" or ProcessCommandLine contains "vmms" or ProcessCommandLine contains "vmwp" or ProcessCommandLine contains "Veeam" or ProcessCommandLine contains "excel.exe" or ProcessCommandLine contains "outlook.exe"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 8. Deployment and Impact

### 8.1 H11 — Note and wallpaper creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE file creation/rename events.

**Review / tuning:** Restored files, research archives and simulations match. Silent modes can suppress wallpaper; filesystem absence is not exclusion.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName in~ ("README-GENTLEMEN.txt", "gentlemen.bmp")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 8.2 H39 — Ownership and permission preparation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Defender for Endpoint process creation; complete command lines required.

**Review / tuning:** Broad file-access preparation hunt. A single event is common administration; correlate multiple tools, scope and the same initiating process before linking it to encryption.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d) and ActionType == "ProcessCreated"
| where ((FileName =~ "takeown.exe") or ((FileName =~ "icacls.exe") and (ProcessCommandLine contains "S-1-1-0" or ProcessCommandLine contains "Everyone:" or ProcessCommandLine contains "ANONYMOUS LOGON")) or ((FileName =~ "attrib.exe") and (ProcessCommandLine contains "-r")))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 8.3 H43 — Free-space wipe temporary file

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE file creation/deletion; does not measure bytes written.

**Review / tuning:** Check volume-root location, rapid growth/disk pressure and creating process. A generic filename does not prove wiping, and missing deletion events do not prove persistence.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType in ("FileCreated","FileDeleted")
| where FileName =~ "wipefile.tmp"
| project Timestamp, DeviceId, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 8.4 H45 — Documented encrypted-file suffixes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE creation/rename events.

**Review / tuning:** Extensions are sample-specific and can be suppressed by silent mode. Correlate file-content/trailer changes and volume of operations; restored evidence archives can match.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType in ("FileCreated","FileRenamed")
| where FileName endswith ".7mtzhh" or FileName endswith ".umc16h" or FileName endswith ".fjn1jw"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 8.5 H47 — ESXi VM shutdown and datastore preparation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Microsoft Sentinel/Azure Monitor Syslog, not Defender XDR. Requires forwarded ESXi shell/command records containing command text.

**Review / tuning:** Default syslog is not guaranteed to record every command. Maintenance can match; correlate initiating session and subsequent datastore changes. An issued power-off is not guest shutdown confirmation.

```kusto
Syslog
| where TimeGenerated > ago(7d)
| where (SyslogMessage contains "vim-cmd" and SyslogMessage contains "vmsvc/power.off")
    or (SyslogMessage contains "esxcli" and SyslogMessage contains "vm process kill")
    or (SyslogMessage contains "esxcfg-advcfg" and SyslogMessage contains "/BufferCache/")
    or (SyslogMessage contains "vmkfstools" and SyslogMessage contains "eztDisk")
| project TimeGenerated, Computer, HostName, ProcessName, SyslogMessage
```

## 9. Multi-Stage Correlation

### 9.1 H12 — Impairment and task activity on the same host

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process creation; host-level grouping.

**Review / tuning:** One-day co-occurrence, not an ordered chain or same-process attribution. Narrow the window and review event times, account and ancestry before escalation.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d) and ActionType == "ProcessCreated"
| extend IsTask = FileName =~ "schtasks.exe" and ProcessCommandLine contains "gentlemen_system"
| extend IsImpairment = FileName =~ "wevtutil.exe" and (ProcessCommandLine has "cl" or ProcessCommandLine contains "clear-log")
| where IsTask or IsImpairment
| summarize TaskEvents=countif(IsTask), ImpairmentEvents=countif(IsImpairment),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Commands=make_set(ProcessCommandLine, 30) by DeviceId, DeviceName
| where TaskEvents > 0 and ImpairmentEvents > 0
```

### 9.2 H46 — Share staging and propagation tasks from one process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE child processes grouped by parent PID plus parent creation time.

**Review / tuning:** Local same-parent co-occurrence hypothesis, not an ordered chain. Intermediary shells can split the tree and evade this grouping; long parent lifetimes can aggregate separate episodes.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d) and ActionType == "ProcessCreated"
| extend Stage = ProcessCommandLine contains "share$" and ProcessCommandLine contains @"C:\Temp"
| extend Task = FileName =~ "schtasks.exe" and ProcessCommandLine has_any ("UpdateGU","UpdateGU2","UpdateGS","UpdateGS2","DefU","DefS")
| where Stage or Task
| where isnotempty(InitiatingProcessCreationTime)
| summarize StagingEvents=countif(Stage), TaskEvents=countif(Task),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Commands=make_set(ProcessCommandLine,50)
    by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCreationTime
| where StagingEvents > 0 and TaskEvents > 0 and LastSeen-FirstSeen <= 30m
```

## 10. Campaign Artifact Hunts

### 10.1 H13 — Primary-source encryptor hash hunt

**Origin:** Repository-authored defensive hunt.

**Telemetry:** MDE process/file records; hash availability varies.

**Review / tuning:** Uses Microsoft's SHA-256 plus Trend Micro's independently classified SHA-1; not asserted to identify the same bytes. Missing hash fields reduce visibility. A file event alone is not execution.

```kusto
union withsource=SourceTable DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 =~ "22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67"
    or SHA1 =~ "c12c4d58541cc4f75ae19b65295a52c559570054"
| project Timestamp, DeviceId, DeviceName, SourceTable, ActionType, FileName, FolderPath, SHA1, SHA256
```

### 10.2 H14 — Velociraptor outside an approved engagement

**Origin:** Repository-authored defensive hunt, adapted from the supplied tracker hypothesis.

**Telemetry:** Defender for Endpoint process creation with command lines.

**Review / tuning:** Supplied tool-inventory hypothesis. Legitimate DFIR use is expected; validate approval, configuration and server ownership rather than treating a match as malicious.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("velociraptor.exe", "velociraptor-client.exe")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
