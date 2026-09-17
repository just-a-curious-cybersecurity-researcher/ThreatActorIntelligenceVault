# The Gentlemen — Splunk Hunting Searches

**Presentation reviewed:** 2026-09-17.

## Scope and Requirements

H01–H46 and H49–H54 use Sysmon XML fields in Splunk; H47–H48 use forwarded ESXi syslog. Replace index=* with the authorized endpoint index and adapt sourcetype/field extractions to your deployment. Event 3/6/7/11/13/23/26 collection must be enabled for corresponding searches.

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

Published procedures support the hypotheses; actual detection depends on your sensors. Allowed administration and security research can match. No connected Splunk backend was used for runtime validation. Queries do not execute the attack commands they search for.

## 1. Credential Access

### 1.1 H01 — Authentication coercion and relay tool names

**Origin:** Repository-authored defensive hunt, adapted from the supplied tracker hypothesis.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Tool-inventory hypothesis from the supplied notes; authorized assessments match. A name does not establish successful relay or stolen credentials.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where like(cmd,"%petitpotam%") OR like(cmd,"%ntlmrelayx%") OR like(cmd,"%responder.py%") OR like(cmd,"%relayking%")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 1.2 H15 — Credential-recovery tools from the shared inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Tool-name hypothesis from the supplied corpus and chat analysis. Validate binary identity and approval; renaming defeats this filter, and execution does not prove successful dumping.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (like(cmd,"%ksldump%") OR like(cmd,"%kslkatz%") OR like(cmd,"%dumpbrowsersecrets%") OR like(cmd,"%xenallpasswordpro%"))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 1.3 H16 — NetExec invocation with credential-access options

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Local hypothesis combining a documented shared tool with credential-oriented options. Confirm tool version, arguments and the remote response; sanctioned assessments match.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where ((((img="nxc.exe" OR like(img,"%\\nxc.exe")) OR (img="netexec.exe" OR like(img,"%\\netexec.exe")) OR (img="nxc" OR like(img,"%\\nxc")) OR (img="netexec" OR like(img,"%\\netexec"))) OR (like(cmd,"%netexec.py%"))) AND (like(cmd,"%--sam%") OR like(cmd,"%--lsa%") OR like(cmd,"%--ntds%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

## 2. Active Directory and Network Discovery

### 2.1 H02 — Domain user and privileged-group enumeration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Compare with administrative baselines; repeated account queries and the initiating script strengthen relevance.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where (like(img,"%net.exe") OR like(img,"%net1.exe")) AND like(cmd,"%/dom%") AND (like(cmd,"%user%") OR like(cmd,"%group%"))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.2 H03 — MANSPIDER share-crawler invocation

**Origin:** Repository-authored defensive hunt, adapted from the supplied tracker hypothesis.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Supplied inventory lead, not proof of observed execution in the 2025 case. Authorized security review can match.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where like(img,"%manspider%") OR like(cmd,"%manspider%")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.3 H17 — Network scanners in endpoint process telemetry

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Approved network inventory and security assessments match. Compare executing account, scan targets and subsequent access; scan execution does not prove exploitation.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="advanced_ip_scanner.exe" OR like(img,"%\\advanced_ip_scanner.exe")) OR (img="nmap.exe" OR like(img,"%\\nmap.exe")) OR (img="nmap" OR like(img,"%\\nmap")) OR (img="gogo.exe" OR like(img,"%\\gogo.exe"))) OR (like(cmd,"%nmap-7.97-setup.exe%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.4 H18 — Directory and cloud discovery tool inventory

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Shared-inventory hypothesis. Inspect command parameters and process identity; a text reference or installation can match without collection.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (like(cmd,"%adfind%") OR like(cmd,"%sharphound%") OR like(cmd,"%bloodhound%") OR like(cmd,"%ldapdomaindump%") OR like(cmd,"%powerzure%"))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.5 H19 — Certificate and privilege-path tooling

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Chat-documented tool inventory, not proof of certificate abuse or privilege escalation. Validate the executed module and resulting directory/service events.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (like(cmd,"%certihound%") OR like(cmd,"%privhound%") OR like(cmd,"%taskhound%") OR like(cmd,"%regpwn%"))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.6 H20 — Volume and cluster-storage enumeration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Cluster administrators and backup jobs commonly match. Retain parent process and following file activity; failures can simply indicate a non-cluster host.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="powershell.exe" OR like(img,"%\\powershell.exe")) OR (img="pwsh.exe" OR like(img,"%\\pwsh.exe"))) AND ((like(cmd,"%get-clustersharedvolume%")) OR ((like(cmd,"%get-wmiobject%") OR like(cmd,"%get-ciminstance%")) AND (like(cmd,"%win32_volume%")))))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.7 H21 — Network-discovery services and firewall group changes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Service starts and rule queries are not automatically malicious or successful. Inspect the operation and actual firewall value; localized group names need local adaptation.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where ((((img="sc.exe" OR like(img,"%\\sc.exe")) OR (img="net.exe" OR like(img,"%\\net.exe")) OR (img="net1.exe" OR like(img,"%\\net1.exe"))) AND (like(cmd,"%fdrespub%") OR like(cmd,"%fdphost%") OR like(cmd,"%ssdpsrv%") OR like(cmd,"%upnphost%")) AND (like(cmd,"%start%") OR like(cmd,"%config%"))) OR (((img="netsh.exe" OR like(img,"%\\netsh.exe"))) AND (like(cmd,"%network discovery%"))))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.8 H50 — Primary-domain-controller discovery

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Includes fragments of the two published UTF-16LE encoded commands as well as decoded text. Encoding/spacing changes evade fragments; script-block logs provide better semantic coverage.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="powershell.exe" OR like(img,"%\\powershell.exe")) OR (img="pwsh.exe" OR like(img,"%\\pwsh.exe")) OR (img="cmd.exe" OR like(img,"%\\cmd.exe"))) AND (((like(cmd,"%get-addomain%")) AND (like(cmd,"%pdcemulator%"))) OR (like(cmd,"%iaaoaecazq%") OR like(cmd,"%iabhaguadaataeearabeag8abqbhagkabg%"))))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 2.9 H52 — Native packet capture through netsh

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command lines.

**Review / tuning:** Native packet collection is documented by Kaspersky. Troubleshooting matches; validate the collector's account, output path and capture authorization. A start command does not prove credentials were captured.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where like(img,"%\\netsh.exe") AND like(cmd,"%trace%") AND like(cmd,"%start%") AND like(cmd,"%capture=yes%")
| table _time Computer User Image CommandLine ParentImage ProcessGuid
```

## 3. Persistence and Remote Administration

### 3.1 H04 — Locker-related scheduled-task commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Generic UpdateSystem/UpdateUser/TaskSystem names need action-path and creator validation. Includes query/delete operations; inspect the verb.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where like(img,"%schtasks.exe") AND (like(cmd,"%gentlemen_system%") OR like(cmd,"%updatesystem%") OR like(cmd,"%updateuser%") OR like(cmd,"%tasksystem%"))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.2 H05 — Locker-associated autorun value writes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13; registry collection must include these paths.

**Review / tuning:** GupdateS/GupdateU are sample-associated strings. Validate the destination image; this is a registry write, not proof of a later logon execution.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| eval target=lower(TargetObject)
| where like(target,"%\\software\\microsoft\\windows\\currentversion\\run\\gupdates") OR like(target,"%\\software\\microsoft\\windows\\currentversion\\run\\gupdateu")
| table _time Computer User Image TargetObject Details ProcessGuid
```

### 3.3 H22 — Propagation-specific task names

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Short DefU/DefS strings can occur inside longer text. Verify exact task name, /S target, action and principal. Do not equate registration with execution.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="schtasks.exe" OR like(img,"%\\schtasks.exe"))) AND (like(cmd,"%defu%") OR like(cmd,"%defs%") OR like(cmd,"%updategu%") OR like(cmd,"%updategu2%") OR like(cmd,"%updategs%") OR like(cmd,"%updategs2%")) AND (like(cmd,"%/create%") OR like(cmd,"%/run%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.4 H23 — Propagation service creation and start commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Verify exact service name and ImagePath. Generic update services and incident-response recreations can match; collect destination service events.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="sc.exe" OR like(img,"%\\sc.exe"))) AND (like(cmd,"%defsvc%") OR like(cmd,"%updatesvc%") OR like(cmd,"%updatesvc2%")) AND (like(cmd,"%create%") OR like(cmd,"%start%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.5 H24 — Payload paths written into propagation services

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13 with TargetObject and Details.

**Review / tuning:** A value write is evidence of configuration, not service start. Inspect quoted ImagePath, remote-origin logon and service creation events.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| eval target=lower(TargetObject)
| where like(target,"%\\services\\defsvc\\imagepath")
    OR like(target,"%\\services\\updatesvc\\imagepath")
    OR like(target,"%\\services\\updatesvc2\\imagepath")
| table _time Computer User Image TargetObject Details ProcessGuid
```

### 3.6 H25 — PsExec with staging or locker context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** PsExec is legitimate administration software. Hunt for unapproved target/account combinations; the presence of a password argument does not recover it or establish successful propagation.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="psexec.exe" OR like(img,"%\\psexec.exe")) OR (img="psexec64.exe" OR like(img,"%\\psexec64.exe"))) AND (like(cmd,"%c:\\temp%") OR like(cmd,"%\\share$%") OR like(cmd,"%\\netlogon%") OR like(cmd,"%--password%") OR like(cmd,"%--spread%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.7 H26 — Remote WMI process creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Generic remote administration hunt. Link the command with target WmiPrvSE child processes and logons; local command success alone is insufficient.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="wmic.exe" OR like(img,"%\\wmic.exe"))) AND (like(cmd,"%/node:%")) AND (like(cmd,"%process%")) AND (like(cmd,"%create%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.8 H27 — PowerShell remoting or WMI with deployment context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Generic administrative automation can match. Script-block telemetry is needed for encoded or in-memory scripts; distinguish WinRM from WMI on the target.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="powershell.exe" OR like(img,"%\\powershell.exe")) OR (img="pwsh.exe" OR like(img,"%\\pwsh.exe"))) AND (like(cmd,"%invoke-command%") OR like(cmd,"%win32_process%") OR like(cmd,"%invoke-wmimethod%")) AND (like(cmd,"%\\share$%") OR like(cmd,"%c:\\temp%") OR like(cmd,"%--password%") OR like(cmd,"%set-mppreference%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.9 H28 — AnyDesk installation or persistent service setup

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Local persistence hypothesis for the documented RMM. Confirm approved software deployment, remote client identity and configuration; signed software can be authorized.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="anydesk.exe" OR like(img,"%\\anydesk.exe"))) AND (like(cmd,"%--install%") OR like(cmd,"%--start-with-win%") OR like(cmd,"%--start%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.10 H42 — Hidden distribution share staging

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Require the actual net share operation and inspect resulting share permissions; quoted investigation text can match. share$ is a published artifact, not a uniquely malicious name.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="net.exe" OR like(img,"%\\net.exe")) OR (img="net1.exe" OR like(img,"%\\net1.exe")) OR (img="cmd.exe" OR like(img,"%\\cmd.exe")) OR (img="powershell.exe" OR like(img,"%\\powershell.exe")) OR (img="pwsh.exe" OR like(img,"%\\pwsh.exe"))) AND (like(cmd,"%share$%")) AND (like(cmd,"%c:\\temp%")) AND (like(cmd,"%share%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.11 H48 — ESXi boot artifact and autostart changes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Forwarded ESXi shell/command logs, expected text in _raw.

**Review / tuning:** A log reference is not file-integrity proof. Inspect recovered boot/cron files and exact autostart verb/value. Queries and legitimate startup customization also match.

```spl
index=* sourcetype="syslog" earliest=-7d
| eval msg=lower(_raw)
| where like(msg,"%/bin/.vmware-authd%")
    OR (like(msg,"%/etc/rc.local.d/local.sh%") AND like(msg,"%sleep%"))
    OR (like(msg,"%vim-cmd%") AND like(msg,"%autostartmanager%"))
| table _time host source _raw
```

### 3.12 H49 — Group Policy consoles with policy-editing context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Console execution alone does not prove a GPO change. Correlate directory auditing, SYSVOL/NETLOGON writes and subsequent client-side policy application.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="mmc.exe" OR like(img,"%\\mmc.exe"))) AND (like(cmd,"%gpmc.msc%") OR like(cmd,"%gpme.msc%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 3.13 H51 — PowerShell Web Access configuration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command lines.

**Review / tuning:** Group-IB documents this access configuration. Inspect the allowed users/computers, certificate, IIS exposure and approval; installation is not by itself malicious.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where (like(img,"%\\powershell.exe") OR like(img,"%\\pwsh.exe"))
    AND (like(cmd,"%windowspowershellwebaccess%") OR like(cmd,"%install-pswawebapplication%") OR like(cmd,"%add-pswaauthorizationrule%"))
| table _time Computer User Image CommandLine ParentImage ProcessGuid
```

### 3.14 H53 — Locker-associated GPO script and policy-task files

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11 with the relevant file paths included.

**Review / tuning:** The script filename is published; ScheduledTasks.xml is also normal Group Policy content. Verify the task action, GPO change owner and directory audit trail. Sysmon creation/overwrite coverage is not all MDE modification coverage.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| eval target=lower(TargetFilename)
| where like(target,"%\\deploy_gpo.ps1")
    OR (like(target,"%\\scheduledtasks.xml") AND like(target,"%\\sysvol\\%"))
| table _time Computer Image TargetFilename ProcessGuid
```

## 4. Tunneling and C2

### 4.1 H06 — Historical affiliate C2 connections

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 3, enabled network telemetry.

**Review / tuning:** Historical Check Point, Huntress and Kaspersky case IPs; revalidate ownership and the connection date. A match is not proof of a current SystemBC implant.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-7d
| where DestinationIp="91.107.247.163" OR DestinationIp="45.86.230.112" OR DestinationIp="193.233.202.17" OR DestinationIp="77.110.122.137" OR DestinationIp="81.177.215.15"
| table _time Computer Image User DestinationIp DestinationPort Initiated ProcessGuid
```

### 4.2 H29 — Case-associated SystemBC file identity

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Events 1/7 with SHA-256 configured.

**Review / tuning:** Identifies the published companion sample, not every SystemBC version. SystemBC is shared across actors; file presence is not execution.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=7) earliest=-30d
| eval hashes=lower(Hashes)
| where like(hashes,"%sha256=992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5%")
| table _time Computer EventCode Image ImageLoaded Hashes ProcessGuid
```

### 4.3 H30 — Tunnel and proxy clients from the toolset

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Cloudflare and VPN software have legitimate uses. Review tunnel owner/configuration, destination, parent and change approval. Process names alone do not prove covert C2.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="cloudflared.exe" OR like(img,"%\\cloudflared.exe")) OR (img="cloudflared" OR like(img,"%\\cloudflared")) OR (img="chisel.exe" OR like(img,"%\\chisel.exe")) OR (img="chisel" OR like(img,"%\\chisel")) OR (img="chisel-ng.exe" OR like(img,"%\\chisel-ng.exe")) OR (img="openconnect.exe" OR like(img,"%\\openconnect.exe")) OR (img="openconnect" OR like(img,"%\\openconnect")) OR (img="proxychains" OR like(img,"%\\proxychains")) OR (img="proxychains4" OR like(img,"%\\proxychains4"))) OR (like(cmd,"%chisel-ng%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 4.4 H54 — Disguised proxy and WindowsConnSvc task

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command lines.

**Review / tuning:** Huntress case artifacts; svchost32.exe is distinct from the normal svchost.exe name. The reported task also produced repeated failures. Confirm actual launch and network connection instead of assuming persistence succeeded.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where (like(img,"%\\svchost32.exe") AND like(cmd,"%socks%"))
    OR (like(img,"%\\schtasks.exe") AND like(cmd,"%windowsconnsvc%"))
| table _time Computer User Image CommandLine ParentImage ProcessGuid
```

## 5. Defense Evasion and Impairment

### 5.1 H07 — Case process killers and privileged launcher

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Generic names, legitimate PowerRun use and approved kavrmvr maintenance create false positives. Inspect hash, driver load and service events; filename match does not prove kernel impairment.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where like(img,"%all.exe") OR like(img,"%allpatch2.exe") OR like(img,"%powerrun.exe") OR like(img,"%\\kavrmvr.exe")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 5.2 H08 — Defender preference impairment

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Approved maintenance and other malware match. Inspect argument values, protection outcomes and process ancestry; encoded or indirect commands require script telemetry.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where (like(img,"%powershell.exe") OR like(img,"%pwsh.exe")) AND ((like(cmd,"%set-mppreference%") AND (like(cmd,"%disablerealtimemonitoring%") OR like(cmd,"%enablecontrolledfolderaccess%"))) OR (like(cmd,"%add-mppreference%") AND (like(cmd,"%exclusionpath%") OR like(cmd,"%exclusionprocess%"))))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 5.3 H31 — ThrottleBlood driver staging or load

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 6 driver load or Event 11 file creation; evidence classes remain separate.

**Review / tuning:** ThrottleStop can be legitimate. Inspect driver identity, loading service, co-occurring All/Allpatch2 process and EDR health. Do not treat a rename as a kernel exploit.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=6 OR EventCode=11) earliest=-7d
| eval artifact=lower(coalesce(ImageLoaded,TargetFilename))
| where like(artifact,"%\\throttleblood.sys") OR like(artifact,"%\\throttlestop.sys")
| table _time Computer EventCode Image ImageLoaded TargetFilename Hashes Signed Signature
```

### 5.4 H34 — Authentication and RDP policy weakening

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13 with DWORD Details.

**Review / tuning:** Restricted Admin enabled is not universally a weakened setting. Assess the intrusion context and baseline. SecurityLayer=1 is negotiation, not proof that NLA is disabled.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| eval target=lower(TargetObject), data=lower(Details)
| where
    (like(target,"%\\control\\lsa\\msv1_0\\restrictsendingntlmtraffic") AND match(data,"(?:^|[^0-9a-z])(?:0x0+|0)(?:$|[^0-9a-z])"))
    OR (like(target,"%\\control\\lsa\\disablerestrictedadmin") AND match(data,"(?:^|[^0-9a-z])(?:0x0+|0)(?:$|[^0-9a-z])"))
    OR (like(target,"%\\winstations\\rdp-tcp\\securitylayer") AND match(data,"(?:^|[^0-9a-z])(?:0x0*1|1)(?:$|[^0-9a-z])"))
| table _time Computer User Image TargetObject Details ProcessGuid
```

### 5.5 H35 — Anonymous-share registry configuration

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 13.

**Review / tuning:** Value-agnostic configuration hunt: verify EveryoneIncludesAnonymous=1, RestrictAnonymous=0 or share$ in NullSessionShares before interpreting permissive changes. Hardening can also match.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
| eval target=lower(TargetObject)
| where like(target,"%\\control\\lsa\\everyoneincludesanonymous")
    OR like(target,"%\\control\\lsa\\restrictanonymous")
    OR like(target,"%\\services\\lanmanserver\\parameters\\nullsessionshares")
| table _time Computer User Image TargetObject Details ProcessGuid
```

### 5.6 H36 — Firewall or SMB1 configuration commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Inspect resulting values: Set-NetFirewallProfile also enables protection. Separate RDP exception changes from disabling all profiles. Authorized legacy support may match.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where ((((img="netsh.exe" OR like(img,"%\\netsh.exe"))) AND (like(cmd,"%advfirewall%") OR like(cmd,"%firewall%")) AND (like(cmd,"%off%") OR like(cmd,"%remotedesktop%"))) OR (((img="powershell.exe" OR like(img,"%\\powershell.exe")) OR (img="pwsh.exe" OR like(img,"%\\pwsh.exe"))) AND ((like(cmd,"%set-netfirewallprofile%")) OR ((like(cmd,"%enable-windowsoptionalfeature%")) AND (like(cmd,"%smb1protocol%"))))))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 5.7 H37 — Deletion of execution and security-support artifacts

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 23/26; deletion collection must be explicitly configured.

**Review / tuning:** Maintenance and retention policies generate many matches. Group by initiating process/time; deletion telemetry is more specific than finding a deletion command, but is not exhaustive.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=23 OR EventCode=26) earliest=-7d
| eval target=lower(TargetFilename)
| where like(target,"%\\windows\\prefetch\\%")
    OR like(target,"%\\windows defender\\support\\%")
    OR like(target,"%\\system32\\logfiles\\rdp%")
    OR like(target,"%\\$recycle.bin\\%")
| table _time Computer Image TargetFilename ProcessGuid
```

### 5.8 H38 — PSReadLine history deletion

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 23/26 with configured path coverage.

**Review / tuning:** User privacy cleanup and profile maintenance match. Look for deletion across multiple profiles and preceding administrative activity; retained central script logs may survive.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=23 OR EventCode=26) earliest=-7d
| eval target=lower(TargetFilename)
| where like(target,"%\\psreadline\\consolehost_history.txt")
| table _time Computer Image TargetFilename ProcessGuid
```

### 5.9 H44 — Executable-named cleanup batch files

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11.

**Review / tuning:** Generic filename heuristic. Inspect script content for image/self deletion and delay; installers can legitimately use similar helpers. Do not execute the recovered script.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| eval target=lower(TargetFilename)
| where like(target,"%.exe.bat")
| table _time Computer Image TargetFilename ProcessGuid
```

## 6. Collection and Exfiltration

### 6.1 H09 — Transfer utility execution

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Execution alone does not prove exfiltration. Correlate authorized jobs, destination, direction, file list and transferred bytes.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where like(img,"%winscp.exe") OR like(img,"%winscp.com") OR like(img,"%rclone.exe")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 6.2 H40 — Transfer utilities with data-movement arguments

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Local behavioral refinement of the documented transfer tools. Scheduled transfers are common; correlate direction, destination, transferred bytes and approval.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where ((((img="rclone.exe" OR like(img,"%\\rclone.exe")) OR (img="rclone" OR like(img,"%\\rclone"))) AND (like(cmd,"% copy %") OR like(cmd,"% sync %") OR like(cmd,"% move %"))) OR (((img="winscp.exe" OR like(img,"%\\winscp.exe")) OR (img="winscp.com" OR like(img,"%\\winscp.com"))) AND (like(cmd,"%/script%") OR like(cmd,"%/command%"))))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 6.3 H41 — WebDAV client activity in the collection context

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Trend Micro assessed this as possible collection and explicitly retained legitimate explanations. A WebDAV initialization is not proof of exfiltration or C2.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="rundll32.exe" OR like(img,"%\\rundll32.exe"))) AND (like(cmd,"%davclnt.dll%")) AND (like(cmd,"%davsetcookie%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

## 7. Recovery Inhibition

### 7.1 H10 — Shadow deletion and event-log clearing

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Backup maintenance and log administration can match. Validate resulting deletion and scope; these commands are not unique to the actor.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where (like(img,"%vssadmin.exe") AND like(cmd,"%delete%") AND like(cmd,"%shadows%")) OR (like(img,"%wmic.exe") AND like(cmd,"%shadowcopy%") AND like(cmd,"%delete%")) OR (like(img,"%wevtutil.exe") AND (like(cmd,"% cl %") OR like(cmd,"%clear-log%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 7.2 H32 — Backup and database service impairment commands

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Inspect stop versus config verbs and requested startup value. Backup upgrades and maintenance match; source lists contain targets, not malicious service names.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((((img="sc.exe" OR like(img,"%\\sc.exe"))) AND (like(cmd,"%stop%") OR like(cmd,"%config%"))) OR (((img="net.exe" OR like(img,"%\\net.exe")) OR (img="net1.exe" OR like(img,"%\\net1.exe"))) AND (like(cmd,"%stop%")))) AND (like(cmd,"%veeam%") OR like(cmd,"%backupexec%") OR like(cmd,"%acronis%") OR like(cmd,"%mssql%") OR like(cmd,"%sqlserveragent%") OR like(cmd,"% vss%") OR like(cmd,"%sophos%") OR like(cmd,"%defwatch%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 7.3 H33 — Targeted process termination before file impact

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** A requested termination may fail. Correlate resulting process exit, workload downtime and the initiating image; administrators may use the same command.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="taskkill.exe" OR like(img,"%\\taskkill.exe"))) AND (like(cmd,"%sqlservr%") OR like(cmd,"%sqlwriter%") OR like(cmd,"%mysqld%") OR like(cmd,"%postgres%") OR like(cmd,"%vmms%") OR like(cmd,"%vmwp%") OR like(cmd,"%veeam%") OR like(cmd,"%excel.exe%") OR like(cmd,"%outlook.exe%")))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

## 8. Deployment and Impact

### 8.1 H11 — Note and wallpaper creation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11; creation coverage, not equivalent to all MDE rename events.

**Review / tuning:** Restored files, research archives and simulations match. Silent modes can suppress wallpaper; filesystem absence is not exclusion.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| eval target=lower(TargetFilename)
| where like(target,"%readme-gentlemen.txt") OR like(target,"%gentlemen.bmp")
| table _time Computer Image TargetFilename ProcessGuid
```

### 8.2 H39 — Ownership and permission preparation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1 with command-line extraction and ProcessGuid.

**Review / tuning:** Broad file-access preparation hunt. A single event is common administration; correlate multiple tools, scope and the same initiating process before linking it to encryption.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine), parent=lower(ParentImage)
| where (((img="takeown.exe" OR like(img,"%\\takeown.exe"))) OR (((img="icacls.exe" OR like(img,"%\\icacls.exe"))) AND (like(cmd,"%s-1-1-0%") OR like(cmd,"%everyone:%") OR like(cmd,"%anonymous logon%"))) OR (((img="attrib.exe" OR like(img,"%\\attrib.exe"))) AND (like(cmd,"%-r%"))))
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```

### 8.3 H43 — Free-space wipe temporary file

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11/23/26; does not measure free-space exhaustion.

**Review / tuning:** Check volume-root location, rapid growth/disk pressure and creating process. A generic filename does not prove wiping, and missing deletion events do not prove persistence.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=11 OR EventCode=23 OR EventCode=26) earliest=-7d
| eval target=lower(TargetFilename)
| where like(target,"%\\wipefile.tmp")
| table _time Computer EventCode Image TargetFilename ProcessGuid
```

### 8.4 H45 — Documented encrypted-file suffixes

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 11; no claim of complete rename coverage.

**Review / tuning:** Extensions are sample-specific and can be suppressed by silent mode. Correlate file-content/trailer changes and volume of operations; restored evidence archives can match.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| eval target=lower(TargetFilename)
| where like(target,"%.7mtzhh") OR like(target,"%.umc16h") OR like(target,"%.fjn1jw")
| table _time Computer Image TargetFilename ProcessGuid
```

### 8.5 H47 — ESXi VM shutdown and datastore preparation

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Forwarded ESXi shell logs in syslog; adapt sourcetype to your deployment.

**Review / tuning:** Default syslog is not guaranteed to record every command. Maintenance can match; correlate initiating session and subsequent datastore changes. An issued power-off is not guest shutdown confirmation.

```spl
index=* sourcetype="syslog" earliest=-7d
| eval msg=lower(_raw)
| where (like(msg,"%vim-cmd%") AND like(msg,"%vmsvc/power.off%"))
    OR (like(msg,"%esxcli%") AND like(msg,"%vm process kill%"))
    OR (like(msg,"%esxcfg-advcfg%") AND like(msg,"%/buffercache/%"))
    OR (like(msg,"%vmkfstools%") AND like(msg,"%eztdisk%"))
| table _time host source _raw
```

## 9. Multi-Stage Correlation

### 9.1 H12 — Impairment and task activity on the same host

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1; unique Computer naming required across tenants.

**Review / tuning:** One-day co-occurrence, not an ordered chain or same-process attribution. Narrow the window and review event times, account and ancestry before escalation.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1d
| eval img=lower(Image), cmd=lower(CommandLine)
| eval is_task=if(like(img,"%schtasks.exe") AND like(cmd,"%gentlemen_system%"),1,0)
| eval is_impairment=if(like(img,"%wevtutil.exe") AND (like(cmd,"% cl %") OR like(cmd,"%clear-log%")),1,0)
| where is_task=1 OR is_impairment=1
| stats sum(is_task) as TaskEvents sum(is_impairment) as ImpairmentEvents min(_time) as FirstSeen max(_time) as LastSeen values(CommandLine) as Commands by Computer
| where TaskEvents>0 AND ImpairmentEvents>0
```

### 9.2 H46 — Share staging and propagation tasks from one process

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Event 1, Computer and nonempty ParentProcessGuid.

**Review / tuning:** Local same-parent co-occurrence hypothesis, not an ordered chain. Intermediary shells can split the tree and evade this grouping; long parent lifetimes can aggregate separate episodes.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1d
| eval cmd=lower(CommandLine), img=lower(Image)
| eval stage=if(like(cmd,"%share$%") AND like(cmd,"%c:\\temp%"),1,0)
| eval task=if(like(img,"%\\schtasks.exe") AND (like(cmd,"%updategu%") OR like(cmd,"%updategs%") OR like(cmd,"%defu%") OR like(cmd,"%defs%")),1,0)
| where (stage=1 OR task=1) AND isnotnull(ParentProcessGuid) AND ParentProcessGuid!="" AND ParentProcessGuid!="{00000000-0000-0000-0000-000000000000}"
| stats sum(stage) as StagingEvents sum(task) as TaskEvents min(_time) as FirstSeen max(_time) as LastSeen values(CommandLine) as Commands by Computer ParentProcessGuid
| where StagingEvents>0 AND TaskEvents>0 AND LastSeen-FirstSeen<=1800
```

## 10. Campaign Artifact Hunts

### 10.1 H13 — Primary-source encryptor hash hunt

**Origin:** Repository-authored defensive hunt.

**Telemetry:** Sysmon Events 1/7 with hash calculation configured.

**Review / tuning:** Uses Microsoft's SHA-256 plus Trend Micro's independently classified SHA-1; not asserted to identify the same bytes. Missing hash fields reduce visibility. A file event alone is not execution.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=7) earliest=-30d
| eval hashes=lower(Hashes)
| where like(hashes,"%sha256=22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67%")
    OR like(hashes,"%sha1=c12c4d58541cc4f75ae19b65295a52c559570054%")
| table _time Computer EventCode Image ImageLoaded Hashes ProcessGuid
```

### 10.2 H14 — Velociraptor outside an approved engagement

**Origin:** Repository-authored defensive hunt, adapted from the supplied tracker hypothesis.

**Telemetry:** Sysmon Event 1 with Image, CommandLine, ParentImage, Computer and User.

**Review / tuning:** Supplied tool-inventory hypothesis. Legitimate DFIR use is expected; validate approval, configuration and server ownership rather than treating a match as malicious.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
| eval img=lower(Image), cmd=lower(CommandLine)
| where like(img,"%velociraptor.exe") OR like(img,"%velociraptor-client.exe")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessGuid
```
