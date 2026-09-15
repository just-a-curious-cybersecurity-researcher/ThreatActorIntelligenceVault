# Akira — Splunk Hunting Queries

These searches are examples for **Windows/Sysmon-oriented Splunk environments**.

> **You must adapt indexes, sourcetypes and field names to your environment.** The examples below assume fields similar to Sysmon XML ingestion: `EventCode`, `Image`, `CommandLine`, `ParentImage`, `User`, `Computer`, `DestinationIp`, `DestinationPort`, `TargetFilename` and `ImageLoaded`.
>
> Many of the tools and commands are legitimate. Before enabling alerts, baseline approved RMM products, administration hosts, backup systems, vulnerability scanners, software deployment tools, red-team systems and automation accounts.

Replace `index=windows` and the Sysmon sourcetype with your local values.

## Coverage, Telemetry and Tuning Register

This register applies to **every numbered query** in this file. These are hunts; no KQL/SPL backend was available for execution. Source attribution describes campaign evidence, not rule specificity. The [current ATT&CK table](../technical/mitre-attack.md) contains supported mappings.

| Query family | Evidence | Required interpretation / false positives |
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

### 1.1 LSASS dump via `comsvcs.dll`

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*" CommandLine="*MiniDump*"
| table _time Computer User Image ParentImage CommandLine ProcessId ParentProcessId
```

### 1.2 Mimikatz / LaZagne / DonPAPI / NetExec / Veeam credential tooling

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
  Image="*mimikatz*" OR Image="*lazagne*" OR Image="*donpapi*" OR Image="*netexec*" OR Image="*veeamhax*"
  OR CommandLine="*sekurlsa::*" OR CommandLine="*lsadump::*" OR CommandLine="*DonPAPI*"
  OR CommandLine="*LaZagne*" OR CommandLine="*Veeam-Get-Creds*"
)
| table _time Computer User Image ParentImage CommandLine
```

### 1.3 SAM / SECURITY / SYSTEM hive export

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\reg.exe" CommandLine="* save *"
(CommandLine="*HKLM\\SAM*" OR CommandLine="*HKLM\\SECURITY*" OR CommandLine="*HKLM\\SYSTEM*")
| table _time Computer User ParentImage Image CommandLine
```

### 1.4 NTDS.dit access / extraction

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(CommandLine="*ntds.dit*" OR CommandLine="*ntdsutil*" OR (Image="*\\esentutl.exe" CommandLine="*ntds*"))
| table _time Computer User ParentImage Image CommandLine
```

### 1.5 Browser credential database access through `esentutl.exe`

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\esentutl.exe"
(CommandLine="*Login Data*" OR CommandLine="*key4.db*" OR CommandLine="*logins.json*" OR CommandLine="*Cookies*")
| table _time Computer User ParentImage Image CommandLine
```

## 2. AD and Network Discovery

### 2.1 SharpHound / BloodHound / AdFind / LDAP tooling

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
  Image="*sharphound*" OR Image="*bloodhound*" OR Image="*adfind*" OR Image="*ldapdomaindump*"
  OR CommandLine="*Invoke-ShareFinder*" OR CommandLine="*SharpShares*" OR CommandLine="*Snaffler*"
)
| stats count min(_time) as first_seen max(_time) as last_seen values(Image) as images values(CommandLine) as commands by Computer User
| convert ctime(first_seen) ctime(last_seen)
```

### 2.2 Native domain discovery

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
  (Image="*\\nltest.exe" (CommandLine="*/dclist*" OR CommandLine="*/domain_trusts*"))
  OR (Image="*\\net.exe" CommandLine="*group*" CommandLine="*domain admins*")
  OR (Image="*\\net.exe" CommandLine="*localgroup*" CommandLine="*administrators*")
)
| table _time Computer User ParentImage Image CommandLine
```

**Review:** highly environment-dependent. These commands are legitimate. Use host/user rarity and temporal clustering.

### 2.3 Network-scanning utilities

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*advanced_ip_scanner*" OR Image="*netscan*" OR Image="*masscan*" OR CommandLine="*SoftPerfect*" OR CommandLine="*Advanced IP Scanner*")
| table _time Computer User ParentImage Image CommandLine Hashes
```

## 3. RMM / RAT

### 3.1 RMM product execution

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
 Image="*anydesk*" OR Image="*rustdesk*" OR Image="*radmin*" OR Image="*teamviewer*"
 OR Image="*logmein*" OR Image="*screenconnect*" OR Image="*meshagent*" OR Image="*level*"
)
| stats count min(_time) as first_seen max(_time) as last_seen values(Image) as images values(CommandLine) as commands by Computer User
| convert ctime(first_seen) ctime(last_seen)
```

### 3.2 Rare RMM use by host

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*anydesk*" OR Image="*rustdesk*" OR Image="*radmin*" OR Image="*teamviewer*" OR Image="*meshagent*")
| stats dc(Computer) as host_count count as executions values(Computer) as hosts values(User) as users by Image Hashes
| where host_count <= 3
| sort host_count executions
```

## 4. Tunneling / C2

### 4.1 Ngrok / Cloudflared

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\ngrok.exe" OR Image="*\\cloudflared.exe" OR CommandLine="*ngrok tcp*" OR CommandLine="*ngrok http*" OR CommandLine="*cloudflared tunnel*")
| table _time Computer User ParentImage Image CommandLine
```

### 4.2 SSH port forwarding

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\ssh.exe" OR Image="*\\plink.exe" OR Image="*\\putty.exe")
| where match(CommandLine,"(^|\\s)-[LRD](?:\\s+|[0-9*:])")
| table _time Computer User ParentImage Image CommandLine
```

### 4.3 Network connections from tunneling binaries

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
(Image="*\\ngrok.exe" OR Image="*\\cloudflared.exe" OR Image="*\\plink.exe")
| stats count values(DestinationHostname) as domains values(DestinationIp) as ips values(DestinationPort) as ports by Computer User Image
```

## 5. Defense Impairment

### 5.1 Defender/AV disabling

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
 CommandLine="*Set-MpPreference*DisableRealtimeMonitoring*"
 OR CommandLine="*DisableBehaviorMonitoring*"
 OR CommandLine="*sc stop WinDefend*"
 OR CommandLine="*net stop WinDefend*"
)
| table _time Computer User ParentImage Image CommandLine
```

### 5.2 Firewall disabling

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
 (Image="*\\netsh.exe" CommandLine="*advfirewall*" CommandLine="*state off*")
 OR CommandLine="*Set-NetFirewallProfile*"
 OR CommandLine="*Disable-NetFirewallRule*"
)
| table _time Computer User ParentImage Image CommandLine
```

### 5.3 Safe Mode manipulation

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\bcdedit.exe" CommandLine="*safeboot*"
| table _time Computer User ParentImage Image CommandLine
```

### 5.4 PowerTool / POORTRY / STONESTOP / KillAV references

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*powertool*" OR Image="*poortry*" OR Image="*stonestop*" OR Image="*killav*" OR CommandLine="*HeartCrypt*")
| table _time Computer User ParentImage Image CommandLine Hashes
```

### 5.5 DLL side-loading pattern

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
(
 (Image="*\\consent.exe" (ImageLoaded="*\\msimg32.dll" OR ImageLoaded="*\\wmsgapi.dll"))
 OR (Image="*\\icardagt.exe" ImageLoaded="*\\version.dll")
 OR (Image="*\\mfpmp.exe" ImageLoaded="*\\rtworkq.dll")
)
NOT ImageLoaded="C:\\Windows\\System32\\*"
NOT ImageLoaded="C:\\Windows\\SysWOW64\\*"
| table _time Computer User Image ImageLoaded Signed SignatureStatus Hashes
```

## 6. Collection / Exfiltration

### 6.1 Rclone / WinSCP / FileZilla / PSCP / MEGA

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*rclone*" OR Image="*winscp*" OR Image="*filezilla*" OR Image="*pscp*" OR Image="*mega*")
| table _time Computer User ParentImage Image CommandLine Hashes
```

### 6.2 Archive creation utilities

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\rar.exe" OR Image="*\\winrar.exe" OR Image="*\\7z.exe" OR Image="*\\7za.exe")
| stats count values(CommandLine) as commands min(_time) as first_seen max(_time) as last_seen by Computer User Image
| convert ctime(first_seen) ctime(last_seen)
```

### 6.3 Archive and transfer tooling in the same fixed two-hour bucket

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
 Image="*\\rar.exe" OR Image="*\\winrar.exe" OR Image="*\\7z.exe" OR Image="*\\7za.exe"
 OR Image="*rclone*" OR Image="*winscp*" OR Image="*filezilla*" OR Image="*pscp*"
)
| eval stage=case(
    match(lower(Image), "(rar|winrar|7z|7za)"), "archive",
    match(lower(Image), "(rclone|winscp|filezilla|pscp)"), "exfil",
    true, "other")
| bin _time span=2h
| stats dc(stage) as stages values(stage) as stage_list values(Image) as images values(CommandLine) as commands by _time Computer User
| where stages>=2 AND mvfind(stage_list,"archive")>=0 AND mvfind(stage_list,"exfil")>=0
```

## 7. Recovery Inhibition

### 7.1 Shadow-copy deletion

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
 (Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*")
 OR (Image="*\\wmic.exe" CommandLine="*shadowcopy*" CommandLine="*delete*")
 OR CommandLine="*Win32_Shadowcopy*Remove-WmiObject*"
)
| table _time Computer User ParentImage Image CommandLine
```

### 7.2 Boot/recovery tampering

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\bcdedit.exe"
(CommandLine="*recoveryenabled no*" OR CommandLine="*bootstatuspolicy*ignoreallfailures*" OR CommandLine="*safeboot*")
| table _time Computer User ParentImage Image CommandLine
```

## 8. Ransomware Deployment / Impact

### 8.1 PsExec / PSEXESVC

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\psexec.exe" OR Image="*\\psexec64.exe" OR Image="*\\psexesvc.exe" OR CommandLine="*PSEXESVC*")
| table _time Computer User ParentImage Image CommandLine Hashes
```

### 8.2 Akira-associated file extensions

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
(TargetFilename="*.akira" OR TargetFilename="*.arika" OR TargetFilename="*.powerranges")
| stats count values(TargetFilename) as files values(Image) as processes by Computer User
| sort - count
```

### 8.3 Akira ransom note

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
(TargetFilename="*\\akira_readme.txt" OR TargetFilename="*\\akira.readme.txt" OR TargetFilename="*\\powerranges.txt" OR TargetFilename="*\\akiranew.txt")
| table _time Computer User Image TargetFilename Hashes
```

## 9. Multi-Stage Detection Strategy

A production analytic can become significantly more useful when the SOC correlates multiple stages rather than alerting on each tool in isolation.

Suggested stages:

```text
Credential Access
AD / Network Discovery
RMM / Tunneling
Defense Impairment
Collection / Exfiltration
Recovery Inhibition
Remote Deployment / Encryption
```

Correlate these by `Computer`, `User`, source host and incident window. A single `net localgroup administrators` or TeamViewer process should generally carry much less weight than a sequence such as:

```text
SharpHound
→ LSASS dump
→ AnyDesk from an unusual path
→ Rclone
→ vssadmin delete shadows
→ PSEXESVC
```

## 10. Source-Linked Campaign Hunts

### 10.1 AnyDesk SafeBoot service registration

**Telemetry:** Sysmon registry Event 13, collected by configuration. **Review:** legitimate troubleshooting can register services; escalate with unplanned reboot and security-service gaps. This detects registration; it does not assert the host actually entered Safe Mode.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
TargetObject="*\\Control\\SafeBoot\\Network\\AnyDesk\\*" Details="Service"
| table _time Computer User Image TargetObject Details
```

### 10.2 AD export files

**Telemetry:** Sysmon Event 11, including ProgramData. **Review:** inventory tools can create both files. The fixed bucket can miss a pair crossing a boundary; tune scheduling and correlate account/process GUID before alerting.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
(TargetFilename="C:\\ProgramData\\AdUsers.txt" OR TargetFilename="C:\\ProgramData\\AdComp.txt")
| bin _time span=30m
| stats dc(TargetFilename) as kinds values(TargetFilename) as files values(Image) as images by Computer _time
| where kinds=2
```

### 10.3 Archive followed by S3 transfer command — ordered interval

**Basis:** observed archive and transfer tradecraft. **Telemetry:** Sysmon process creation. **Review:** backup jobs are expected; use the destination account/bucket, user and schedule. `sort 0` can be expensive: constrain hosts/time in large deployments. `streamstats` limits may truncate high-volume windows. Correlation establishes command order, not file identity or completed exfiltration.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1d
(Image="*\\7z.exe" OR Image="*\\7za.exe" OR Image="*\\rar.exe" OR Image="*\\winrar.exe" OR Image="*\\s5cmd.exe")
| eval stage=if(match(lower(Image),"s5cmd[.]exe$"),"transfer","archive")
| sort 0 + _time
| streamstats current=f time_window=2h latest(eval(if(stage="archive",_time,null))) as archive_time by Computer User
| where stage="transfer" AND isnotnull(archive_time) AND _time>archive_time AND _time-archive_time<=7200
    AND match(CommandLine,"(?i)s3://") AND match(CommandLine,"(?i)\\b(cp|sync|run)\\b")
| table _time Computer User archive_time Image CommandLine
```

### 10.4 ESX Admins security-group changes

**Telemetry:** Windows **Security** audit logs on domain controllers, not Sysmon. Field extraction varies; `TargetUserName` is the group in these event types. **Review:** legitimate provisioning; investigate unexpected recreation and privileged membership. Hypervisor events are needed to prove follow-on access.

```spl
index=windows sourcetype="XmlWinEventLog:Security" earliest=-7d
EventCode IN (4727,4731,4754,4728,4732,4756) TargetUserName="ESX Admins"
| table _time Computer EventCode SubjectUserName TargetUserName MemberName MemberSid
```

### 10.5 Driver loading near suspicious service creation

**Basis:** reported POORTRY/STONESTOP. **Telemetry:** Sysmon Event 6 for driver load plus Windows System Event 7045 for services. **Review:** signed drivers may still be malicious; legitimate driver updates are frequent. This broad hunt identifies candidates, not BYOVD exploitation or proof of EDR termination. Obtain the driver hash, signer validation, service path and subsequent security-agent health.

```spl
index=windows earliest=-1d
((sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=6)
 OR (sourcetype="XmlWinEventLog:System" EventCode=7045))
| eval activity=if(EventCode=6,"driver","service")
| bin _time span=10m
| stats dc(activity) as kinds values(ImageLoaded) as drivers values(Hashes) as hashes
        values(Signature) as signatures values(ServiceName) as services values(ImagePath) as paths by Computer _time
| where kinds=2
```
