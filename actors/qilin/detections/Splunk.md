# Qilin — Splunk Hunting Queries

**Status:** reviewed defensive hunts, not production alerts or Qilin attribution signatures. Reviewed 2026-09-10. No connected query backend was available; validation is static. Each hunt states source, sensor assumptions and tuning.

MDE queries require the named Defender for Endpoint tables. SHA256 may be empty; preserve SHA1 and process identity in pivots. Registry/path representations and ActionType support need tenant verification. Splunk examples assume Windows XML extraction, `index=windows`, `Computer`, `User`, `Image`, `CommandLine`, `TargetFilename` and the stated EventCode/sourcetype. Configure Sysmon collection first; Event 4104 uses PowerShell logging and may require block-fragment reassembly. No query scans hypervisor logs implicitly.

Avoid blanket tool allowlists. Combine approved owner, instance/tenant, hash/signer, path and maintenance window. Time buckets are co-occurrence; none of these aggregates proves stage ordering. Process ancestry can be deeper than the fields shown. See [coverage and limitations](Detections.md).

## Q01 — Unexpected logon scripts written into SYSVOL

**Evidence:** [Q11](../References.md#q11).  
**Telemetry:** MDE file events or Sysmon Event 11; collect SYSVOL paths on DCs.

**Review / tuning:** Approved policy maintenance and deployment scripts can match. Confirm policy version/owner, writer identity and endpoint execution. SYSVOL replication can duplicate events; a write is not proof a GPO was linked.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
TargetFilename="*\\SYSVOL\\*" (TargetFilename="*\\IPScanner.ps1" OR TargetFilename="*\\logon.bat")
| table _time Computer User Image ProcessGuid TargetFilename
```

## Q02 — Credential output staged back into SYSVOL

**Evidence:** [Q11](../References.md#q11).  
**Telemetry:** MDE file creation/modification or Sysmon Event 11.

**Review / tuning:** LD and temp.log are generic names. Stronger context is new host-specific directories and the Q01 logon script; baseline replication and administration. Fixed buckets can miss pairs crossing boundaries.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
TargetFilename="*\\SYSVOL\\*" (TargetFilename="*\\LD" OR TargetFilename="*\\temp.log")
| eval artifact=if(match(TargetFilename,"(?i)\\\\LD$"),"LD","temp.log")
| bin _time span=30m
| stats dc(artifact) as kinds values(TargetFilename) as files values(Image) as producers by Computer _time
| where kinds=2
```

## Q03 — WDigest plaintext retention enabled

**Evidence:** [Q15](../References.md#q15).  
**Telemetry:** MDE RegistryValueSet or Sysmon registry Event 13.

**Review / tuning:** Legacy compatibility/security labs can match. Registry change makes future credential exposure possible; it is not evidence a password was dumped. Verify OS behavior and follow-on credential tooling.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-7d
TargetObject="*\\SecurityProviders\\WDigest\\UseLogonCredential"
| where match(Details,"(?i)(0x00000001|DWORD.*\\b1\\b)")
| table _time Computer User Image TargetObject Details
```

## Q04 — Credential toolkit and output orchestration

**Evidence:** [Q15](../References.md#q15).  
**Telemetry:** Process creation; script block/module logs improve renamed-tool visibility.

**Review / tuning:** NirSoft and Mimikatz have legitimate forensic/assessment uses. Prioritize new accounts/paths and proximity to WDigest changes or SMTP output. Filenames alone are evadable and not actor attribution.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
(Image="*\\netpass.exe" OR Image="*\\WebBrowserPassView.exe" OR Image="*\\BypassCredGuard.exe" OR Image="*\\mimikatz.exe"
 OR CommandLine="*SharpDecryptPwd*" OR CommandLine="*!light.bat*" OR CommandLine="*pars.vbs*")
| table _time Computer User Image ParentImage CommandLine Hashes ProcessGuid
```

## Q05 — ScreenConnect instance installed through an existing RMM session

**Evidence:** [Q22](../References.md#q22).  
**Telemetry:** Process ancestry and installation command; verify software installation and RMM tenant logs.

**Review / tuning:** Legitimate agent rollout and upgrades are common. The suspicious distinction is an unapproved instance/customer identifier or control endpoint. ru.msi alone is insufficient; do not mistake this for a product exploit.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
Image="*\\msiexec.exe" (CommandLine="*ru.msi*" OR CommandLine="*ScreenConnect*")
| where match(ParentImage,"(?i)ScreenConnect") OR match(ParentCommandLine,"(?i)ScreenConnect")
| table _time Computer User ParentImage ParentCommandLine CommandLine
```

## Q06 — Cyberduck connection to Backblaze

**Evidence:** [Q15](../References.md#q15).  
**Telemetry:** MDE network events; Splunk Sysmon Event 3 requires DestinationHostname enrichment.

**Review / tuning:** Authorized backups and migrations match. Connection alone does not establish direction or bytes uploaded; obtain Cyberduck history, destination bucket/account and cloud audit. No hostname means this query can miss an event.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-7d
Image="*\\Cyberduck.exe" (DestinationHostname="*.backblazeb2.com" OR DestinationHostname="backblazeb2.com")
| table _time Computer User Image DestinationHostname DestinationIp DestinationPort ProcessGuid
```

## Q07 — RMM-launched domain reconnaissance

**Evidence:** [Q22](../References.md#q22), [Q23](../References.md#q23).  
**Telemetry:** Endpoint process ancestry; collect parent and grandparent when available.

**Review / tuning:** MSPs legitimately enumerate domains. Review tenant/customer scope, session administrator, schedule and neighboring agent installations. Parent process checks can miss deeper shells; pivot on process tree.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
(CommandLine="*/domain_trusts*" OR CommandLine="*/dclist*" OR CommandLine="*domain admins*")
| where match(ParentImage,"(?i)(ScreenConnect|SRManager)") OR match(ParentCommandLine,"(?i)ScreenConnect")
| table _time Computer User Image ParentImage ParentCommandLine CommandLine
```

## Q08 — Qilin restoration-task or Run-key artifacts

**Evidence:** [Q15](../References.md#q15).  
**Telemetry:** Process creation for task commands; registry telemetry for Run value content.

**Review / tuning:** TeamViewer installation/repair is legitimate. Require task name plus restoration argument, or suspicious encryptor-style arguments in a Run value. Renamed task/payload can evade; generic --password alone is weak.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-7d
((EventCode=1 Image="*\\schtasks.exe" CommandLine="*TVInstallRestore*" CommandLine="*/RESTORE*")
 OR (EventCode=13 TargetObject="*\\Microsoft\\Windows\\CurrentVersion\\Run\\*" Details="*--password*" Details="*--no-admin*"))
| table _time Computer User Image CommandLine TargetObject Details
```

## Q09 — Safe Mode and recovery-inhibition commands

**Evidence:** [Q12](../References.md#q12), [Q22](../References.md#q22).  
**Telemetry:** Process command lines; validate boot/System logs and VSS audit separately.

**Review / tuning:** Disaster-recovery testing and maintenance can match. The aggregate is co-occurrence, not an ordered attack chain. Require unapproved change context and preserve pre-reboot telemetry.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
((Image="*\\bcdedit.exe" CommandLine="*safeboot*" CommandLine="*/set*")
 OR (Image="*\\vssadmin.exe" CommandLine="*delete*shadows*")
 OR (Image="*\\wevtutil.exe" (CommandLine="* cl *" OR CommandLine="*clear-log*")))
| bin _time span=30m
| stats count values(Image) as tools values(CommandLine) as commands by Computer User _time
```

## Q10 — PowerShell vCenter cluster and hypervisor changes

**Evidence:** [Q15](../References.md#q15).  
**Telemetry:** Command-line hunting on management hosts; ScriptBlockText query for Splunk Event 4104.

**Review / tuning:** Authorized PowerCLI maintenance is expected. Commands read from a script may not appear on the command line; KQL coverage is intentionally partial. Confirm vCenter tasks, principal, SSH changes and time before treating HA/DRS changes as malicious.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 earliest=-7d
(ScriptBlockText="*execInstalledOnly*" OR (ScriptBlockText="*Set-Cluster*" (ScriptBlockText="*HAEnabled*" OR ScriptBlockText="*DrsEnabled*")))
| table _time Computer UserID ScriptBlockId MessageNumber MessageTotal ScriptBlockText
```

## Q11 — Ransom-note creation with variable company identifier

**Evidence:** [Q09](../References.md#q09), [Q12](../References.md#q12), [Q31](../References.md#q31).  
**Telemetry:** MDE file events or Sysmon Event 11.

**Review / tuning:** Recovery simulations, research archives and restored notes match. Match either ordering; do not require a fixed ten-character extension. Alerting needs creator/process/volume context and evidence of actual file impact.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
| where match(TargetFilename,"(?i)(?:^|\\\\)(?:README-RECOVER-[^\\\\]+|[^\\\\]+-RECOVER-README)[.]txt$")
| table _time Computer User Image TargetFilename ProcessGuid
```

## Q12 — QLOG encryptor-worker artifacts

**Evidence:** [Q15](../References.md#q15).  
**Telemetry:** File-creation telemetry; writes must be enabled for temp paths.

**Review / tuning:** Unrelated software can use QLOG/ThreadId names. The combined directory and exact filename structure is stronger; correlate with note drops, share writes and known sample hashes. Presence is not proof encryption completed.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-7d
TargetFilename="*\\QLOG\\*"
| where match(TargetFilename,"(?i)ThreadId\\([0-9]+\\)[.]LOG$")
| table _time Computer User Image TargetFilename ProcessGuid
```

## Q13 — Reported driver and DLL artifacts

**Evidence:** [Q15](../References.md#q15), [Q23](../References.md#q23).  
**Telemetry:** MDE file events; Splunk Sysmon driver-load Event 6. The platforms detect different stages.

**Review / tuning:** Legitimate utilities may include similarly named drivers. A file drop is weaker than an actual load. Verify hash/signature, service owner, driver behavior and nearby endpoint-agent termination; no kernel exploit is inferred solely from name.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=6 earliest=-7d
(ImageLoaded="*\\eskle.sys" OR ImageLoaded="*\\rwdrv.sys" OR ImageLoaded="*\\hlpdrv.sys" OR ImageLoaded="*\\dark.sys")
| table _time Computer ImageLoaded Hashes Signed Signature SignatureStatus
```

## Q14 — Linux-payload or WSL clues under RMM ancestry

**Evidence:** [Q23](../References.md#q23).  
**Telemetry:** Windows process ancestry only; Linux/WSL auditing required to verify execution.

**Review / tuning:** WSL is legitimate developer infrastructure. This is a hypothesis-oriented hunt for the report’s unresolved execution path, not a confirmed Qilin WSL technique. A transferred ELF file may never execute locally; investigate remote target and process tree.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-7d
(Image="*\\wsl.exe" OR Image="*\\bash.exe" OR CommandLine="*mmh_linux_x86-64*")
| where match(ParentImage,"(?i)(SRManager|MeshAgent)") OR match(ParentCommandLine,"(?i)(SRManager|MeshAgent)")
| table _time Computer User Image ParentImage ParentCommandLine CommandLine
```
