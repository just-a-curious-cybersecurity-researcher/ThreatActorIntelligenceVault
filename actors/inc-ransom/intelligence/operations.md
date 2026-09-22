# INC Ransom — Operations

**Presentation reviewed:** 2026-09-22.

These stages combine documented INC incidents. They are not a mandatory sequence inside one binary. The [encryptor analysis](encryptor.md) distinguishes payload routines from affiliate tooling.

## 1. External Reconnaissance

Reported entry paths make exposed VPN, remote desktop and edge-management services a priority for investigation. Access can also arrive through a broker after someone else performed reconnaissance.

An exposed service is an opportunity, not proof that INC scanned it. Preserve perimeter authentication and appliance logs; the eventual encrypted endpoint may contain little evidence of the original entry.

## 2. Initial Access

Secureworks associates GOLD IONIC with Citrix NetScaler exploitation. Later reporting includes other edge/RMM products, valid accounts and phishing. The [vulnerability register](../technical/vulnerabilities.md) separates supported associations from broader claims and incorrect product labels.

A successful login with a stolen account may resemble normal administration. Correlate source, device, MFA/session changes and first internal connections. The date encryption was discovered is not necessarily the compromise date.

A quiet interval in the September 2026 Huntress case supports investigating an access handoff, but does not prove a broker transaction.

## 3. Execution and Foothold

RDP and remote administration utilities give operators an interactive foothold. AnyDesk, ScreenConnect and similar signed tools acquire significance through the installer, session owner and subsequent activity.

Early Huntress reporting describes payload staging through Windows administrative mechanisms. A file in Windows Temp is not automatically the first-stage implant. Establish arrival time, copying account and launch lineage.

## 4. Credential Access

The collected research covers Mimikatz/lsassy, directory-database tools and Veeam credential extraction. They are separate utilities or scripts rather than assumed encryptor functions.

The newer Veeam script supports salted DPAPI-protected data and target-specific connection settings. Backup application access can therefore expose credentials useful elsewhere in the environment.

Investigate suspicious PowerShell around Veeam, LSASS access and directory-database acquisition, then correlate subsequent authentication. Do not use a leaked incident password as an actor signature.

## 5. Discovery and Active Directory Reconnaissance

NetScan and Advanced IP Scanner find systems and services; AdFind, net and nltest expose domain structure, accounts and trust relationships. Operators use these results to identify servers, shares, administrative paths and recovery infrastructure.

A new remote session followed by enumeration, scanning and connections to file servers is more useful than a scanner filename alone. Compare activity with the host's administrative role and expected accounts.

## 6. Privilege Escalation

The official regional advisory describes account-based expansion, including new administrative accounts. Distinguish local changes from domain privilege changes and trace the authorizing identity.

Execution through an elevated service proves authority at that point, not the mechanism that obtained it. Likewise, the payload's service-control API access is not evidence of a local exploit.

## 7. Lateral Movement

Documented deployment includes RDP, WMI, administrative shares and PsExec. The early Huntress case includes Windows Temp staging and a PsExec-related service called winupd.

Join network logon, share access, file creation, service installation and process execution across source and destination. Renaming PsExec does not erase its resulting service activity.

Later reporting describes Impacket atexec and temporary tasks. Historical task logs matter because an operator can remove a task before responders inspect the current configuration.

## 8. Defense Evasion

Operators have impaired protection through Windows components and separate termination utilities. Huntress documented SystemSettingsAdminFlows-associated Defender changes; other cases involve HRSword and vulnerable-driver loaders.

Reported drivers include filwfp.sys, filnk.sys and fildds.sys, and a separate HWAuidoOs2Ec.sys/HwAudio chain. Confirm hash, signature, service configuration, loading and security-product interruption rather than treating the filename as proof of exploitation.

Renamed edr.exe and HealthUpdater.exe require binary classification. They must not automatically be called encryptor modules.

## 9. Persistence and Remote Access

Remote-management agents and scheduled execution maintain access across sessions. The February 2026 reporting includes Recovery Diagnostics; the September case includes a script under Vendettister communicating with an external domain.

The payload's dmksvc/SafeBoot path supports its own boot transition. It is a different mechanism from an affiliate's persistent remote access.

Preserve task XML, service ImagePath, creator and timestamps. “Update,” “recovery” and “health” names do not establish legitimacy.

## 10. Command and Control / Tunneling

AnyDesk, ScreenConnect, TeamViewer and framework agents provide operator control in collected reporting. Their provider infrastructure is not automatically actor-owned.

INC's negotiation onions serve extortion, not necessarily payload C2. For PuTTY/Bitvise leads, require forwarding or session evidence before describing a tunnel.

Correlate newly installed remote access, outbound sessions and subsequent privileged actions. Tenant and operator identifiers are more useful than indiscriminately blocking a shared vendor.

## 11. Collection and Exfiltration

Operators stage sensitive data, often with 7-Zip, and transfer it using cloud clients. Early incidents include MEGASync; later reporting includes Rclone and Restic.

Renamed Restic winupdate.exe is especially important. It creates encrypted backup objects in an attacker-selected repository, including Wasabi-hosted storage in reported incidents. That archive encryption is separate from INC encrypting the original victim files.

Collect repository arguments, configuration, scheduling, cloud audit events and upload volume. Normal process-creation logs do not reliably expose all AWS or RESTIC environment variables. Shared storage services should be assessed at the account/bucket level.

## 12. Recovery Inhibition

Separate payload shadow-copy manipulation and application shutdown from operator actions against backup systems. Veeam credential theft is not itself evidence of backup deletion.

Confirm job disruption, retention changes, storage deletions and immutable-copy status in the recovery platform. Direct API-based actions may have no vssadmin process. Preserve intact encrypted-file endings before testing a decryptor.

## 13. Ransomware Deployment and Impact

Affiliates launch the payload using previously obtained access. A February 2026 example used win.exe under PerfLogs with shutdown, hidden-console and medium-mode arguments.

.INC filenames, INC-README notes, printing and wallpaper changes accompany reported execution. On ESXi, encrypting host-accessible VM disks can affect multiple guests without a Windows process inside each one.

Confirm actual file damage; a note alone does not prove complete encryption. Stopping the payload also does not undo earlier exfiltration.

## Operational Detection Principle

Prioritize chains across identity, endpoint, storage and outbound telemetry: unusual access, discovery, credentials, impaired recovery/security, upload and deployment. [Copyable queries](../detections/Detections.md) provide investigative pivots, not an actor verdict.

## Evidence Anchors for the Lifecycle

Huntress 2023 anchors early staging and deployment; Secureworks supplies intrusion context. Cybereason, independent classic analysis and GuidePoint cover payload/file behavior. The official 2026 regional advisory supports affiliate organization and account abuse.

Sample capability and incident observation are different evidence classes. Neither should silently substitute for the other.

## Additional Case Evidence

### Recovery of exfiltrated copies is different from decrypting original files

Cyber Centaurs' January 2026 investigation describes recovery of data from twelve organizations through attacker-used Restic repositories. In its initial engagement, Restic artifacts were present even though the reported data movement used another path. The evidence supports investigating prepared tooling separately from completed exfiltration.

The recovery concerned stored copies and repository configuration. It did not demonstrate a cryptographic break in INC or restoration of every encrypted original. Investigators may need to reconcile recovered versions, timestamps and application consistency with the affected organization's own records.

### Affiliate deployment in healthcare

Microsoft identifies Vanilla Tempest as a financially motivated actor using INC obtained through RaaS providers against US healthcare. This is a deployment relationship, not another name for the INC core. Preserve the distinction between an access provider, an intrusion operator and the malware service.

### Earlier incident ordering


The February 2026 Huntress cases expand exfiltration coverage with renamed Restic and scheduled execution. Cyber Centaurs independently discusses backup infrastructure. September reporting adds a driver-loader chain, temporary-task execution and differently timed ransom notes.

Publication dates, incident dates and present infrastructure availability remain distinct.

### Published chronology as a check on assumed sequence

The early Huntress incident spans roughly a week: initial observable remote access and domain discovery preceded archive staging; broader deployment came later. The February 2026 case separates scheduled Restic preparation from subsequent security-product impairment and payload execution. These accounts show why encryption time alone is an inadequate starting point for log preservation.

A scheduled upload may run under a different context from the operator's interactive session. Correlate task registration, scheduled execution, mapped resources and actual outbound transfer. Local paths and mapped drive letters can change between accounts, so a script's configured source is not proof that every intended file was accessible.

## Negotiation and Organizational Signals

The official advisory describes affiliates conducting intrusions while the core manages extortion infrastructure and payments. Private negotiation and public leak posting serve different functions.

The second-note case demonstrates escalation beyond an encryption notice. A threatened deadline or publication does not by itself confirm that every threatened disclosure occurred.
