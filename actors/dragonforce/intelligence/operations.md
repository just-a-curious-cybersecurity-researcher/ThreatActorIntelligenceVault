# DragonForce — Operational Lifecycle

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

DragonForce intrusions vary by affiliate. The sequence below separates behavior seen in DragonForce-ending incidents from capabilities of named affiliates and from malware-only behavior.

## 1. External Reconnaissance

Affiliates identify internet-facing remote-access appliances, exposed RMM servers and organizations whose help desks can be socially engineered. Huntress observed repeated malformed Citrix authentication attempts before session replay in 2026; Sophos linked exploitation of an MSP’s SimpleHelp deployment to downstream compromise. Scattered Spider-linked cases instead build employee and help-desk context for convincing identity-reset calls.

Network discovery can continue after entry with NetScan/Netscanold, ADExplorer or native name-resolution and host-enumeration commands. Backdoor.Turn also implements scanning, TLS-title collection and LDAP/Active Directory discovery.

## 2. Initial Access

No single initial vector belongs to all DragonForce affiliates.

- Scattered Spider-linked activity uses voice phishing, help-desk impersonation, password/MFA reset manipulation, SMS phishing and adversary-in-the-middle credential capture. Microsoft observed ngrok, Chisel and AADInternals around this access model.
- Huntress has high confidence that an access broker exploited CitrixBleed 2, CVE-2025-5777, in several 2026 cases. One downstream chain deployed DragonForce. The responder could not determine whether the broker and affiliate were identical.
- Sophos assessed with medium confidence that CVE-2024-57727, CVE-2024-57728 and CVE-2024-57726 in SimpleHelp were used against an MSP before DragonForce deployment to customer endpoints.
- Trend Micro associates exploitation of Ivanti CVE-2023-46805, CVE-2024-21887 and CVE-2024-21893, Log4Shell CVE-2021-44228 and Windows SmartScreen CVE-2024-21412 with Water Tambanakua reporting. Public case detail is thinner than for Citrix and SimpleHelp, so those entries remain “reported association.”
- Symantec’s December 2025 case likely began through an exposed Microsoft SQL service or purchased broker access; the source could not resolve which.

Huntress’s session chronology shows why successful authentication cannot be assessed from MFA alone. A legitimate employee completed LDAP plus OTP/MFA at 13:07 UTC from a known address; the same session was used from an adversary address at 13:28. The 21-minute source change is evidence of session replay, while the preceding malformed failures establish the exploit context. Detection therefore needs Citrix session/cookie continuity as well as login success/failure counts.

FortiGuard lists a much larger catalog of vulnerabilities under the actor profile. Those values are retained separately as catalog associations and are not represented as observed DragonForce exploitation.

## 3. Execution and Foothold

Observed chains use PowerShell, command shells, signed-binary side-loading and legitimate RMM software. In the Symantec case, actors side-loaded a malicious `vboxrt.dll` through a signed VirtualBox binary and also abused DbgView-associated loading. Huntress saw MSI-based installation of ScreenConnect and Zoho Assist after Citrix session replay; other hosts showed NetBird and Atera.

SimpleHelp compromise provided a direct RMM execution channel across an MSP/customer boundary. This is a high-impact route because a trusted management plane can deploy the locker without a separate endpoint exploit.

The service-side workflow begins after access is supplied. Group-IB observed affiliates create a victim/client record, select the native Conti-derived or then-available LockBit-derived builder, configure scope, suffix, note, exclusions, payment/test-decrypt window and EDR/XDR driver, and download victim-specific Windows/ESXi outputs. The panel separately tracks negotiation and publication. These steps explain why two DragonForce incidents can carry different visible artifacts while using the same backend.

## 4. Credential Access

Published tooling includes Mimikatz, LaZagne, PassView, registry-hive export and browser credential access. Scattered Spider-linked activity emphasizes identity control: resetting credentials and MFA, registering attacker-controlled factors and taking over privileged cloud or virtualization accounts. Backdoor.Turn includes browser credential extraction and credential-assisted lateral movement.

Analysts should distinguish presence from success. A hive export, LSASS access or credential utility execution is direct endpoint evidence; a later privileged login requires authentication logs to show the credential was usable.

## 5. Discovery and Active Directory Reconnaissance

AdFind and ADExplorer enumerate domains, users, groups and computers. NetScan/Netscanold and Backdoor.Turn survey address space and exposed services. Native commands observed in the Citrix-linked intrusion included `whoami`, `qwinsta` and `wmic`. The Conti-derived locker has its own network-encryption discovery path: it enumerates local ARP data, selects private addresses, tests TCP/445 and calls share-enumeration APIs while excluding `ADMIN$`.

This phase can be split between the operator’s tools and the encryptor. An SMB scan immediately before a ransom-note burst can be part of the locker itself.

## 6. Privilege Escalation

Huntress documented a SYSTEM escalation chain based on a registry symbolic-link technique involving AppMgmt. Case artifacts included `eng.exe`, `legal.exe`, `exsym.exe`, `as.exe` and `exp6.exe`; names are incident-specific. Resulting accounts included `ctxsvc`, `CtxAppVCOMService` and `test`.

The Conti-derived Windows locker can create or replace a scheduled task configured to run as SYSTEM when its embedded configuration enables that path. This behavior belongs to the binary and should be correlated with task creation and near-term encryption.

Scattered Spider cases often reach privileged access through identity administration rather than a local exploit. Help-desk reset, privileged-group modification and VMware management access are therefore part of privilege escalation even when no kernel vulnerability is used.

## 7. Lateral Movement

PsExec and Impacket/RemCom-style remote service execution are reported in incident response. RDP is used for interactive administration, and compromised RMM platforms can distribute payloads to many managed endpoints. The locker’s network-share mode can encrypt reachable SMB shares after TCP/445 testing.

VMware impact requires access to ESXi or management infrastructure. CISA and Microsoft describe Scattered Spider deployment against ESXi. The Linux branch enumerates VMs with `vim-cmd` and powers them off before encrypting datastore content; those commands describe payload execution after access, not the access method.

## 8. Defense Evasion

Operators use renamed tooling, signed-binary side-loading, process termination and driver-assisted security impairment. Symantec observed four vulnerable-driver families and one custom malicious driver:

- `HWAuidoOs2Ec.sys`, associated with a “Havoc Process Terminator” technique;
- `wsftprm.sys` exploiting CVE-2023-52271;
- `GameDriverx64.sys` associated with CVE-2025-61155;
- `K7RKScan.sys` associated with CVE-2025-1055;
- a custom Abyss Worker driver masquerading as Palo Alto software.

The Conti-derived locker can load `truesight.sys` or `rentdrv2.sys` and issue driver requests to terminate protected processes. If that option is unavailable, it enumerates processes and attempts direct termination. Published target lists include Microsoft Defender, database, backup and office processes; a process-stop event alone is not unique to DragonForce.

Configuration changes in the Symantec case allowed blank-password remote behavior and altered Windows Firewall rules. These changes expanded remote access and weakened local policy; they should be investigated as a sequence with new accounts and RMM installation.

S2W’s 2026 panel review found that the visible driver selector had been removed, but BYOVD termination remained compiled into generated payloads. A defender cannot infer absence of driver abuse from the newer panel interface or from a missing affiliate-selected driver field.

## 9. Persistence and Remote Access

Observed persistence includes scheduled tasks, new local accounts, group membership changes, RMM services and side-loaded DLL launch paths. The service ecosystem uses AnyDesk and SimpleHelp; individual cases used ScreenConnect, Zoho Assist, Atera and NetBird. Legitimate enterprise use is common, so detection must compare installer origin, signer, tenant and first-seen time.

Backdoor.Turn is a post-compromise Go backdoor associated by Symantec with Hackledorb. In the documented case it appeared after ransomware activity and provided command execution, discovery, LDAP queries, credential access and lateral-movement support. Its ordering shows that encryption did not necessarily end the intrusion.

## 10. Command and Control / Tunneling

Reported frameworks include Cobalt Strike and SystemBC. Scattered Spider-linked cases also use ngrok and Chisel. Backdoor.Turn obtained Microsoft Teams/Skype visitor credentials, used them to request TURN relay connectivity and then transported its real C2 traffic over QUIC. Teams infrastructure was a relay mechanism, not the ultimate command server.

Symantec associated `62.164.177[.]25` with Backdoor.Turn C2 and published several compromised or attacker-used domains. These indicators are campaign-scoped and should not be treated as permanent DragonForce infrastructure.

## 11. Collection and Exfiltration

Operators stage archives and transfer data using MEGA, FTP, SFTP or HTTP-based methods. Public tooling lists also include common archivers. Unit 42 documented a Muddled Libra case in which roughly 100 GB was exfiltrated in two days before extortion. The figure belongs to that incident, not a service-wide baseline.

The service’s 2025 data-analysis offer was designed to search large stolen datasets and extract leverage for revenue-based demands. Archived note text also states that the operator reviews income/insurance data and provides a stolen-file list during negotiation. Those statements support the extortion workflow but do not validate deletion promises.

## 12. Recovery Inhibition

The Windows locker can delete volume shadow copies and change boot/recovery configuration. Published analyses show invocation of Windows-native VSS, WMI/WMIC and BCD mechanisms; the detailed, non-executable event forms are retained in the encryptor documents and detections. Database and backup-related processes may be terminated before file access.

On ESXi, the Linux branch enumerates virtual machines, issues power-off operations and encrypts datastore content. Stopping a VM both releases file locks and increases operational impact.

## 13. Ransomware Deployment and Impact

The early LockBit-derived Windows branch accepts LockBit-like runtime options for local paths, shares, deletion and Safe Mode behavior. The later Conti-derived branch loads an encrypted configuration, prevents duplicate execution with a mutex, optionally creates a SYSTEM task, terminates configured processes, writes notes, discovers local and network targets, encrypts with ChaCha8 and protects per-file material with RSA-4096.

Encryption can be full, header-only or partial. In the analyzed Conti-derived build, database files receive full encryption while large files can be split across three regions. Sample thresholds were 2 MB for full processing and 10 MB for the header/partial decision. Modes, thresholds, extensions and ransom-note names are build-specific.

The 2026 beta builder can override the default mode per file extension. It expands the stored ratio from one to four bytes, changing the footer from 534 to 537 bytes. This is a version distinction with direct forensic impact: recovery tooling and file parsers must select the correct layout rather than treating either length as universal. The newer panel no longer exposed the LockBit builder, narrowing current generated output toward the maintained Conti-derived core.

Reported suffixes include `.locked`, `.dragonforce_encrypted`, `.RNP` and `.RNP_esxi`. A suffix identifies an observed build or victim configuration, not a universal family invariant.

## Operational Detection Principle

Use ordered correlations: new remote access or anomalous identity reset, privileged discovery, credential access, security impairment, high-volume share enumeration, recovery changes and a note/extension burst. Exact hashes and infrastructure are useful for confirmation but cover only published samples. Keep affiliate evidence and payload evidence in separate fields during triage.

## Evidence Anchors for the Lifecycle

- **CISA/Microsoft Scattered Spider advisories — named affiliate:** high-confidence social-engineering, cloud/VMware and deployment context.
- **Huntress CitrixBleed 2 cases — broker/affiliate chain:** authentication anomaly, session replay, SYSTEM escalation, RMM and one DragonForce payload.
- **Sophos SimpleHelp investigation — access/RMM supply chain:** internet-facing RMM exploitation and downstream deployment.
- **Symantec Backdoor.Turn case — Hackledorb-associated campaign:** side-loading, BYOVD, persistence, Teams TURN/QUIC and post-ransomware access.
- **S2W malware analysis — Conti-derived payload:** configuration, mutex, process termination, network enumeration, algorithms and footer.
- **S2W/Group-IB panel reviews — service workflow and versioning:** affiliate permissions, victim/build lifecycle, removal of LockBit output and the 537-byte beta revision.
- **Trend Micro spotlight — multi-branch payload/tooling:** command-line options, tools, Linux/ESXi behavior and reported CVEs.

## Additional Case Evidence

The UK retail cluster is operationally important because it demonstrates affiliate attribution limits. Social engineering and identity compromise align with Scattered Spider, while DragonForce provides the extortion layer. The NCA arrests confirm a linked investigation into the three attacks but do not identify the arrested people as service administrators.

The 2026 Citrix chain is equally important for a different reason: exploitation can be performed by a broker and sold onward. The initial exploit, post-exploitation and locker may belong to three commercial layers. An endpoint showing `1.exe` as the DragonForce payload should therefore not cause every earlier action to be labeled “DragonForce core.”

## Negotiation and Organizational Signals

The original archived note promises test decryption, a stolen-file list, a decryptor after BTC payment and a post-incident report. The later “cartel” note says the price is set using victim income and insurance data. Both notes use the same Tox identity and negotiation onion in the public archive.

The service’s commercial signals include an 80/20 affiliate split, white-label branding, large-dataset analysis and revenue thresholds. Rival DLS compromises, RansomHub/BlackLock disputes and the Devman split show that these arrangements are unstable. Negotiation language should be used for incident validation and threat modeling, not as evidence that the service honors deletion commitments.
