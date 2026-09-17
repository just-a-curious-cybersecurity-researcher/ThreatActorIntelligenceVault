# The Gentlemen — Operations and Attack Lifecycle

**Presentation reviewed:** 2026-09-17.

The lifecycle describes reported intrusion activity and executable capability. An affiliate can use only part of it, and some steps run concurrently.

```mermaid
flowchart LR
 A[External access] --> B[Foothold and discovery]
 B --> C[Privileged access]
 C --> D[Defense impairment]
 D --> E[Collection and transfer]
 E --> F[Coordinated deployment]
 F --> G[Encryption and extortion]
```

## 1. External Reconnaissance

The reviewed tool inventory includes internet-search services and internal scanners. Their roles differ: exposed-service discovery identifies entry opportunities; Advanced IP Scanner and Nmap map systems after entry. A reference to Censys or Shodan in a tool collection does not prove a particular victim was selected through that service.

## 2. Initial Access

Reported paths include exposed remote access and compromised credentials. Fortinet administrative interfaces are a recurrent concern. In Trend Micro's examined incident, the initial path is assessed rather than reconstructed from a confirmed exploit trace.

Unit 42 additionally reports brute-force access, leaked/stolen credentials and initial access brokers. Check Point's chats include edge-device access and reuse of OWA/Microsoft 365 credentials. These are program-level access paths, not a replacement for the unresolved entry sequence in the August case.

The CVE register separates perimeter flaws, local driver abuse and post-compromise privilege techniques. In particular, ThrottleStop is not a Fortinet vulnerability. Inventory scanning or discussion of a proof of concept is not successful exploitation.

## 3. Execution and Foothold

Native Windows utilities, encoded PowerShell and remote administration appear in the supplied case material. A password-gated encryptor is deployed later in the intrusion. Its invocation gate can prevent automatic detonation in a sandbox, but does not establish that all analysis is defeated.

In the Check Point incident, an internal server staged the image as `grand.exe`, downloaded to `C:\ProgramData\r.exe`. This is a case-specific delivery path, not a fixed filename for the family. The distinction between download, process creation and domain deployment matters when reconstructing the foothold.

Establish the initiating account and parent process for every executable. Operator shells, a process killer and the encryption worker have different responsibilities.

## 4. Credential Access

Check Point's reviewed chats contain credential-recovery utilities, authentication coercion and relay tooling. The toolset includes KslDump/KslKatz and DumpBrowserSecrets, plus NetExec and RelayKing-related workflows. Browser cookies and reusable web sessions extend the scope beyond Windows password hashes. Tool discussion establishes availability/intent; it does not prove every module was executed in every intrusion. Domain or administrative credentials enable subsequent PsExec and policy activity.

Authentication-policy edits affect future authentication behavior. Changing RestrictSendingNTLMTraffic or DisableRestrictedAdmin is not itself proof that credentials were dumped.

## 5. Discovery and Active Directory Reconnaissance

Advanced IP Scanner and Nmap provide host and service visibility. The supplied 1.bat example enumerates numerous domain users and privileged groups, including virtualization-related accounts. The operational objective is to identify administrative paths and valuable storage before deployment.

The same case records two encoded PowerShell commands whose decoded content selects `PDCEmulator` from `Get-ADDomain`. This identifies critical domain infrastructure before policy editing. A command-line hunt should cover both decoded content and the published encoded fragments, while preserving script-block records where available.

The command fragments in the original notes lack the leading net executable in several places. They are interpreted as net user/group queries rather than literal standalone Windows commands.

## 6. Privilege Escalation

PowerRun was used for privileged operations in the reported campaign; the evidence does not establish that PowerRun itself was modified. The tailored component was the process-killing tool.

The encryptor's SYSTEM mode creates a scheduled execution context only when launched with sufficient administrative rights. It is not an unauthenticated privilege-escalation exploit. Driver-based protection impairment is a separate supporting component.

## 7. Lateral Movement

PsExec and domain policy facilities distribute execution. GPO/NETLOGON activity can expose many hosts to one privileged change, while share encryption can damage remote data from a single process.

The locker accepts an explicit credential context or the current session for its spreading mode. This capability must be distinguished from an observed successful remote execution. Remote service events, authentication and resulting child processes provide the sequence.

The built-in propagation routine stages through `C:\Temp` and `share$`, then attempts PsExec, WMIC, tasks, services and PowerShell-based remote execution. The named task families `DefU`/`DefS` and `UpdateGU`/`UpdateGS` are distinct from local restart tasks. A repeated remote logon can reflect separate attempted routes to the same host; it is not automatically a new affiliate.

The Trend Micro case shows GPMC/GPME use and a NETLOGON-distributed payload. Check Point additionally documents GPO execution during policy refresh and an explicit GPO option in its analyzed build. Directory policy changes, share writes and endpoint execution should be collected as separate evidence.

## 8. Defense Evasion

The case material describes All.exe with ThrottleBlood.sys, followed by Allpatch2.exe adapted to the encountered protection. These tools target security processes outside the main file-encryption routine.

Separate registry changes loosen NTLM/RDP restrictions. RestrictSendingNTLMTraffic=0 permits outbound NTLM; DisableRestrictedAdmin=0 enables Restricted Admin behavior; SecurityLayer=1 selects negotiated RDP security rather than proving that TLS or NLA is universally disabled.

The encryptor itself also attempts Defender preference changes and deletion of event/log artifacts. Successful impairment depends on privilege and active protection. The remote-preparation routine also changes firewall profiles, SMB1 availability and anonymous-share policy. Driver-file creation does not establish a loaded driver; obtain load/signature records and security-service outcomes.

The EDRStartupHinder, gfreeze and glinker names are supported by the reviewed chat toolset. Unit 42 later names GentleKiller, but supplies no reproducible rule or sample identity in that passage. The name is retained as vendor-reported tooling without fabricating a hash or a family-specific signature.

## 9. Persistence and Remote Access

AnyDesk supports continuing operator access. Registry autoruns and scheduled tasks can restart the payload. A machine can therefore retain remote administration even after removal of the encryptor.

Firewall changes and remote-access settings require account and process correlation. An installed legitimate signed tool does not establish that the session was authorized. Check Point's chats also describe a new Okta service account during the Turkish-company intrusion. That is identity-platform persistence; it cannot be ruled out by cleaning the Windows host alone.

## 10. Command and Control / Tunneling

The supplied inventory includes Chisel-ng, ProxyChains, openconnect and Tor-related communication. These are different transport mechanisms, not a single permanent C2 stack. Check Point additionally documents SystemBC in an affiliate case; infrastructure is retained as historical case evidence. Its proxy role is separate from the locker: surviving proxy access can outlast encryption. Cloudflare tunnels and VPN setups appear in the internal tool discussions. A trusted cloud service or signed client does not establish authorization for a tunnel.

The onion leak/negotiation service is not automatically the endpoint used by every compromised host.

## 11. Collection and Exfiltration

The supplied campaign notes identify WinSCP as the likely transfer utility and WebDAV as a possible internal collection path. Keep transfer execution, bytes leaving the network and an adversary theft claim distinct.

Rclone and MANSPIDER appear in the broader tool inventory. Their presence supports investigation, not proof that each was used in the Trend Micro case. The 2025 investigation identifies `C:\ProgramData\data` as a possible consolidation directory and `davclnt.dll,DavSetCookie` WebDAV activity. The report explicitly leaves legitimate alternatives open; neither a Zone.Identifier stream nor WebDAV initialization proves theft.

## 12. Recovery Inhibition

The Windows binary attempts shadow-copy removal and event-log clearing. It also deletes selected execution and support artifacts. Supporting process/service termination can interrupt databases and backups before encryption.

Separate the pre-encryption attempts to remove snapshots from the optional post-encryption free-space routine. `wipefile.tmp` activity can indicate the latter; it is not a snapshot name. In ESXi, VM shutdown and autostart suppression affect workload recovery, while guest security agents do not observe all hypervisor actions.

A deletion request is not proof that offline backups, snapshots on other systems or all forensic evidence were removed. The claims in ransom notes are not a backup assessment.

## 13. Ransomware Deployment and Impact

Policy-based distribution and remote administration coordinate deployment. The Windows binary distinguishes local SYSTEM processing from user-visible shares. Small files are fully encrypted in the documented sample; larger files use partial regions. Therefore the supplied statement that all files are partially encrypted is corrected.

README-GENTLEMEN.txt, the sample-specific .7mtzhh/.umc16h suffixes and gentlemen.bmp are useful artifacts, but silent operation can suppress some visible changes. Follow the [binary analysis](encryptor.md) for the execution branches.

## Operational Detection Principle

Prioritize connected evidence: privileged discovery, security impairment, task/policy changes, transfer and mass file modification. Generic commands identify behavior; sample hashes and process ancestry bind that behavior to an executable.

## Evidence Anchors for the Lifecycle

The August 2025 incident underlies the adaptive-tooling narrative. Microsoft's 2026 analysis describes a Windows sample's capability. Internal chats describe plans, shared tools and organizational discussion. These are complementary evidence classes and are not merged into one observed attack.

## Additional Case Evidence

Check Point's SystemBC investigation extends the infrastructure picture beyond the locker. A proxy server's client population is not a count of confirmed The Gentlemen encryption victims. In particular, the reported SystemBC population above 1,570 is a visibility measure for related infrastructure, not a verified tally of encrypted organizations. The historical endpoints and identified companion hash are retained in the [IOC index](../iocs/IOCs.md).

Huntress's April–May 2026 cases add post-incident evidence: NETLOGON/Configuration Manager deployment, failed Defender remediation, and a renamed SOCKS client with WindowsConnSvc task persistence attempts. Repeated task failures show why registration is not execution. Its workstation-name overlap with other reports does not establish common ownership.

Group-IB's March analysis directly supports the ArmCorp lineage and Fortinet access discussion. It also documents PowerShell Web Access configuration. Kaspersky's June report adds native packet capture and a separate Go backdoor; these are pre-encryption activities rather than proof that the locker itself steals documents.

## Negotiation and Organizational Signals

The program combines encryption with threatened publication. Check Point describes a UK consultancy case in which stolen business material was reused to support a later intrusion against a company in Turkey. The chats discuss legal and reputational pressure as well as file decryption. The proposed story that one victim acted as an access broker is an extortion narrative, not a proven commercial relationship.

 Affiliates can customize contact fields and deployment. Archive note suffixes are collection identifiers, not release numbers; read the [three externally archived notes](../ransom-notes/Ransom-Notes.md).
