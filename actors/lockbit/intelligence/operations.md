# LockBit — Operations and Attack Lifecycle

**Presentation reviewed:** 2026-09-21.

The lifecycle below separates affiliate activity from executable behavior. It combines dated cases and technical capabilities; it is not a claim that every intrusion follows every stage. Version-specific internal routines are documented in the [encryptor directory](encryptor/README.md).

## 1. External Reconnaissance

Affiliates identify exposed remote-access services, unpatched appliances and usable credentials. Broker-supplied access can replace direct reconnaissance. Public reporting supports opportunistic enterprise targeting; the encryptor itself is normally deployed after access has already been established.

The external objective is to find an entry point that provides a useful identity or execution context. A VPN account grants network reachability; an application exploit grants execution under that application's account; an exposed remote desktop can provide an interactive session. These outcomes offer different permissions and should not be treated as interchangeable evidence of domain compromise.

The investigation can begin before the first ransomware event. Appliance requests, unsuccessful logins followed by success, new source networks and unusual session duration can establish the access window. Where an affiliate purchased access, the first visible affiliate action may already be authenticated. The absence of scanning from that operator's address does not establish the absence of an earlier compromise.

## 2. Initial Access

### Valid credentials and remote services

The international advisory describes compromised accounts, exposed RDP and VPN access. Distinguish password authentication from reuse of already authenticated sessions. A successful VPN session after a password reset can have a different cause from a fresh password compromise.

Antigen's Red-era case began with compromised credentials for a single-factor Fortinet SSL VPN, followed by RDP to an Active Directory server. The important transition is from appliance authentication to an internal privileged session. The allocated VPN address links those two evidence sources. It should not be mistaken for an attacker-controlled public address or for proof that the domain controller itself was exposed to the internet.

### Exploitation of public-facing infrastructure

The 2023-11 Citrix Bleed advisory documents affiliate exploitation of CVE-2023-4966 to recover session material from NetScaler appliances. Reusing a valid session can bypass the expected interactive authentication flow. This is an access procedure performed before ransomware deployment.

The broader advisory associates affiliates with several other public-facing vulnerabilities. [Vulnerabilities](../technical/vulnerabilities.md) preserves product, date and evidence scope instead of presenting one universal exploit chain.

ASD's ACSC separately documented CVE-2018-13379 exploitation in LockBit 2.0 activity. That supports a vulnerability-based Fortinet access route, but does not prove that the same vulnerability supplied the credentials in every Fortinet case. Product association, exploitable configuration and incident evidence are three different propositions.

Exploitation is also stage-dependent. An edge flaw may establish the first foothold; an internal privilege flaw may enlarge permissions after access. Code execution as a service account, administrative access to one endpoint and control of domain policy should be recorded as distinct outcomes. The encryptor's later appearance cannot retrospectively establish which transition occurred.

### Phishing

Phishing is one of the documented affiliate access routes. A phishing-capable affiliate and a particular LockBit payload are separate attribution objects; the binary does not itself establish how access was obtained.

A downloaded loader is not sufficient evidence of phishing. Establish its delivery using browser history, email telemetry, URL redirection and the process that created the file. A lure, a malicious advertisement and an operator's remote download can all lead to an executable in the same user-writable directory.

## 3. Execution and Foothold

PowerShell, command scripts and existing administration interfaces support staging. In the Citrix campaign, `123.ps1`, `adobelib.dll` and `Mag.dll` appear in specific chains. Their names are useful together with parent processes, paths and hashes; “Adobe” in a filename alone is weak evidence.

The ransomware can be delivered as a PE executable or DLL depending on branch and build. A `rundll32.exe` process may host a malicious DLL, whereas direct API calls inside an EXE produce no equivalent shell command.

### Establishing operator control

The foothold is the component that allows repeated commands, reconnaissance and additional downloads. It can be a beacon, a remote-management installation or an authenticated session. The encryptor is normally the later impact component. Deleting the encryptor therefore does not necessarily remove the mechanism that delivered it.

SentinelOne documented a LockBit-associated chain using a signed VMware transfer utility, a side-loaded DLL and an encrypted `.log` file containing a Cobalt Strike loader. The subsequent update links it to an affiliate tracked as DEV-0401. The legitimate executable supplies the hosting process; the adjacent malicious library redirects execution. The misleading log extension describes storage, not the payload's function. The RC4-protected loader is separate from ransomware file encryption.

### Post-exploitation activity

Once control exists, the operator gathers credentials, examines trust relationships, establishes fallback access and selects data and deployment hosts. These activities can overlap rather than follow a fixed checklist. A backup server may be both a credential source and a later staging host; a file server may host the proxy through which other systems are reached.

```text
MOCK INVESTIGATION TIMELINE — descriptive, not executable
external access -> internal session or application-owned process
foothold -> operator tasking -> credentials and environment discovery
remote access to additional hosts -> data staging and transfer
deployment mechanism -> platform-specific encryptor -> file impact

Persistence and repeated reconnaissance can recur between these stages.
```

## 4. Credential Access

Published affiliate tooling includes Mimikatz, LaZagne, ProcDump and registry-hive extraction. The Citrix advisory additionally describes an `a.exe` / `a.dll` chain that writes a memory dump as `a.png`, followed by cabinet archives. File extensions therefore do not reliably describe content.

Prioritize LSASS access, unusual dump creation, SAM/SYSTEM hive export and subsequent transfers. Recovery and incident-response tools can perform the same operations legitimately; identity, parent process and timing determine the case.

The objective is usable authority, not merely possession of a dump file. Local credential material may unlock another endpoint, a reusable administrative identity or a backup-management account. Determine whether the collected material was later used: new logons and remote service creation are stronger evidence of progression than the collection tool alone.

In The DFIR Report's January 2024 intrusion published in 2025, observed credential access included LSASS memory and stored backup-system credentials; an NTDS collection attempt was blocked. Successful and prevented steps must remain separate. A failed collection alert does not prove the actor lacked other already-compromised credentials.

## 5. Discovery and Active Directory Reconnaissance

### Network discovery

Advanced IP Scanner, Advanced Port Scanner and SoftPerfect Network Scanner appear in the public tool register. Connection fan-out to SMB, RDP and management services can expose the same activity even when binaries are renamed.

Scanning answers which hosts and services are reachable from the current foothold. It does not answer which accounts can administer them. Compare the scan's source host with its later authentication and execution targets. A narrow internal scan from a backup or file server can be more relevant than a large external scan unrelated to the intrusion.

### Active Directory and share discovery

AdFind and BloodHound support directory discovery; native account and domain utilities supply additional context. Recovered enumeration output and access to backup or virtualization systems help establish how an affiliate selected deployment targets.

Directory reconnaissance adds users, groups, computers and privilege relationships to that reachability map. Share discovery adds accessible data. Backup and virtualization discovery identifies systems whose compromise can affect many workloads. These are different information products, even when one tool collects several of them.

Antigen recovered files suggestive of user/group and email-account enumeration, as well as evidence of later data staging. Such output helps connect discovery to the resources eventually selected. An analyst should distinguish an enumerated object from an accessed object, and an accessed object from one actually changed or encrypted.

## 6. Privilege Escalation

Affiliates may obtain privileged credentials or exploit weaknesses in the environment. Separately, analyzed Windows LockBit samples implement elevation-related COM behavior. A privileged encryptor process is not proof that the binary stole credentials or performed every earlier escalation step.

COM activation involving CMSTPLUA or ColorDataProxy should be correlated with the initiating image and subsequent high-integrity process. The same activation can occur during legitimate system management.

Local elevation, token impersonation and domain-level privilege are separate mechanisms. SYSTEM on a member server is not automatically domain administrator. A COM elevation path may depend on the starting account's privileges and host configuration; it is not evidence of a remote domain exploit. Resolve the security principal before and after the transition and the scope in which that principal can act.

## 7. Lateral Movement

PsExec, SMB administrative shares, WMI, RDP and WinRM support remote execution. Red / 2.0 introduced automated Group Policy deployment capabilities in suitable domain contexts. Finding such code does not establish that it succeeded without sufficient directory permissions.

Citrix campaign evidence includes WMI-style output redirection and a Python WinRM client. Preserve remote source, destination, account and service/task creation records, rather than attributing the whole chain from one command-line string.

### Remote file access versus remote execution

SMB access can expose documents to a process running elsewhere. Remote service, WMI, WinRM or task execution instead starts work on the destination. RDP supplies an interactive desktop. These routes leave different evidence: a share write alone does not establish a new process, while a service-start event alone does not identify the external source of the request.

### Centralized deployment

With sufficient domain rights, Group Policy can distribute configuration and launch tasks across multiple endpoints. Red-era research documents this deployment capability. The relationship spans directory changes, policy files in SYSVOL, policy retrieval by clients and eventual task/process execution. A file placed in SYSVOL establishes only one part of that sequence. Group membership, policy scope, replication and client reachability affect the eventual coverage.

## 8. Defense Evasion

Affiliates use security-process termination and tools such as GMER, PCHunter, Process Hacker and Defender Control. These are not immutable components of every payload.

Impairment can target policy, services, running processes or the in-memory observation surface. These effects require separate checks. A service stop differs from changing its start mode; an exclusion differs from disabling a sensor; log deletion differs from preventing a particular provider from producing new events. Record both attempted changes and resulting state rather than collapsing them into “AV disabled.”

Sophos's government-agency case illustrates the operational effect: a protective feature left disabled after maintenance enabled further sabotage, followed by ScreenConnect access and transfer to MEGA. The study also found evidence of multiple intruder groups over months, so all earlier artifacts should not be assigned to the final LockBit operator.

### Safe Mode and binary-local impairment

Black contains configurable Safe Mode and anti-analysis behavior, including password-gated builds. Native 4.0/5.0 samples resolve APIs dynamically and interfere with telemetry. An in-process modification of an ETW routine does not disable all Windows logging across the machine; separate EDR, kernel and forwarded telemetry can remain available.

## 9. Persistence and Remote Access

Affiliate-deployed AnyDesk, Atera, ScreenConnect, Splashtop and other RMM software can provide recurring access. The Citrix advisory records an auto-start AnyDesk installation and scheduled tasks including `UpdateAdobeTask`.

Persistence is not synonymous with encryption. A note on disk does not establish a Run key, scheduled task or installed service, and encryptors can complete their work without maintaining a long-lived foothold.

### Persistence trigger and scope

A service can restart at boot; a scheduled task depends on its registered trigger and principal; a user Run value ordinarily depends on that user's logon. Capture those properties, the referenced file and the creation time. An installed RMM agent also has an account or enrollment relationship that can survive removal of one local payload.

The January 2024 DFIR case used scheduled tasks and later a user Run entry for GhostSOCKS. Persistence was distributed across hosts. The practical implication is that containment must account for alternate entry points: one stopped beacon is not proof that the operator cannot return through a proxy, another compromised account or a remote-management service.

## 10. Command and Control / Tunneling

Cobalt Strike and other offensive-security tooling occur in the affiliate ecosystem. The international advisory specifically lists Ligolo, Ngrok, Plink and ThunderShell. Their network sessions must be tied to a host and an unauthorized operator before becoming malicious findings.

The Citrix case includes a renamed Plink binary at `C:\Windows\servicehost.exe` with `sysconf.bat`. Filename similarity to Windows components is a pivot; SSH traffic and forwarding options supply the functional context.

A beacon carries operator instructions; a SOCKS proxy relays access to other destinations; an exfiltration client transports selected files. One process or server may support several functions, but those functions should still be reconstructed separately. Map which host initiated each connection and whether the destination is a relay, a collection endpoint or a legitimate service abused by the intruder.

For public-key-based file encryption, the ransomware does not necessarily need a fresh external exchange for every file. Blocking an unrelated Tor hostname cannot be assumed to stop a running locker. Publication and negotiation infrastructure is also distinct from the route that initially delivered commands inside the victim network.

## 11. Collection and Exfiltration

StealBit is a service-associated transfer utility introduced with the Red era. Affiliates also use Rclone, MEGA, FreeFileSync, WinSCP, FileZilla and archives. The exfiltration client and the final encryptor can execute on different machines and at different times.

Large outbound transfers, archive staging and unusual cloud destinations are stronger together than a tool name. Shared storage domains are legitimate infrastructure and should not be globally blocked solely because they appear in an advisory.

Collection selects and stages data; exfiltration moves it across the trust boundary. A local archive proves staging, not successful upload. A transfer client can also fail authentication or fail to connect. In the January 2024 DFIR case, unsuccessful FTP attempts preceded successful transfers through other configured destinations. Preserve outcomes and byte counts rather than treating every attempt as completed theft.

Antigen's investigation found compression and cloud-oriented transfer activity before impact. This explains why restoration from backup addresses availability but not the confidentiality of material already copied away. Encryption and extortion are related business stages, not evidence that the encryptor itself contains the transfer client.

## 12. Recovery Inhibition

Reported routines remove shadow copies or Windows backups, stop backup/database services and interfere with recovery. Implementation varies: some branches spawn `vssadmin` or `wbadmin`; others call WMI or management APIs internally.

Shadow-copy disappearance without a child `vssadmin.exe` is therefore meaningful. Retain service-control, VSS/WMI and backup-system records alongside process creation. A command-line hunt alone cannot observe every equivalent API implementation.

Recovery resources are also distributed. Local snapshots, a central backup catalog, repository storage and offline copies do not have identical control paths. Loss of one does not prove loss of the others. Assess which account reached the backup system, whether jobs or repositories changed, and whether a restoration point remains independently usable.

## 13. Ransomware Deployment and Impact

Windows endpoints and file servers, Linux hosts and ESXi infrastructure require separate payloads and permissions. Hypervisor encryption can affect many guest workloads without the encryptor executing inside each guest.

Black may produce a generated nine-character suffix and corresponding README filename; NG-Dev can use `locked_for_LockBit`; 5.0 commonly uses a randomized 16-hex suffix and `ReadMeForDecrypt.txt`. Configuration can suppress notes, renaming or timestamp changes. Collect content and I/O evidence as well as filenames.

Deployment can be manually repeated through RDP, scripted from a staging server or coordinated through domain tooling. The January 2024 DFIR intrusion used the backup server for deployment scripts and combined WMI/PsExec execution on day eleven. This was a documented campaign choice, not evidence of an eleven-day waiting period built into LockBit.

Impact assessment should distinguish changed filenames, changed content, failed applications and unavailable infrastructure. Sophos documented some systems with renamed but unencrypted files in its government-agency investigation. That observation supports content verification, not a general recommendation to rename all LockBit output. Completed encryption normally requires an appropriate recovery method or intact backups.

## Operational Detection Principle

Correlate access anomalies, credential collection, discovery, remote deployment, recovery inhibition and file impact. A shared tool or one ransom note supports triage; it does not prove the affiliate, core organization or complete intrusion sequence.

## Evidence Anchors for the Lifecycle

The joint AA23-165A advisory anchors the broad affiliate model and toolset. AA23-075A anchors Black-era behavior. AA23-325A provides the Citrix-specific artifacts and CISA's four public YARA signatures. Reverse engineering supplies executable internals; it does not retrospectively identify the entry vector for every victim.

Antigen, SentinelOne, Sophos, ASD's ACSC and The DFIR Report add dated access, foothold and post-exploitation evidence. Their source records and incident-date distinctions are centralized in the actor's reference register. The sequence combines documented cases; it is not a single reconstructed intrusion shared by every affiliate.

## Additional Case Evidence

### Citrix Bleed, 2023

The public case material links stolen sessions to discovery, remote tooling, credential collection and payload staging. It includes low-fidelity shared-hosting observations as well as high-fidelity artifacts. Keep those ratings separate.

### 4.0 and 5.0 observations, 2025–2026

Deep Instinct and independent reverse engineering describe 2025 native 4.0 samples. Trend Micro links analyzed 5.0 routines to that code. Check Point later observes renewed deployments and DLS postings. These sources support continued activity without proving that every historical affiliate tool appears in the newer incidents.

### ActiveMQ access and independent Black-builder use, 2024

The DFIR Report published this case on 2026-02-23, but the intrusion began in 2024-02. CVE-2023-46604 exploitation on an exposed Windows ActiveMQ server led to a Metasploit foothold. After losing access, the intruder exploited the still-vulnerable service again. Later activity included privileged execution, discovery, RDP, AnyDesk persistence and interactive ransomware deployment.

The source reports 419 hours to ransomware and less than 90 minutes between the later return and encryption. The long overall timeline therefore concealed a short final response window. Crucially, the researchers assess independent use of the leaked Black builder from the modified contact note and lack of official-service linkage. This is a LockBit-family intrusion example, not a newly confirmed 2026 LockBit affiliate campaign.

## Negotiation and Organizational Signals

Versioned notes and individualized negotiation portals can help relate incidents to a service era. The 2022 builder leak permits altered contact channels and independently generated keys. A low ransom demand or different email is an investigative clue, not a sufficient standalone test for impersonation.

Law-enforcement disclosures also show why promises to delete stolen data cannot be inferred from payment. Financial proceeds, affiliate share, developer share and downstream exchange deposits remain separate categories in [financial intelligence](blockchain.md).
