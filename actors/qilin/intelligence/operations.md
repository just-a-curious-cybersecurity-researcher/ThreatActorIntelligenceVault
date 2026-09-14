# Qilin — Operations and Attack Lifecycle

Qilin does not follow a single immutable intrusion chain. Its RaaS affiliates differ in access, tooling and deployment. The stages below organize reported procedures; they are not a guaranteed sequence for every incident. **Observed** means observed by the cited investigator. Sample capabilities and hypotheses are identified separately. Reviewed **2026-09-11**.

```mermaid
flowchart LR
    A[External Recon / Targeting] --> B[Initial Access]
    B --> C[Foothold / Execution]
    C --> D[Credential Access]
    D --> E[AD & Network Discovery]
    E --> F[Privilege Expansion]
    F --> G[Lateral Movement]
    G --> H[Defense Evasion]
    H --> I[Persistence / C2]
    I --> J[Collection & Staging]
    J --> K[Exfiltration]
    K --> L[Recovery Inhibition]
    L --> M[Ransomware Deployment]
    M --> N[Extortion]
```

Credential collection, persistence and defense impairment can recur. Exfiltration and encryption can affect different systems.

## 1. External Reconnaissance

Documented entry points include VPN appliances, a public-facing Citrix server and an MSP's remote-management account. These expose different opportunities: reachable services, usable credentials and trusted administrative access to downstream customers. Public reporting is more detailed about internal discovery than original victim selection. [Q12](../References.md#q12), [Q22](../References.md#q22), [Q30](../References.md#q30)

The January 2025 phishing lure imitated the MSP administrator's ScreenConnect alerts. That demonstrates targeted social engineering, but does not reveal how the attacker identified the administrator. Later NetScan activity inside a victim does not establish internet-wide scanning.

## 2. Initial Access

### Valid credentials and remote services

Reported paths include:

- **Citrix-facing infrastructure, 2022:** Trend Micro assessed entry with valid privileged credentials, followed by internal access. No particular Citrix exploit was established. [Q12](../References.md#q12)
- **VPN, July 2024:** compromised credentials on a portal without MFA. The 18-day interval before further activity is compatible with an IAB handoff, but does not prove one. [Q11](../References.md#q11)
- **VPN, Talos 2025 cases:** credential exposure preceded access in some timelines. Temporal proximity supports an access-source hypothesis, not a demonstrated causal chain. [Q15](../References.md#q15)

A successful login proves account use; it does not independently distinguish phishing, password reuse, purchased access or an appliance exploit.

### Exploitation of public-facing infrastructure

Italian 2026 reporting links Qilin campaigns to affected Fortinet and Ivanti EPMM services. Separate SSL-VPN exploitation from administrative-interface bypass. Backup-server compromise may follow initial access rather than cause it. [Q30](../References.md#q30)

Veeam credential disclosure is documented in Qilin incidents; however, authenticated database extraction does not automatically demonstrate CVE-2023-27532 exploitation. Products, preconditions and confidence are recorded in [Vulnerabilities](../technical/vulnerabilities.md). [Q22](../References.md#q22), [Q23](../References.md#q23)

Symantec assessed a possible Adobe Acrobat exploit in October 2024 without identifying a CVE. That remains a case hypothesis. [Q38](../References.md#q38)

### Phishing

In the January 2025 STAC4365 intrusion, an MSP administrator followed a fake ScreenConnect alert to `cloud.screenconnect[.]com.ms`. An adversary-in-the-middle relay intercepted authentication, enabling access to the genuine service and then its customers. This is an identity/trust compromise, not evidence of a ScreenConnect product exploit. [Q22](../References.md#q22)

Trend's October 2025 report describes fake-CAPTCHA connections, but the proposed link to stolen credentials and Qilin deployment remains a vendor hypothesis. Browser navigation and subsequent ransomware must not be collapsed into a fully observed delivery chain. [Q23](../References.md#q23)

## 3. Execution and Foothold

Reported mechanisms include:

- PowerShell and Windows command-shell scripts;
- VBScript for credential-output orchestration;
- WMI, WinRM and PsExec remote execution;
- commands delivered through legitimate RMM agents under attacker control;
- SSH and management scripts against virtualization infrastructure. [Q12](../References.md#q12), [Q15](../References.md#q15), [Q22](../References.md#q22)

In the MSP case, the trusted ScreenConnect service deployed `ru.msi` to install another attacker-managed instance across customers. Distinguish the authorized instance from the new one using tenant, instance identifier and destination; a valid signature does not authorize its operator. [Q22](../References.md#q22)

Talos found Cobalt Strike-related execution; other Agenda chains involve NETXLOADER/SmokeLoader. These are campaign components, not prerequisites for all Qilin intrusions. [Q15](../References.md#q15), [Q18](../References.md#q18)

## 4. Credential Access

Reported methods include:

- Windows and application credential extraction;
- browser-secret collection;
- Veeam credential extraction;
- enabling WDigest plaintext retention;
- domain-policy distribution of credential-collection scripts. [Q11](../References.md#q11), [Q15](../References.md#q15), [Q22](../References.md#q22)

Talos recovered `!light.bat` orchestration involving NirSoft utilities, SharpDecryptPwd, BypassCredGuard and Mimikatz. `pars.vbs` consolidated output into `result.txt` and specified SMTP destinations. Password-protected toolkit contents and script references do not independently establish successful execution of every component. [Q15](../References.md#q15)

In July 2024, a changed Default Domain Policy launched `logon.bat` and `IPScanner.ps1` at user logon. Despite the scanner-like name, the PowerShell script collected Chrome credential data. `LD` and `temp.log` were staged into host-specific SYSVOL directories during a three-day collection window. [Q11](../References.md#q11)

**Analytical implication:** domain-password rotation alone may leave saved third-party accounts exposed. Determine which users logged on, what databases were copied and which external services those credentials could reach.

## 5. Discovery and Active Directory Reconnaissance

### Network discovery

Reported tools include:

- SoftPerfect Network Scanner / NetScan;
- Nmap;
- Advanced Port Scanner;
- native host, process and network enumeration. [Q12](../References.md#q12), [Q15](../References.md#q15), [Q36](../References.md#q36)

Darktrace observed SMB, DCE-RPC and RDP enumeration in probable Qilin cases. Connection volume and protocol alone do not establish execution or attribution. [Q09](../References.md#q09)

### Active Directory and share discovery

Talos describes domain-controller discovery, privilege checks, processes and host enumeration. Group-IB documents payload-driven computer discovery with an RSAT installation fallback. [Q15](../References.md#q15), [Q35](../References.md#q35)

Reported read-only discovery command, for telemetry recognition:

```powershell
Import-Module ActiveDirectory; Get-ADComputer -Filter * | Select-Object -ExpandProperty DNSHostName
```

This discovers domain computers, not users. Follow-on remote activity determines whether the resulting list became a deployment target set. [Q35](../References.md#q35)

Share enumeration and file traversal also occur inside the encryptor. Separate manual exploration of business data from payload discovery of encryptable paths. Do not classify `IPScanner.ps1` as reconnaissance solely from its name.

## 6. Privilege Escalation

Privilege expansion can follow:

- use of recovered administrative credentials;
- access to privileged backup accounts;
- account/token impersonation in particular samples;
- control of a privileged RMM or domain identity. [Q12](../References.md#q12), [Q22](../References.md#q22), [Q35](../References.md#q35)

The early Go sample supports account-token impersonation. Group-IB describes SYSTEM-token acquisition in another analyzed branch. These are build-specific capabilities, not proof of universal kernel exploitation. [Q12](../References.md#q12), [Q35](../References.md#q35)

Symantec reported SharpZeroLogon and Hashcarve in its October 2024 case. Their presence does not reconstruct a successful exploit transaction. [Q38](../References.md#q38)

Credential theft is Credential Access; obtaining greater authority with those secrets is the escalation step. Loading an impairment driver may already require administrative privileges.

## 7. Lateral Movement

Observed mechanisms include:

- RDP with compromised accounts;
- SMB/admin shares and PsExec;
- WinRM and WMI;
- RMM commands across managed customer systems;
- SSH and vCenter-mediated access to hypervisors. [Q09](../References.md#q09), [Q15](../References.md#q15), [Q22](../References.md#q22)

Talos's `encryptor_1.exe` used PsExec distribution; `encryptor_2.exe` processed multiple shares from one host. Widespread impact therefore does not require a local encryptor on every file server. Group-IB independently describes embedded PsExec propagation as a selectable payload capability. [Q15](../References.md#q15), [Q35](../References.md#q35)

Talos found several RMM products without establishing lateral movement by every one. Installation, external control and movement to another host are separate observations.

## 8. Defense Evasion

Reported techniques include:

- endpoint-agent uninstallation and service termination;
- driver-based process termination;
- obfuscated PowerShell and security-setting changes;
- DLL loading abuse;
- log clearing and tool removal;
- lowering virtualization execution restrictions. [Q15](../References.md#q15), [Q23](../References.md#q23)

Talos observed dark-kill/`dark.sys` and HRSword. Trend confirmed `eskle.sys` in two anti-AV components. Its `msimg32.dll` experiment demonstrated driver drops; the compatible Foxit loader in that experiment is not a confirmed victim-side loader. Suspected `fnarw.sys` use remains unresolved. [Q15](../References.md#q15), [Q23](../References.md#q23)

### Safe Mode EDR bypass attempt

Early Agenda analysis documents Safe Mode capability, and Sophos observed boot changes toward Safe Mode with Networking in the MSP intrusion. The Akira out-of-memory failure is not a Qilin outcome. [Q12](../References.md#q12), [Q22](../References.md#q22)

A boot-setting change establishes preparation. Verify that the reboot happened, which protections loaded and whether the payload executed before concluding that impairment succeeded.

Trend's WSL execution explanation is also a hypothesis. A Linux payload transferred through Windows/RMM does not establish local WSL installation or execution. [Q23](../References.md#q23)

## 9. Persistence and Remote Access

Reported mechanisms include:

- additional attacker-managed RMM instances;
- creation of a `Supportt` administrator;
- registry Run entries;
- a `TVInstallRestore` restoration task;
- redundant remote-control/proxy channels. [Q22](../References.md#q22), [Q23](../References.md#q23), [Q15](../References.md#q15)

Talos's task used ONLOGON and `/RESTORE`; another startup path used password/no-admin arguments. The masqueraded TeamViewer installer belongs to that sample context, not all genuine TeamViewer software. [Q15](../References.md#q15)

Enumerate control endpoints, accounts, tasks and startup entries together. Removing one agent does not establish removal of every access channel.

## 10. Command and Control / Tunneling

Reported components include:

- Cobalt Strike;
- SystemBC / COROXY;
- `socks64.dll` proxy artifacts;
- PuTTY/SSH;
- legitimate RMM channels operated without authorization. [Q09](../References.md#q09), [Q15](../References.md#q15), [Q23](../References.md#q23)

Talos found Cobalt Strike before SystemBC, without proving one installed the other. Its ScreenConnect port-8880 connection is case evidence, not a permanent Qilin port signature. Trend describes renamed PuTTY clients and redundant RMM access. [Q15](../References.md#q15), [Q23](../References.md#q23)

Distinguish control, relaying, file transfer and ransom negotiation. A Tor portal in a note is not automatically an encryptor C2 endpoint. Historical values retain their roles in [IP Addresses](../iocs/ip-addresses.md) and [Domains](../iocs/domains.md).

## 11. Collection and Exfiltration

Reported tooling and destinations include:

- WinRAR archive staging;
- Cyberduck and Backblaze;
- Rclone;
- WinSCP and FileZilla;
- MEGA / MEGAsync;
- browser-based EasyUpload;
- FTP in an earlier probable case. [Q15](../References.md#q15), [Q22](../References.md#q22), [Q09](../References.md#q09), [Q38](../References.md#q38)

Talos found manual inspection of business files and Cyberduck history supporting multipart transfers. The MSP attackers uploaded WinRAR archives through Chrome Incognito. That browsing mode does not erase all endpoint, network or provider evidence. [Q15](../References.md#q15), [Q22](../References.md#q22)

Darktrace reported roughly 30 GB to MEGA in its 2023 case and roughly 102 GB over FTP to `194.165.16[.]13` in May 2024, alongside other transfers. These are bounded observations, not universal Qilin exfiltration volumes. [Q09](../References.md#q09)

Determine the collecting account, source shares, archive contents and destination tenancy. A connection alone proves neither completed upload nor sensitive-data exposure. SMTP credential output is a distinct channel from bulk business-data theft.

## 12. Recovery Inhibition

Documented recovery targets include:

- backups and scheduled backup jobs;
- VSS copies/services;
- VM snapshots;
- hypervisor access credentials;
- workloads holding files open. [Q22](../References.md#q22), [Q15](../References.md#q15), [Q35](../References.md#q35)

Group-IB describes deletion of tape backups and jobs and disabling schedules. Those console actions extend beyond host-level shadow-copy removal. [Q35](../References.md#q35)

Reported command, for forensic recognition:

```cmd
vssadmin.exe Delete Shadows /all /quiet
```

Corroborate successful deletion and backup-console activity; a command string is not an outcome. Preserve recovery assets and management logs outside compromised administrative authority. [Q35](../References.md#q35)

## 13. Ransomware Deployment and Impact

Deployment includes GPO execution, RMM distribution, PsExec fan-out and central share encryption. Windows and Linux/ESXi payloads differ, as do Go, early Rust and later configurations. [Q12](../References.md#q12), [Q13](../References.md#q13), [Q15](../References.md#q15)

Talos's virtualization script changed HA/DRS, root/SSH settings and `execInstalledOnly`. These are management-plane changes, not proof of a hypervisor exploit. Trend's newer Nutanix checks establish awareness, not demonstrated AHV compromise. [Q15](../References.md#q15), [Q23](../References.md#q23)

Impact may include:

- unavailable files and virtual disks;
- stopped services and VMs;
- impaired recovery;
- notes and wallpaper changes;
- publication pressure using stolen information.

Sophos observed the same binary across customers with distinct execution passwords and chat IDs. A common hash does not make multiple organizations one negotiation. Missing encryption telemetry does not exclude prior theft. [Q22](../References.md#q22)

## Operational Detection Principle

No single tool above identifies Qilin. Correlate unauthorized identity use, management changes, credential collection, remote execution, exfiltration and impact. Authorized administration and IR can use the same products.

The [detection collection](../detections/Detections.md) identifies sensors and tuning. Windows telemetry cannot replace VPN, RMM tenant, backup, cloud-storage or hypervisor logs.

## Evidence Anchors for the Lifecycle

The core evidence is [early Agenda analysis](../References.md#q12), [Darktrace network cases](../References.md#q09), [Sophos GPO theft](../References.md#q11), [Sophos MSP response](../References.md#q22), [Talos cases](../References.md#q15), [Trend's driver/Linux investigation](../References.md#q23) and [Italian reporting](../References.md#q30). These populations must not become one composite incident.

The specific refinements above also use [Group-IB](../References.md#q35), [Arete](../References.md#q36) and [Symantec](../References.md#q38). The [source review](source-review.md) records limitations.

## Additional Case Evidence

**2022 Agenda:** the investigated intrusion progressed from the Citrix-facing service to internal activity and GPO deployment in under two days. Sample capabilities do not prove every option ran. [Q12](../References.md#q12)

**July 2024:** the 18-day post-entry gap and three-day browser-collection interval describe different parts of the timeline. Repeated logons could renew collection; neither duration is a universal dwell time. [Q11](../References.md#q11)

**January 2025 MSP:** Sophos attributes the intrusion to STAC4365 with high confidence. Customers shared upstream administrative exposure but had separate ransomware credentials and chats. [Q22](../References.md#q22)

**October 2025 report:** fake-CAPTCHA causality, WSL execution and one driver chain remain separate hypotheses. [Q23](../References.md#q23)

**May 2026 Italy:** the bulletin's SME/cloud-provider incidents do not describe every affiliate. Earlier Darktrace cases also have sensor gaps, including a related April case without observed encryption. [Q30](../References.md#q30), [Q09](../References.md#q09)

## Negotiation and Organizational Signals

Group-IB's March 2023 panel access exposed target configuration, payload generation, publication, supporting material, payments and help. Reported affiliate terms offered 80% up to USD 3 million and 85% above that; these are historical advertised shares, not audited transfers. [Q10](../References.md#q10)

SANS examined a February 3–26, 2025 negotiation with trial decryption of up to three files and offers of decryption, stolen-file inventories, deletion assurances and an intrusion explanation. It reports no payment in that case. Those offers are adversary claims, not proof of complete restoration or destruction of all stolen copies. [Q37](../References.md#q37)

**Assessment — Moderate Confidence:** builders and negotiation/publication support permit specialization while affiliates retain operational freedom. Proposed legal and multilingual calling services remain reported marketing; staffing qualifications and effectiveness are unverified. [Q17](../References.md#q17)

See [Ransom Notes](../ransom-notes/Ransom-Notes.md) for variant evidence and [Blockchain](blockchain.md) for the distinction between advertised splits and observed transfers.
