# APT29 — Operations and Attack Lifecycle

**Presentation reviewed:** 2026-09-25.

The lifecycle below joins procedures that appear across separate APT29 campaigns. It is an analytical model, not a claim that every intrusion uses every stage.

## 1. External Reconnaissance

The actor identifies intelligence-bearing organizations, privileged identities, externally reachable services, cloud tenants and trusted providers. Government reporting documents broad scanning for vulnerable systems. Modern identity operations also require discovery of tenant configuration, dormant or service accounts, device-code flow availability and application permissions.

Reconnaissance is often low-noise and external. A domain resembling Microsoft or a compromised high-reputation website can support delivery while keeping actor-controlled infrastructure separate from the victim-specific C2 tier.

## 2. Initial Access

### Valid credentials and cloud authentication

Password spraying targets weak, dormant and system accounts, including accounts without MFA. Operators use stolen credentials, session tokens and personal-account password reuse. Storm-2372 social engineering moves from Signal, WhatsApp or Teams conversations to legitimate device-code pages so the victim authorizes the attacker's session.

UNC6293 demonstrates a parallel identity path outside Microsoft 365. After extended rapport-building, targets were instructed to create a Google application-specific password, label it with a plausible government name and transmit the 16-character secret. The secret gave a mail client persistent mailbox access despite normal two-step verification. Later waves added Microsoft device-code and OAuth authorization. Google relates UNC6293 to an ICE RELIC initial-access subcluster only with moderate confidence.

Anthropic's GTG-20006 case retained device-code phishing as the primary cloud access method and described an actor-built `Embassy Kit` platform for Microsoft 365 token theft. The actor also stole VPN-appliance credentials in a North African government intrusion and used compromised hospitality-provider administration to alter DNS records. These observations are scoped to GTG-20006 and do not prove that every APT29 operator uses the same platform.

### Exploitation of public-facing infrastructure

Joint reporting links SVR actors to exploitation of Fortinet, Zimbra, Pulse Secure, Citrix and VMware appliances. These are campaign-era observations, not a standing list of zero-days. Exploitation can provide a foothold before web shells, credential theft or cloud pivoting. The October 2024 joint advisory adds confirmed exploitation of Zimbra CVE-2022-27924 against hundreds of domains and preserves a separate, non-observed list of vulnerabilities the agencies assess the actor has capability and interest to exploit.

From September 2023, FBI, CISA, NSA, SKW, CERT.PL and NCSC observed large-scale exploitation of CVE-2023-42793 in exposed JetBrains TeamCity servers. The access was used to escalate privileges, move laterally, deploy additional backdoors and retain long-term access. Because TeamCity can expose source code, signing certificates and build pipelines, the compromise created supply-chain risk; the agencies did not report that the known victim set had been used for a SolarWinds-style downstream compromise.

### Phishing and trusted delivery

Historical and current campaigns use targeted links, attachments, ISO/VHDX containers, HTML smuggling, compromised websites and legitimate hosting. WINELOADER used a CDU-themed lure and a compromised WordPress site. In October 2024, malicious RDP files mapped local resources to actor servers. CaptiveCrunch used fake update prompts and ClickFix-style instructions after traffic manipulation.

The 2025 GRAPELOADER wave impersonated a European foreign ministry and repeatedly sent wine-event or diplomatic-dinner invitations. Successful links downloaded `wine.zip`; unsuccessful or non-target visits could be redirected to the legitimate ministry site. The archive combined a legitimate PowerPoint executable with a dependency DLL and the obfuscated `ppcore.dll` loader.

AWS's 2025 watering-hole case broadened delivery beyond named spear-phishing. Compromised legitimate websites injected obfuscated JavaScript that redirected roughly 10% of visitors, set cookies to avoid repeated selection and led to fake Cloudflare verification pages. After disruption, the operator shifted to server-side redirects. The final action asked the visitor to authorize an attacker-controlled device through Microsoft's legitimate device-code flow.

### Supply chain

The SolarWinds operation compromised the Orion build process so signed updates carried SUNBURST. The initial distribution reached many customers; follow-on exploitation was selective. Trusted providers and cloud solution partners have also supplied downstream access without a poisoned software update. Microsoft observed NOBELIUM chaining access across four providers and abusing delegated administrative privileges to reach downstream tenants; this was trust abuse rather than a product vulnerability.

## 3. Execution and Foothold

Execution chains frequently combine script hosts and signed Windows utilities. ROOTSAW wrote an encoded archive under `C:\Windows\Tasks`, invoked `certutil` to decode it, used `tar` to extract it and launched legitimate `SqlDumper.exe` for DLL side-loading. Other campaigns used `mshta`, `rundll32`, PowerShell, Visual Basic, Python, Azure administrative functions and web shells.

GRAPELOADER executes when `wine.exe` resolves the delayed import exported by `ppcore.dll`. It profiles the user, host, process and PID, adds a campaign tag, polls every 60 seconds and receives position-independent shellcode for memory-only execution. It cycles memory from read/write to no-access, creates a suspended thread, sleeps, changes the region to executable and resumes the thread. The behavior is an anti-scanning sequence, not persistence by itself.

CaptiveCrunch's CornFlake copies itself to `%APPDATA%\svchost32\svchost32.exe` while displaying a fake update or utility interface. ChocoShell executes in PowerShell memory, profiles the environment and implements credential-focused modules.

## 4. Credential Access

Credential theft spans password spraying, browser cookies/passwords, DPAPI-protected data, Kerberos material, private keys, AD FS signing material and cloud tokens. SolarWinds responders observed DCSync, Kerberoasting and browser-profile copying in selected environments.

Cloud campaigns treat tokens and applications as durable credentials. A successful device-code phish can yield Graph access without a fake Microsoft password page. A compromised administrator can add credentials to service principals, grant mailbox permissions or create applications that survive a user password reset.

ChocoShell reads browser and Microsoft 365 authentication data and can create a temporary volume snapshot to access locked databases. CornFlake adds keylogging, clipboard capture and Chrome credential theft. These behaviors are credential collection, not ransomware preparation.

## 5. Discovery and Active Directory Reconnaissance

### Network and host discovery

Malware and operators enumerate hostname, user, interfaces, processes, services, security products, files, network connections and accessible storage. GoldFinder traces HTTP redirects and proxy/security hops between the victim and a hard-coded destination, giving operators visibility into inspection points.

### Active Directory, federation and cloud discovery

APT29 has used PowerShell, LDAP, AdFind and Exchange cmdlets to identify accounts, groups, trusts, accepted domains and service principals. Cloud enumeration includes users, applications, permissions, devices, subscriptions and mailbox access paths. MAGICWEB and FoggyWeb operations require detailed knowledge of AD FS deployment and configuration.

## 6. Privilege Escalation

Observed paths include credential reuse, token/ticket manipulation, UAC bypass, vulnerable certificate templates and privilege obtained through cloud roles. Rapid domain-administrator access in some Mandiant cases reflects a favorable victim path, not a guaranteed twelve-hour timeline.

Operators may compromise an existing privileged application rather than create a visibly privileged user. In cloud investigations, privilege review must include application credentials, consent grants, delegated administration and role assignment history.

Microsoft observed Azure Run Command paired with Azure admin-on-behalf-of access to execute against virtual machines and move from cloud administration into on-premises resources. The same provider campaign created users, applications, roles and service-principal credentials for persistence.

## 7. Lateral Movement

The actor uses valid accounts, RDP, SMB/admin shares, PsExec, WinRM, remote scheduled tasks, WMI and cloud-service relationships. Credential hopping and residential proxies reduce the value of simple source-IP correlation. Stolen cookies or application tokens can move between resources without a conventional host-to-host executable transfer.

SolarWinds operations crossed from on-premises identity infrastructure into Microsoft 365 through forged or stolen authentication material. Provider compromise can move laterally across organizational boundaries through delegated administration. In one Microsoft case, four provider relationships and access artifacts were chained before the final target was reached.

## 8. Defense Evasion

APT29 compartmentalizes infrastructure per victim, uses high-reputation or compromised domains, legitimate cloud storage, encrypted C2, domain fronting, residential proxies and victim-local cloud resources. Operators clear files and logs, timestomp artifacts, disable or reduce logging, restore modified tasks, monitor response communications and shift access when defenders act.

Malware uses delayed activation, environment checks, encrypted configuration, in-memory execution, DLL side-loading and process injection. GoldMax adds decoy web traffic. WINELOADER checks execution context and bypasses user-mode hooks. SUNBURST delayed execution and impersonated normal Orion behavior.

GRAPELOADER resolves APIs at runtime, unhooks libraries before use, applies a distinct decrypt-use-zero routine to each protected string and adds junk loops. The 2025 WINELOADER variant uses an RWX `.text` section, self-modifying unpacking, hundreds of decoy exports, a single functional `Str_Wcscpy` entry point and immediate string cleanup. Its reported user agent combines Windows 7 with Edge 119, an internally inconsistent fingerprint suitable for network hunting.

Anthropic observed GTG-20006 using AI-assisted monitoring to detect when security products identified its implants, then modifying, rebuilding and redeploying those artifacts. The reported Windows payloads could freeze victim security updates so newly published signatures would not be retrieved or applied. This is evidence of defense impairment in that campaign, not proof of a universal APT29 malware feature.

## 9. Persistence and Remote Access

Persistence exists on both endpoint and identity planes. Historical Dukes implants use scheduled tasks, Run keys and WMI event subscriptions. GoldMax hides behind task and directory names chosen to resemble installed management software. FoggyWeb and MAGICWEB persist in AD FS components after privileged access.

Cloud persistence includes additional service-principal credentials, OAuth applications, mailbox permissions, roles, device registration and modified federation trust. CornFlake maintains a service named `svchost32`, Run-key and scheduled-task options, plus a watchdog that restores removed mechanisms.

## 10. Command and Control / Tunneling

APT29 uses HTTP/S, DNS, encrypted custom protocols, dynamic DNS, legitimate web services, victim-specific domains, proxies and compromised infrastructure. Documented legitimate services include Dropbox, Google Drive, Trello, GitHub, Microsoft OneDrive/Graph and social platforms used to recover tasking or stage payloads.

The October 2024 government advisory states that operators lease infrastructure through resellers using fake identities, low-reputation email accounts and cryptocurrency, and destroy infrastructure when discovery is suspected. No wallet or transaction was published, so cryptocurrency is retained as an acquisition method without a blockchain-address attribution.

Mandiant observed Tor with the meek domain-fronting plugin to carry remote services inside traffic that appeared to reach Google infrastructure. This documents Tor transport; no public `.onion` service hostname is retained. CaptiveCrunch uses FruitStone relays and TLS SNI spoofing, while CornFlake uses ephemeral ECDH P-256 and a custom encrypted JSON channel.

## 11. Collection and Exfiltration

Email is a recurring objective. Operators use EWS, Microsoft Graph, mailbox export, delegate permissions and application impersonation. Search terms in Storm-2372 focused on credentials, remote-access products, government/ministry terms and secrets before Graph-based exfiltration.

Other collection includes local and shared files, source-code repositories, browser data, screenshots, audio/video, clipboard, keystrokes and removable media. Data may be staged in archives on internal servers or transferred through the established C2 and legitimate services.

GTG-20006 used scheduled token renewal and cloud-storage harvesting, bulk-exported mailboxes and processed hundreds of gigabytes of stolen data. Anthropic reported theft of a drone-vision software development kit and associated architecture and supplier data, as well as WhatsApp collection through linked companion devices. These details reinforce the intelligence objective while expanding the collection surface beyond Microsoft 365.

## 12. Recovery Inhibition

No reviewed APT29 campaign uses shadow-copy deletion, backup destruction or recovery inhibition as an impact stage. ChocoShell's temporary VSS operation is scoped to reading locked browser data and cleanup. Hunt the behavior because it is security-relevant, but do not label it ransomware recovery inhibition without evidence of destructive intent.

## 13. Ransomware Deployment and Impact

No public source reviewed here establishes APT29 ransomware deployment, an encryption extension, a locker builder, a ransom note or a payment workflow. The impact sought in the documented corpus is confidentiality loss and persistent intelligence access. T1486 is excluded from the ATT&CK mapping.

## Operational Detection Principle

Correlate identity, cloud control-plane, mailbox, endpoint and network evidence. The strongest cases join a suspicious authentication sequence to application/role changes, mailbox or repository access, endpoint execution and known campaign artifacts. Actor attribution follows the incident reconstruction; it should not be the first filter.

## Evidence Anchors for the Lifecycle

**Initial access:** preserve password-spray patterns, device-code sign-ins, exploit logs and malicious RDP/HTML/ISO attachments so identity and endpoint entry paths can be separated.

**Cloud persistence:** collect service-principal credentials, consent grants, roles, delegates and device registrations because a password reset may not remove access.

**Endpoint persistence:** correlate CornFlake service/path evidence, anomalous AD FS DLLs and WMI/task/Run-key events to define host recovery scope.

**Collection:** Graph/EWS mailbox access, export requests, repository access and file staging connect access to the intelligence objective.

**Evasion and C2:** audit changes, residential proxies, victim-local cloud egress, task restoration, file deletion, Tor/fronting behavior and exact IoCs explain visibility gaps but require process and campaign context.

## Additional Case Evidence

**SolarWinds / UNC2452.** The build-system compromise distributed SUNBURST through signed updates. Selected victims received TEARDROP/RAINDROP and Cobalt Strike, credential operations, federation manipulation and targeted email/source-code collection. The distribution count is not the same as the number of hands-on compromises.

**Microsoft 2023–2024.** A legacy non-production test account without MFA was password-sprayed. The actor abused a legacy OAuth application, created additional applications and granted Exchange Online application permissions. Exfiltrated email secrets supported later attempts to reach source-code repositories.

**Storm-2372.** Social engagement over messaging platforms established trust before device-code phishing. Successful authentication produced tokens used for Graph searches and mail exfiltration, sometimes followed by actor device registration.

**GRAPELOADER / WINELOADER 2025.** Ministry-themed diplomatic lures delivered a three-file side-loading bundle. GRAPELOADER established Run-key persistence and memory-only next-stage delivery; Check Point assessed the revised WINELOADER as a likely follow-on based on code, compilation and campaign overlap.

**AWS watering hole 2025.** Legitimate sites were compromised to select and redirect a small subset of visitors toward fake Cloudflare verification and Microsoft device authorization. AWS reported no compromise of AWS services and no direct AWS impact.

**UNC6293 / UNC7005.** Google observes long-form social engineering, application-specific-password theft, OAuth/device-code abuse, messaging-device linking, residential proxies and limited malware delivery. Google relates both clusters to an ICE RELIC initial-access subcluster with moderate confidence; UNC5976 remains outside this dossier.

**CaptiveCrunch / Storm-2945.** Compromised captive-portal infrastructure enabled DNS/HTTP manipulation, AitM phishing and fake-update delivery. Microsoft observed CornFlake, ChocoShell and possible Android-directed lures; it did not resolve the upstream portal-compromise vector at publication.

**GTG-20006.** Anthropic linked the cluster to Midnight Blizzard only through qualified consistency with public reporting. The provider observed AI-assisted operational workflows across infrastructure acquisition, phishing, command execution, persistence, malware rebuilding and exfiltration. It reported more than 20 planned or active organizational targets and published Windows, Android and iOS tool names plus network and file indicators. The overlap with CaptiveCrunch includes compromised hospitality Wi-Fi, DNS hijacking, ClickFix delivery and several shared indicators.

## Negotiation and Organizational Signals

There is no ransom negotiator or victim-payment workflow to profile. Human interaction instead supports access: diplomats receive tailored lures, targets are approached on Signal/WhatsApp/Teams, and travelers see context-aware captive-portal prompts. These social signals should be preserved with authentication and endpoint telemetry because the message may explain why a legitimate device-code event or signed RDP client session occurred.
