# Qilin — Operational Model and Campaign Evidence

## RaaS Division of Work

Group-IB's March 2023 access exposed a panel separating targets, publication, supporting material, announcements, payments and help. Target configuration supported company details, demand, timing, note content, exclusions and payload generation. An interlocutor reported affiliate shares of **80% up to USD 3 million and 85% above that**; those are historical advertised terms, not audited transfers or a universal current split. [Q10](../References.md#q10)

**Moderate Confidence assessment:** builders and negotiation/publication support reduce the operational burden on affiliates, while intrusion methods remain diverse. The panel demonstrates service organization, not the real number of staff or how revenue moves on-chain. Group-IB's 2026 account of proposed legal and multilingual calling services reflects attacker marketing: the existence of qualified lawyers, effectiveness of regulatory threats and scale of call operations are unverified. [Q17](../References.md#q17)

## Case A — Early Agenda, 2022

Trend Micro observed a Citrix-facing entry followed by internal access with valid privileged credentials, scanning and GPO deployment in less than two days. The paper assesses valid-account entry; it does **not** establish a particular Citrix vulnerability. Its Go sample can change passwords, use Safe Mode and customize processing per victim. Do not interpret every sample capability as an observed step in that incident. [Q12](../References.md#q12)

## Case B — Domain-Wide Browser Credential Collection, July 2024

Sophos found compromised VPN credentials on a portal without MFA and an 18-day gap before further activity. An IAB handoff is one hypothesis, not a proven explanation. An attacker changed the Default Domain Policy to run `logon.bat` and `IPScanner.ps1` at user logon. The latter collected Chrome credential data; `LD` and `temp.log` were staged back to SYSVOL under host-specific directories. The policy remained active over three days before later encryption and cleanup. [Q11](../References.md#q11)

**Defensive implication:** domain-password resets alone may leave third-party saved credentials exposed. Investigate affected user sessions, policy versions, script distribution and copied browser databases to bound the exposure; repeated policy execution can renew collection. The script's scanner-like name is a masquerade clue, not evidence it performs network scanning.

## Case C — MSP Trust and ScreenConnect, January 2025

Sophos describes a fake authentication alert leading an MSP administrator to `cloud.screenconnect[.]com.ms`. An AiTM relay captured credentials/MFA inputs, allowing access to the genuine ScreenConnect service. The attacker pushed `ru.msi`, installing an additional attacker-managed instance across customers, then used administrative tooling, Veeam credential exploitation, archive staging and EasyUpload transfer through Chrome. Boot settings and backups were targeted before Qilin deployment. Distinct victim passwords/chat IDs occurred with the same ransomware binary. [Q22](../References.md#q22)

**Assessment:** the leverage came from trusted provider administration and session compromise, not proof of an RMM software supply-chain implant or a ScreenConnect CVE. Investigations should correlate the MSP control plane with each customer's agent installation and commands. A legitimate signed RMM client can carry unauthorized instructions.

## Case D — Multi-Case Talos Findings, 2025

Talos found temporal proximity between exposed credentials and VPN authentication, but could not prove how the credentials were obtained. Observed discovery included domain controllers, user privilege checks, processes and NetScan. A credential-toolkit script enabled WDigest plaintext retention, invoked NirSoft utilities, SharpDecryptPwd and Mimikatz, consolidated output through `pars.vbs`, and specified SMTP destinations. Archive listing or script contents alone do not prove every component ran successfully. [Q15](../References.md#q15)

Cyberduck history pointed to Backblaze with multipart transfers; separate artifacts showed manual inspection of business files. Investigate object-storage credentials and provider history alongside archive creation. Multiple RMM tools were present, although Talos could not establish that every one performed lateral movement. Cobalt Strike appeared before SystemBC, without proving that one installed the other.

The two deployment patterns matter for sensor placement: `encryptor_1.exe` spread with PsExec, while `encryptor_2.exe` encrypted multiple shares from one system. Windows persistence used a restoration task/Run entry; the hypervisor script changed HA/DRS and root/SSH settings and lowered `execInstalledOnly`. Preserve vCenter tasks and remote syslog: host-only process searches can miss datastore impact.

## Case E — Drivers, RMM and Linux Payload, October 2025 Report

Trend Micro's incident includes Veeam credential queries, a `Supportt` administrator, redundant RMM channels, renamed PuTTY clients and `socks64.dll` proxies. It confirms `eskle.sys` use in two anti-AV tools. Its analysis of `msimg32.dll` demonstrates DLL loading and dropping `rwdrv.sys`/`hlpdrv.sys` in testing; Foxit was a compatible loader in that test, not necessarily the observed victim's loader. Suspected `fnarw.sys` use remains unconfirmed. [Q23](../References.md#q23)

The article observes fake CAPTCHA connections and valid-account use but **assesses** the causal path through stolen credentials. It also proposes WSL as the mechanism behind a Linux payload seen in a Windows/RMM context. No confirmed WSL installation/configuration trace is supplied. A Linux binary's presence on Windows does not prove native execution. New samples include Nutanix detection; this establishes targeting capability, not successful AHV compromise in that incident.

## Case F — Italian Campaign Reporting, 2026

CSIRT Toscana's May publication reports an Italian campaign affecting SMEs and cloud providers, using exposed Ivanti/Fortinet devices, VPN credentials and backup access before ESXi-focused deployment. It also highlights legitimate RMM use and deletion of logs. This is a national incident population, not a global claim that every Qilin intrusion exploited those products. [Q30](../References.md#q30)

## Network Evidence Across Earlier Cases

Darktrace's June 2022, April 2023 and May 2024 probable cases show different C2 and exfiltration paths. Its 2023 APAC case includes SMB/DCE-RPC/RDP enumeration and MEGA transfer; its 2024 case includes FTP to `194.165.16[.]13` plus other transfers. A related April case shares infrastructure but lacked observed encryption. Sensor gaps and absence of encryption telemetry cannot establish absence of impact. Those IPs belong to historical case infrastructure, not a universal Qilin C2 set. [Q09](../References.md#q09)

## Collection Priorities

Preserve remote-access/MFA audit, GPO versions/SYSVOL, script blocks, RMM tenant/agent identifiers, cloud-transfer histories, drivers and signing evidence, vCenter/ESXi tasks, ransomware configuration and note bodies. Correlate immutable device/process identifiers and timestamps. Keep operator claims, source observations and inferred chains separate; see [detections](../detections/Detections.md).
