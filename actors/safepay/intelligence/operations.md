# SafePay — Operational Lifecycle

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR  

SafePay intrusions are hands-on operations. The sequence below distinguishes actions observed in incident response from tools or vectors listed only in aggregate profiles.

## 1. External Reconnaissance

The operators identify exposed VPN, RDP and edge access and test credential quality. DCSO directly observed password spraying against a VPN gateway. NCC documented a FortiGate policy misconfiguration that allowed a local account to authenticate to VPN without the MFA control applied to the intended group. FortiGuard additionally lists purchased access, stolen credentials and weak passwords.

The available cases support identity and configuration discovery more strongly than exploitation of a specific CVE. An exposed product or a vendor CVE tag must not be treated as proof that the vulnerability opened a given SafePay intrusion.

## 2. Initial Access

Observed routes include a valid account through RDP/VPN, password spraying and a remote-access policy error combined with weak passwords. Huntress saw access from a VPN gateway or portal followed by RDP, without evidence that the actor created the original account. NCC saw a local VPN account followed by escalation into a domain-administrator account lacking MFA.

The reported Ingram Micro route through GlobalProtect remains public reporting rather than a victim-confirmed root cause. No specific GlobalProtect CVE was established in the reviewed corporate disclosure.

Sygnia's 2025 case began through SSL VPN on a FortiGate appliance. The accessible administrative account was weak, lacked MFA, was permitted to authenticate to VPN and was domain-enabled even though it was intended for local appliance administration. Sygnia called the condition a firewall flaw and misconfiguration but did not identify a CVE. Triskele independently observed VPN entry and described exposed VPN/RDG services and compromised credentials across its SafePay-related response work.

## 3. Execution and Foothold

Batch files such as `C:\ProgramData\<single digit>.bat` coordinate discovery and deployment. NCC observed `1.bat` and `1.exe`; Huntress observed a DLL loaded through `regsvr32.exe` with victim password, encryption-level, UAC and path arguments. PowerShell and `cmd.exe` support reconnaissance, Defender changes, wallpaper retrieval and staging.

QDoor provides a separate foothold in the NCC case. `soc.dll` exports `DllRegisterServer`, begins through `regsvr32.exe`, unpacks an embedded DLL, maps it into memory, creates `WerFault.exe` suspended and uses RunPE-style process hollowing. Its final payload registers with hard-coded C2 and supports heartbeat and tunnel commands.

## 4. Credential Access

Public profiles list Mimikatz. NCC saw a temporary artifact detected as `Behavior:Win32/RemoteRegDump.A`, consistent with an attempt to collect credential material. The attacker then used a domain-administrator account and, near impact, changed administrative passwords to obstruct recovery.

Credential evidence is case-scoped. The recurring use of valid accounts and password spraying makes identity logs, MFA policy evaluation and source-device continuity more useful than searching only for one credential-dumping filename.

## 5. Discovery and Active Directory Reconnaissance

ShareFinder, SharpShares and native commands enumerate accessible servers and shares. DCSO observed targeted collection after SharpShares identified business data; Huntress saw ShareFinder blocked by Defender before the actor impaired protection. NCC linked the batch workflow to servers, drives and shares that were later encrypted.

System-language inspection is also part of early execution in some builds. The early locker exits on selected CIS languages; a later DCSO build did not retain that guard.

Sygnia recovered a broader, case-specific discovery set: `nslookup.exe`, `ping.exe`, `powershell.exe`, `dsa.msc`, `ServerManager.exe`, Advanced IP Scanner, NetScan, SharpShares, ShareFinder and Snaffler. `RouteCIDR.py`, `p.bat_S.bat`, `p.bat_W.bat`, `check.ps1`, `search.ps1` and `sorted.ps1` produced or filtered domain, route, host and share information. This cluster is stronger than any one filename because several tools are common in administration and security testing.

## 6. Privilege Escalation

The locker attempts to obtain or use elevated rights and enables `SeDebugPrivilege`. Huntress identified behavior consistent with the auto-elevating CMSTPLUA COM interface, including `DllHost.exe` ancestry and the CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`. The CLI includes `-uac` and `-uac=` forms, although the precise meaning of every build’s `-uac=` value remains unresolved.

The operators also exploit identity-control gaps: NCC’s actor moved from a local VPN account to an unprotected domain-administrator account. This is privilege escalation through account control rather than a software exploit.

## 7. Lateral Movement

RDP provides interactive movement. SMB and administrative shares distribute batch files and the locker to servers. NCC recorded commands shaped as:

```text
start C:\[locker].exe -pass=[victim-key] -path=\\[host]\[share] -enc=1
```

Huntress observed remote-share impact through a DLL invocation shaped as:

```text
C:\Windows\SysWOW64\regsvr32.exe /n "/i:-pass=[victim-key] -enc=[level] -uac -path=\\[host]\[share]\ -uac=[value]" C:\[locker].dll
```

These redacted forms are telemetry references. Their presence does not prove that encryption succeeded.

Sygnia observed domain-administrator credentials used to reach identity, file, backup and virtualization infrastructure. RDP remained the primary interactive channel, with C$ and ADMIN$ traversal visible in Shellbags and other file-access artifacts. The operators interacted with Hyper-V utilities and a local vCenter/ESXi console. This establishes operator access to virtualization management, not a native ESXi SafePay binary. Triskele also observed AnyDesk in SafePay-related response work.

## 8. Defense Evasion

In one Huntress incident, ShareFinder was blocked and the actor then disabled Defender using trusted Windows interfaces and commands also seen in an INC deployment. The activity produced Defender configuration and protection-state changes, including events 5001 and 5007. Microsoft also reports direct GUI manipulation through `SystemSettingsAdminFlows.exe`.

The locker constructs more than one hundred strings on the stack and decodes them with an index-dependent triple-XOR routine. API names are resolved with a CRC32-based scheme. QDoor adds modified-UPX packing, an embedded stage and process hollowing. Optional self-deletion and trusted `regsvr32.exe` execution further reduce simple filename-based coverage.

Sygnia saw operators delete scripts, discovery outputs and staged RAR volumes after use. Triskele observed Proton VPN and Mullvad used to obscure the source of interactive activity. These services are legitimate and shared; tenant/session history and behavior are better evidence than provider IP reputation alone.

## 9. Persistence and Remote Access

NCC found a `ScreenConnect Client` service configured for automatic start under LocalSystem; its precise use in that case was not fully observed, so persistence is probable rather than proven. Microsoft reports optional Run-key persistence in some telemetry. Huntress saw neither new users nor a persistence mechanism in its first two incidents.

Persistence is therefore variable. Defenders should preserve service creation, registry Run keys, RMM tenant details and the first-seen installer rather than assume every SafePay intrusion uses a fixed mechanism.

Sygnia directly confirmed the Run-key pattern: entries under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` launched `locker.dll` through `regsvr32.exe` at user logon from a centralized server, allowing the process to work against remotely reachable data. This closes the earlier evidence gap for at least one 2025 incident while remaining case-scoped.

## 10. Command and Control / Tunneling

QDoor communicated with `88.119.167[.]239:443` using an unencrypted custom protocol beginning with `C4 C3 C2 C1`; commands included heartbeat and tunnel setup. Halcyon and Microsoft additionally publish `45.91.201[.]247`, `77.37.49[.]40` and `80.78.28[.]63` as SafePay-associated C2 infrastructure.

The DLS and negotiation environment uses Tor, with a TON mirror also advertised. Onion endpoints are extortion infrastructure and should not be assumed to be malware C2.

## 11. Collection and Exfiltration

DCSO observed SharpShares-driven selection, WinRAR compression and 450 GB of successful exfiltration by an unidentified channel. Huntress saw WinRAR archive remote-user data across three hosts, then FileZilla 3.67.1 and `fzsftp.exe` installed and rapidly removed. Huntress lacked network evidence to prove that FileZilla completed the transfer.

FortiGuard lists 7-Zip, Rclone and FileZilla. Microsoft also reports Rclone, but these aggregated associations do not establish universal use. The defensible hunt is a sequence: unusual share discovery, large archive creation, first-seen transfer tooling and outbound volume before recovery inhibition.

Sygnia observed the actor seek Veeam service credentials with native PowerShell, stage split WinRAR volumes, and attempt FileZilla transfer to `192.166.225[.]69`. When FTP was blocked, the operators signed a compromised server into their own Microsoft 365 tenant and synchronized the archives to OneDrive for Business over ordinary HTTPS. Browser history exposed `jjvq-my-sharepoint[.]com`; the published IOC table records `jjvq-sharepoint[.]com`. The NTFS MFT retained deleted `$Orphan` entries for multipart archives named around `Data`, `SQL`, `Accounting`, IP addresses and other victim-like paths.

Triskele adds two other patterns: use of the RDP clipboard during staging and transfer directly over the VPN connection without dedicated tooling. These cases explain why a hunt limited to FileZilla or Rclone will miss part of the SafePay egress picture.

## 12. Recovery Inhibition

The locker stops database, mail, backup and Volume Shadow Copy services and terminates applications that can lock target files. Documented recovery commands include:

```text
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
```

DCSO also observed active searches for backup systems followed by encryption of them. These actions can be emitted by the binary itself and should not automatically be attributed to a separate operator script.

## 13. Ransomware Deployment and Impact

The victim-specific `-pass` value decrypts embedded configuration; `-enc` controls partial-encryption depth. The program enumerates local, mapped and remote targets, excludes system paths and file types, stops configured services and processes, encrypts through a multithreaded asynchronous queue, appends `.safepay`, adds recovery metadata to the file and drops `readme_safepay.txt` or a related note.

NCC’s `-enc=1` case encrypted 1 MiB from each 10 MiB region. Revised builds select AES-CBC on AES-NI-capable CPUs and ChaCha20 otherwise; early reporting described ChaCha20. Each file receives independent random key material protected through X25519/Curve25519 exchange. No public implementation weakness was identified that permits recovery without the actor’s private material.

## Operational Detection Principle

Prioritize sequences over brand strings: anomalous remote authentication, share discovery, RMM or QDoor staging, archive creation, Defender changes, backup/service interruption and mass file rename activity. Exact hashes are useful for known samples but do not cover customized or later builds.

## Evidence Anchors for the Lifecycle

- **Huntress:** two October 2024 incidents, RDP/VPN access, Defender impairment, WinRAR/FileZilla, DLL deployment and binary analysis.
- **DCSO:** password-sprayed VPN, long dwell, SharpShares, 450 GB theft, telephone pressure and revised-build reverse engineering.
- **NCC Group:** FortiGate policy error, weak credentials, ScreenConnect, QDoor, RDP/SMB distribution, password changes and encryption details.
- **Microsoft:** family behavior, algorithm selection, optional persistence, wallpaper and combined IOC synthesis.

## Additional Case Evidence

- **Unnamed global organization, 2025; Sygnia publication 2026-03:** VPN/FortiGate entry, domain-admin access within hours, seven days of staging and OneDrive exfiltration, then encryption of more than 60 servers. This is the most detailed public SafePay intrusion chain reviewed.
- **Australian/APAC organizations, published 2026-06:** Triskele describes direct response to SafePay-related intrusions involving VPN/RDG exposure, valid accounts, RDP, AnyDesk, common archive/transfer tools, anonymizing VPNs and direct VPN exfiltration. The article inconsistently says both two and three engagements; the dossier uses the behavior but does not infer a case count.

- **Ingram Micro, 2025-07:** the victim confirmed ransomware, temporary global operational disruption and restoration; SafePay attribution and the 3.5 TB claim came through later reporting and DLS activity.
- **Conduent, 2024-10 to 2025-01:** the company confirmed unauthorized access, exfiltration, response costs and client notification. SafePay separately claimed 8.5 TB. Affected-person counts expanded as client datasets were processed.
- **Children’s Council of San Francisco, 2025-08:** official filings confirm unauthorized access and notification to 12,655 people. SafePay’s claim is separate and was not acknowledged by the victim.
- **Ryomo, ARA Lyss and `gob.pe`, 2026-09:** tracker-visible SafePay claims without public technical confirmation at cutoff.

## Negotiation and Organizational Signals

The note states a purely financial motive, directs victims to two Tor chat endpoints, gives a victim ID, advertises Tor/TON blogs and sets a ten-day response period before a three-day publication countdown. DCSO observed direct phone calls after encryption. Negotiation behavior supports centralized brand control but does not reveal the legal identity or physical location of the operators.
