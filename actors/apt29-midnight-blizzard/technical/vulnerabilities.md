# APT29 — Vulnerabilities and Exposed Infrastructure

**Presentation reviewed:** 2026-09-25.

Last updated: **2026-09-25**. The table records actor-specific public reporting. A CVE year is not the exploitation date, and inclusion does not imply use in every APT29 campaign.

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2018-13379 | Fortinet FortiOS SSL VPN | Path traversal used against exposed VPN appliances for access or credential material | Listed in 2021 NSA/CISA/FBI SVR advisory | High for government-reported SVR use |
| CVE-2019-9670 | Synacor Zimbra Collaboration Suite | XXE vulnerability used against exposed mail infrastructure | Listed in 2021 joint advisory | High for government-reported SVR use |
| CVE-2019-11510 | Pulse Secure Pulse Connect Secure | Arbitrary file read used against exposed VPN appliances | Listed in 2021 joint advisory | High for government-reported SVR use |
| CVE-2019-19781 | Citrix ADC / Gateway | Directory traversal and code execution path against exposed remote-access infrastructure | Listed in 2021 joint advisory | High for government-reported SVR use |
| CVE-2020-4006 | VMware Workspace ONE Access / Access Connector / Identity Manager | Command injection used against internet-facing identity infrastructure | Listed in 2021 joint advisory | High for government-reported SVR use |
| CVE-2022-27924 | Zimbra Collaboration Suite | Unauthenticated memcache-command injection used against mail servers at hundreds of domains; enabled credential and mailbox access without victim interaction | Confirmed exploited in 2024 joint SVR advisory | High |
| CVE-2023-42793 | JetBrains TeamCity Server | Authentication bypass and remote code execution used for initial access, followed by privilege escalation, lateral movement, additional backdoors and durable access | Exploited at scale from 2023-09; joint AA23-347A assessment | High |

SolarWinds was a software build and update-channel compromise, not exploitation of a SolarWinds Orion CVE. The WINELOADER chain used social engineering, a compromised website and Windows utilities; no client vulnerability is assigned from that report. The agencies behind AA23-347A warned that TeamCity access exposed source code, signing certificates and build/release processes, but the limited opportunistic victim set then known did not show an SVR supply-chain operation comparable to SolarWinds.

## Qualified and Disputed Entries

The 2024 joint advisory separately lists publicly disclosed vulnerabilities as technologies the agencies assess SVR operators have the **capability and interest** to exploit. It does not state that APT29 exploited each one. They are retained below for exposure management, not promoted into the confirmed table. The same advisory repeats CVE-2018-13379 and CVE-2023-42793; both remain in the supported table because separate government reporting documents actor use.

| Entry | Disposition |
|---|---|
| CVE-2023-20198 | Cisco IOS XE web UI privilege escalation / local-user creation; capability and interest only, not confirmed APT29 exploitation. |
| CVE-2023-4911 | GNU C Library `ld.so` local privilege escalation; capability and interest only. |
| CVE-2023-38545 / CVE-2023-38546 | libcurl SOCKS5 heap overflow / cookie insertion; capability and interest only. |
| CVE-2023-40289 | Supermicro X11 management-firmware command injection; capability and interest only. |
| CVE-2023-24023 | Bluetooth BR/EDR BLUFFS key-downgrade condition; capability and interest only. |
| CVE-2023-40076 / CVE-2023-40077 / CVE-2023-40088 | Android credential access, privilege escalation or adjacent remote-code-execution issues; capability and interest only. |
| CVE-2023-45866 | BlueZ Bluetooth HID unauthenticated keystroke injection; capability and interest only. |
| CVE-2022-40507 | Qualcomm double-free condition; capability and interest only. |
| CVE-2023-36745 | Microsoft Exchange Server remote code execution; capability and interest only. |
| CVE-2023-4966 | Citrix NetScaler ADC/Gateway buffer overflow; capability and interest only. |
| CVE-2023-6345 | Google Chrome integer overflow / possible sandbox escape; capability and interest only. |
| CVE-2023-37580 | Zimbra cross-site scripting; capability and interest only. |
| CVE-2021-27850 | Apache Tapestry unauthenticated remote code execution; capability and interest only. |
| CVE-2021-41773 / CVE-2021-42013 | Apache HTTP Server traversal / remote code execution; capability and interest only. |
| CVE-2023-29357 / CVE-2023-24955 | Microsoft SharePoint Server privilege escalation / remote code execution; capability and interest only. |
| CVE-2023-35078 | Ivanti Endpoint Manager Mobile authentication bypass; capability and interest only. |
| CVE-2023-5044 | Kubernetes ingress-nginx code injection; capability and interest only. |
| Log4Shell / CVE-2021-44228 | Not added without an APT29-specific primary case in the reviewed corpus; broad Russian exploitation reporting is insufficient. |
| Microsoft Exchange ProxyLogon family | SVR actors used Exchange web shells in public reporting, but this dossier does not assign a specific ProxyLogon CVE without source-level linkage. |
| SolarWinds Orion vulnerability labels | Excluded. SUNSPOT modified the build process and SUNBURST was delivered through signed updates; this is T1195.002, not generic vulnerability exploitation. |
| Device-code and OAuth abuse | Protocol and identity-flow abuse, not a Microsoft software vulnerability. Conditional Access and token controls are the relevant defenses. |
| CaptiveCrunch captive portals | Microsoft had not resolved the initial compromise vector for portal networks at publication; no appliance CVE is inferred. |
| MAGICWEB / FoggyWeb | Post-compromise AD FS persistence requiring privileged access; no initial-access CVE is inferred from the implant. |
| CVEs attributed to APT28, Sandworm or Turla | Not transferred across Russian services or actors. Shared state nexus does not establish exploitation by APT29. |

## Operational Interpretation

Prioritize exposed VPN, mail and identity infrastructure that matches the supported product set, then inspect identity history after patching. A patched appliance does not revoke stolen passwords, cookies, application credentials or tokens.

For cloud-focused activity, audit dormant and service accounts, enforce phishing-resistant MFA, constrain device-code authentication, review device enrollment and application consent, rotate service-principal credentials, and validate federation configuration. For SolarWinds-era exposure, use the vendor and government scoping guidance rather than a CVE scanner result.

The [detection collection](../detections/Detections.md) focuses on observable access and persistence. No exploit code or reconstruction steps are included.
