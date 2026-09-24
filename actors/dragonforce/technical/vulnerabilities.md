# DragonForce — Vulnerability Associations

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2025-5777 | Citrix NetScaler ADC/Gateway (“CitrixBleed 2”) | Access broker obtained/replayed sessions in multiple Huntress cases; one downstream chain deployed DragonForce | 2026 Huntress IR | High for route; moderate for DragonForce affiliate ownership |
| CVE-2024-57727 | SimpleHelp RMM | Path traversal used in MSP compromise chain before downstream DragonForce deployment | 2025 Sophos IR | Moderate |
| CVE-2024-57728 | SimpleHelp RMM | Arbitrary file upload/RCE in same campaign context | 2025 Sophos IR | Moderate |
| CVE-2024-57726 | SimpleHelp RMM | API-key privilege escalation in same campaign context | 2025 Sophos IR | Moderate |
| CVE-2023-46805 | Ivanti Connect Secure | Reported public-facing access association under Water Tambanakua | 2025 Trend spotlight | Moderate; no case artifact supplied |
| CVE-2024-21887 | Ivanti Connect Secure | Reported command-injection access association | 2025 Trend spotlight | Moderate |
| CVE-2024-21893 | Ivanti Connect Secure | Reported SSRF/access association | 2025 Trend spotlight | Moderate |
| CVE-2021-44228 | Apache Log4j2 | Reported exploit association | 2025 Trend spotlight | Moderate-low; incident not specified |
| CVE-2024-21412 | Microsoft Windows SmartScreen | Reported security-feature-bypass association | 2025 Trend spotlight | Moderate-low |
| CVE-2023-52271 | Topaz OFD / `wsftprm.sys` | Vulnerable driver used for process termination in Hackledorb-associated case | 2025–2026 Symantec IR | High |
| CVE-2025-61155 | `GameDriverx64.sys` | Vulnerable driver used for security impairment | 2025–2026 Symantec IR | High |
| CVE-2025-1055 | K7 `K7RKScan.sys` | Vulnerable driver used for security impairment | 2025–2026 Symantec IR | High |

The Citrix cases showed 5,937 `AAA_LOGIN_FAILED` messages over roughly five hours with binary/unprintable username data. In a separate session sequence, a legitimate employee completed LDAP plus OTP/MFA at 13:07 UTC from a known address and the same session was used from an adversary address at 13:28 without a second ordinary login. Failure volume and rapid session-source change are concrete log-hunting patterns, not vulnerability scanner signatures.

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| CVE-2024-21412, CVE-2025-1055, CVE-2025-31324, CVE-2021-40539, CVE-2024-57727, CVE-2019-6693, CVE-2024-55591, CVE-2024-57728, CVE-2024-21893 | Listed in FortiGuard’s DragonForce actor card. Only entries independently supported above are treated as observed/reported operational associations |
| CVE-2023-4966, CVE-2024-21762, CVE-2024-57726, CVE-2021-44228, CVE-2021-27878, CVE-2025-8088, CVE-2024-3400, CVE-2025-61882 | FortiGuard catalog association. No reviewed incident-level DragonForce evidence located, except CVE-2024-57726 and CVE-2021-44228 as qualified above |
| CVE-2023-46805, CVE-2025-31161, CVE-2024-21887, CVE-2024-40766, CVE-2023-52271, CVE-2021-27877, CVE-2025-53770, CVE-2025-53771, CVE-2024-37085 | FortiGuard catalog association. CVE-2023-46805, CVE-2024-21887 and CVE-2023-52271 have independent support above; the remainder are not promoted |
| `HWAuidoOs2Ec.sys` | Symantec describes a novel/unknown vulnerable-driver path; no CVE was assigned in the reviewed report |
| AppMgmt registry symbolic-link escalation | Exploit behavior observed by Huntress; this dossier does not assign an unverified CVE |
| SQL/MSSQL exposure in Symantec case | Possible initial route, with broker purchase as alternative; no CVE identified |

FortiGuard’s card is useful as a collection lead but combines actor aggregation with a disputed Malaysia/hacktivism profile. The whole list must not be represented as a complete set of exploits used by one DragonForce operator.

## Operational Interpretation

Patch prioritization should start with the strongest intrusion evidence:

1. Citrix NetScaler systems exposed during CVE-2025-5777 exploitation windows.
2. Internet-facing SimpleHelp servers and downstream trust paths.
3. Ivanti Connect Secure and other reported edge products.
4. Windows vulnerable-driver block rules for the published driver families.
5. Identity/help-desk controls, because prominent affiliates often bypass software vulnerabilities through social engineering.

Vulnerability remediation does not remove stolen sessions, new accounts, RMM agents or backdoors. After patching, invalidate sessions and credentials, inspect administrative changes, check driver/service installation and hunt for the post-access sequence described in the operations file.
