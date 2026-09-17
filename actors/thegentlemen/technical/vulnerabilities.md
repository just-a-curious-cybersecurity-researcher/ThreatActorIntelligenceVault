# The Gentlemen — Vulnerabilities

**Presentation reviewed:** 2026-09-17.

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2025-7771 | ThrottleStop.sys driver | Local driver abuse for defense impairment; not internet entry | Unit 42 actor reporting; Kaspersky driver research | High in driver identity; campaign association vendor-reported |
| CVE-2024-55591 | FortiOS / FortiProxy management interface | Authentication bypass on exposed management; discussed in chats; exploitation reported by Group-IB and Unit 42 | 2026 reporting | High in Group-IB's reported observations; not assigned to the separate August 2025 case |
| CVE-2025-32433 | Erlang/OTP SSH | Remote-code-execution opportunity; evaluated in chats, subsequently listed by Unit 42 | 2026 reporting | Moderate; chat evidence alone establishes evaluation |
| CVE-2025-33073 | Windows SMB client | NTLM reflection/relay-related privilege path | Chat/tool discussion and Unit 42 association | Moderate; not a universal perimeter-entry step |
| CVE-2025-55182 | React Server Components | Internet-facing application exploitation association | Unit 42 reporting | Moderate; contextual vendor association |

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| CVE-2024-37085 / CVE-2023-27532 | CUHK lists ESXi AD-integration and Veeam credential-exposure associations; retained as research leads rather than proven exploit steps in the Trend Micro case. |
| CVE-2017-0144 / CVE-2020-1472 / CVE-2021-36942 / CVE-2024-21412 | Supplied tracker entries; tool availability and broad matrices do not establish successful exploitation. |
| Unspecified zero-day in Unit 42's July update | Retained as a suspected vendor-reported capability; no CVE, exploit trace or confirmed affected product is inferred. |
| FortiGuard's extended CVE list | Reviewed as actor-profile associations; additional undetailed entries not promoted to confirmed incidents. |
| Allpatch2.exe / PowerRun | Tool use is not itself a new CVE. The primary case does not demonstrate modification of PowerRun. |
| Initial access in August 2025 case | Exposed services or credentials are assessed; no exact entry CVE is assigned. |

## Operational Interpretation

Prioritize the affected asset and stage: exposed management, Windows authentication, backup infrastructure and vulnerable drivers need different evidence. Apply vendor remediation appropriate to the deployed product/version. These associations are not an exploitation procedure.
