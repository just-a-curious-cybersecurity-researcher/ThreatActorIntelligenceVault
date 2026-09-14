# APT28 — Vulnerabilities and Exposed Infrastructure

Last updated: **2026-09-14**. A CVE's identifier year is not its exploitation date. Source reports are used for actor association; this is not an exploit catalogue or a claim that every listed vulnerability was exploited at every victim.

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2015-3043 | Adobe Flash Player | Delivery in RussianDoll; patch already existed by the article's analysis | 2015; [A72](../References.md#a72) | Probable APT28 association as framed by FireEye |
| CVE-2015-1701 | Microsoft Windows | Local privilege escalation after execution; distinct from Flash delivery | 2015; [A72](../References.md#a72) | Probable campaign attribution |
| MS17-010 / EternalBlue family | Microsoft SMB | Historical lateral movement in hotel case; do not assign an exact exploit CVE from the bulletin name alone | 2017; [A15](../References.md#a15) | Moderate campaign attribution |
| CVE-2017-6742 | Cisco IOS / SNMP | Router exploitation leading to Jaguar Tooth; management exposure and SNMP configuration matter | 2021 activity, 2023 disclosure; [A48](../References.md#a48) | High |
| CVE-2020-0688 | Microsoft Exchange Server | Authenticated remote execution following credential discovery in some cases | 2019–2021 campaign; [A55](../References.md#a55) | High |
| CVE-2020-17144 | Microsoft Exchange Server | Authenticated exploitation for additional access | 2021 advisory; [A55](../References.md#a55) | High |
| CVE-2022-38028 | Windows Print Spooler | GooseEgg local elevation; post-compromise, not the original entry point | Microsoft 2024 disclosure; [A17](../References.md#a17) | High |
| CVE-2023-23397 | Outlook for Windows | Crafted item triggers Net-NTLMv2 leakage; subsequent relay/mail access are separate events | Exploitation since 2022 in FBI account; ongoing after patch in reporting; [A16](../References.md#a16), [A20](../References.md#a20) | High |
| CVE-2023-38831 | WinRAR | Malicious archive handling during delivery | 2023 FROZENLAKE campaign; [A39](../References.md#a39), [A21](../References.md#a21) | High |
| CVE-2023-50224 | TP-Link router web interface | Credential disclosure followed by configuration abuse; NCSC says likely exploited for the WR841N path | 2024–2026; [A32](../References.md#a32) | Moderate for exact CVE; high for documented DNS campaign |
| CVE-2026-21509 | Microsoft Office / OLE security boundary | Malicious documents trigger delivery; Zscaler observed exploitation after emergency patch publication | Patch 2026-01-26, observed 2026-01-29; [A29](../References.md#a29) | High |
| CVE-2026-21513 | Windows MSHTML framework | Trend reports zero-day activity but qualifies the proposed connection to the CVE-2026-21509-delivered LNK chain | 2026; [A31](../References.md#a31) | Qualified; shared-infrastructure linkage not independently confirmed by Trend |

The MS17-010 row is intentionally a bulletin/exploit-family association, not an invented single CVE.

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| RoundPress / SpyPress vulnerabilities | ESET's medium-confidence Sednit attribution is not silently upgraded. Proofpoint tracks TA458 separately from TA422, including SOGo CVE-2026-8496 and other webmail exploits. Not included as confirmed core APT28 CVEs. [A60](../References.md#a60), [A45](../References.md#a45) |
| CVE-2026-21509 described as a zero-day | Zscaler's observation is after disclosure. Earlier infrastructure preparation alone does not prove earlier exploitation. [A29](../References.md#a29), [A31](../References.md#a31) |
| GooseEgg and PrintNightmare alert names | Microsoft's listed generic detection names do not establish that CVE-2021-34527 was the GooseEgg exploit. Preserve the CVE-2022-38028 association. [A17](../References.md#a17) |
| MooBot and default router credentials | Access reuse is documented; do not assign an unsupported Ubiquiti product CVE. [A19](../References.md#a19), [A20](../References.md#a20) |
| Captive portal / Wi-Fi exploitation | Nearest-neighbor access used valid credentials and proximity; CaptiveCrunch belongs to Midnight Blizzard. Neither establishes an APT28 captive-portal CVE. [A18](../References.md#a18), [A46](../References.md#a46) |
| Fortinet, Ivanti, Citrix, Veeam, VMware entries in other dossiers | Not imported from ransomware cases without APT28-specific evidence. |
| Splinter, VPNFilter and Sandworm exploit lists | A generic tool or historically conflated actor label does not justify transferring CVEs into this table. [A10](../References.md#a10), [A47](../References.md#a47) |

## Operational Interpretation

Prioritize exposed authentication, email clients/servers, network-device management and local escalation paths according to the organization's actual assets. Patching removes a vulnerability; it does not revoke previously stolen credentials or restore a modified router configuration.

The public advisories recommend supported firmware, restricted management exposure, strong authentication, monitoring and appropriate NTLM protections. Their recovery guidance includes more than rebooting an infected router. [A20](../References.md#a20), [A32](../References.md#a32), [A55](../References.md#a55)

For confirmed compromise, validate restoration of configuration and access controls, investigate affected identities and retain evidence of the original state. Use the [published hunting collection](../detections/Detections.md); no exploit payloads are included.
