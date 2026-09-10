# Akira — Vulnerabilities and Exposed Infrastructure

Review date: **2026-09-10**. Confidence describes the **Akira association**, not CVE severity. Product exposure, exploitation evidence and attack stage are separate. Version and patch decisions require the current vendor advisory.

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2020-3259 | Cisco ASA/FTD web services | Information disclosure associated with VPN credential compromise; not itself generic RCE | [A01](../References.md#a01), reporting through Nov. 2025 | High Confidence in reporting |
| CVE-2023-20269 | Cisco ASA/FTD remote-access VPN AAA | Authentication separation weakness; password attacks / remote-access chain | [A01](../References.md#a01), [A18](../References.md#a18), 2023–2025 | High Confidence |
| CVE-2022-40684 | Fortinet FortiOS management interface | Authentication bypass to collect device configuration | [A12](../References.md#a12), June 2023 operator history | High Confidence |
| CVE-2019-6693 | Fortinet FortiOS stored configuration secrets | Offline credential recovery from configuration; not standalone remote entry | [A12](../References.md#a12), June 2023 | High Confidence |
| CVE-2023-48788 | Fortinet **FortiClient EMS**, database interface | SQL injection associated with initial compromise; distinguish EMS server from endpoint client | [A03](../References.md#a03), 2024 | Moderate Confidence; vendor IR reporting |
| CVE-2023-27532 | Veeam Backup & Replication backup service | Retrieval of encrypted stored credentials, enabling subsequent access | [A01](../References.md#a01), [A03](../References.md#a03), 2024–2025 | High Confidence in association; incident stage varies |
| CVE-2024-40711 | Veeam Backup & Replication deserialization | Service exploitation followed by account creation; often after VPN foothold | [A05](../References.md#a05), 2024 STAC5881 | High Confidence |
| CVE-2024-37085 | VMware domain-joined ESXi / AD integration | ESX Admins group abuse for hypervisor administration after sufficient AD access | [A04](../References.md#a04), July 2024 | High Confidence; post-compromise, not unauthenticated internet entry |
| CVE-2024-40766 | SonicWall SonicOS access control | Suspected/likely entry or antecedent credential theft in SSL-VPN cases | [A06](../References.md#a06), [A18](../References.md#a18), Aug. 2024–Sept. 2025 | Moderate Confidence for exploit mechanism; high confidence in VPN intrusion association |
| CVE-2020-3580 | Cisco ASA/FTD web interface | XSS included in updated official association list; exact incident mechanism unspecified | [A01](../References.md#a01), Nov. 2025 revision | Moderate Confidence |
| CVE-2023-28252 | Microsoft Windows CLFS driver | Local privilege escalation, even though listed under initial access in the advisory | [A01](../References.md#a01), Nov. 2025 revision | Moderate Confidence; incident specifics missing |

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| CVE-2021-21972 — VMware vCenter / vSphere Client plugin | Qualys associates it with Akira but supplies limited incident provenance. Retained as **Low Confidence** reporting, not established exploitation in a named case. [A13](../References.md#a13) |
| CVE-2023-20263 — Cisco HyperFlex HX open redirect | The original dossier inherited a Talos ASA/FTD association. Cisco PSIRT identifies a different product and weakness. Excluded from the confirmed exploitation set; suspected source error, with no replacement CVE guessed. [A03](../References.md#a03), [A23](../References.md#a23) |

## Operational Interpretation

Patching an appliance does not invalidate already stolen credentials, sessions or MFA seeds. Investigate credential exposure and access history separately. Arctic Wolf's 2024 cases involved affected firmware but lacked definitive exploit evidence; its 2025 update explicitly left credential theft as a likely explanation and did not connect the MySonicWall backup incident to this campaign. [A06](../References.md#a06), [A18](../References.md#a18)

**Intelligence gaps:** exact exploit dates and affected versions per victim; initial credential acquisition; prevalence by CVE; whether legacy configuration or existing access explains activity on patched systems. Do not add every CVE in an attractive product to an actor's observed exploit list.
