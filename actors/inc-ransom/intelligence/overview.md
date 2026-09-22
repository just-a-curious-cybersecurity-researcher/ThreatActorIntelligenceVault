# INC Ransom — Overview

**Presentation reviewed:** 2026-09-22.

## Background

INC Ransom emerged in mid-2023 as a financially motivated extortion operation. The actor brand, INC-branded malware and individual intrusion clusters should be tracked separately. MITRE distinguishes the group G1032 from software S1139.

## Targeting and Victimology

Healthcare, education, manufacturing, government and professional services recur in the collected material. Western organizations feature prominently, alongside Australian, New Zealand and Pacific victims. Ransomware impacts clinical and public services beyond the confidentiality of stolen files.

The official regional advisory records 11 Australian incidents between 2024-07-01 and 2025-12-31. It also describes healthcare incidents in New Zealand and Tonga. These are scoped observations, not a worldwide total.

## Operational Model

The current official account describes a RaaS structure: affiliates conduct intrusions and the core manages extortion infrastructure and payments. Secureworks' earlier 2024 assessment described a closed group. Retain the dates of those assessments rather than rewriting the earlier report as if it had already established the later affiliate model.

Operators obtain access, discover valuable systems, steal data, impair recovery and deploy an encryptor. Tools and paths vary between incidents.

## Ransomware Development

Classic Windows payloads and Linux/ESXi targeting precede the Rust generations reported in 2026. The [executable analysis](encryptor.md) separates these branches and their cryptographic/file-format evidence.

Code overlap with Lynx and Sinobi does not turn their sample sets into INC samples. A shared codebase can support technical lineage without establishing common ownership of every campaign or negotiation panel.

## Data Leak Site

Public leak infrastructure advertises victims and stolen information; private negotiation infrastructure handles victim communication. Leak-site listings are actor claims and collection events, not a deduplicated list of proven intrusions.

The [onion register](../iocs/onion-infrastructure.md) records roles and provenance. Archive links are grouped in the single [ransom-note index](../ransom-notes/Ransom-Notes.md).

## Current Evolution in the Collected Research

The 2026 material adds Rust payload analysis, backup-credential targeting, renamed cloud-backup tools and incident-specific driver loaders. These changes broaden detection opportunities across identity, endpoint and storage telemetry.

Language choice alone does not establish superior evasion. Rust artifacts help identify implementation changes; effectiveness depends on the actual code, configuration and defensive visibility.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| 2023-07–2023-08 | Emergence in collected reporting; early Huntress investigation documents deployment and exfiltration |
| 2023-12 | Linux variant appears in Trend Micro's historical account |
| 2024-04 | Secureworks publishes GOLD IONIC intrusion findings and an early closed-group assessment |
| 2024-06-04 | SonicWall documents Linux-generated ESXi helpers; its displayed delete script removes snapshots |
| 2024-07–2024-08 | Classic sample analysis and GuidePoint recovery research clarify execution and encrypted-file structure |
| 2024 onward | Lynx code relationship enters public reporting; INC remains a distinct tracking scope |
| 2025-06-15 | Tonga Ministry of Health incident described by the joint regional advisory; leak claim followed on 2025-06-26 |
| 2026-02 | Huntress cases document Restic-based exfiltration and INC deployment |
| 2026-03-06 | ACSC/CERT Tonga/NCSC advisory describes the affiliate model and regional incidents |
| 2026-05-19 | Microsoft reports a malware-signing supplier relationship involving INC affiliates |
| 2026-06-17 | Acronis publishes Windows/Linux Rust analysis |
| 2026-09-21 | Huntress publishes an August incident timeline with driver activity and two ransom-note stages |

## Law-Enforcement Development

The joint government advisory publicly identifies Roman Khubov, also known as blackod, in connection with exfiltration infrastructure used in the Tonga incident. That attribution concerns an infrastructure role in a specific case; it does not identify him as the leader or developer of the entire operation.
