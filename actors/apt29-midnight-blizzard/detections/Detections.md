# APT29 — Detections

**Presentation reviewed:** 2026-09-25.

This directory contains defensive detection and threat-hunting content associated with the APT29 procedures documented in this repository.

> **Review / tuning:** queries are investigation starting points. Validate table or index availability, tenant configuration, approved administration and campaign context before production use. A behavioral or artifact match does not establish APT29 attribution.

## Content

- [KQL](KQL.md) — 28 copyable queries, with Entra ID and Microsoft 365 coverage first.
- [Splunk](Splunk.md) — 28 paired searches using representative sourcetypes and endpoint fields.
- [YARA](APT29-Hunting.yar) — two public NCSC WellMess rules and five contextual repository rules.
- [ATT&CK evidence mapping](../technical/mitre-attack.md).

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 6 | 6 | Entra sign-in, device-code and OAuth/application changes require tenant-specific baselines |
| 2. Active Directory and Network Discovery | 1 | 1 | Administrative discovery and inventory tooling can match |
| 3. Persistence and Remote Administration | 6 | 6 | Correlate identity-object changes with endpoint persistence |
| 4. Tunneling and C2 | 2 | 2 | Historical IoCs and shared anonymity infrastructure require dated context |
| 5. Defense Evasion and Impairment | 1 | 1 | Audit-policy and security-tool administration can be legitimate |
| 6. Collection and Exfiltration | 1 | 1 | Mailbox and Graph activity needs user/application baselines |
| 9. Multi-Stage Correlation | 1 | 1 | Correlation windows are repository triage thresholds |
| 10. Campaign Artifact Hunts | 10 | 10 | Direct and qualified exact indicators, side-loading, provider trust, Run Command and network fingerprints support retrospective review |

## Query Organization

KQL and Splunk use the same identifiers `H01`–`H28`, family order and metadata fields. Platform syntax differs, but each pair implements the same decision. Only populated families appear. Bibliographic sources remain in [References](../References.md).

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| `wellmess_certificate_base64_snippets` | Published by NCSC | Certificate fragments found in a published WellMess sample | PE/ELF context and multiple string groups required; historical rule |
| `wellmess_regex_used_for_parsing_beacons` | Published by NCSC | Command/beacon parsing expressions in WellMess | PE/ELF context required; inspect family and campaign evidence |
| `APT29_CornFlake_Artifact_Bundle_Triage` | Repository-authored | Co-occurring CornFlake service/configuration strings | PE context and multiple strings; not a family proof |
| `APT29_GoldMax_Artifact_Bundle_Triage` | Repository-authored | GoldMax configuration and decoy/C2 implementation strings | Historical behavior heuristic; exact hash remains stronger |
| `APT29_WINELOADER_Staging_Script_Triage` | Repository-authored | Textual ROOTSAW certutil/tar/SqlDumper staging bundle | Can match administrative scripts; requires combined chain |
| `APT29_Retained_SHA256_Exact_Match` | Repository-authored | Exact match against 19 directly attributed or core-campaign SHA-256 values | Includes legitimate campaign bundle members; match identifies a retained file, not maliciousness or current attribution by itself |
| `APT29_Qualified_Cluster_SHA256_Exact_Match` | Repository-authored | Exact match against 13 Google-published UNC6293/UNC7005 SHA-256 values | Moderate-confidence ICE RELIC relationship; includes benign pages/lure and commodity malware; UNC5976 excluded |

## Review Notes

Reviewed **2026-09-25**. Microsoft-published CaptiveCrunch hunts were normalized where necessary; repository-authored hunts translate source-described procedures into testable hypotheses and are labelled accordingly. No recovery-inhibition or ransomware-impact section is added because the source corpus does not support those stages.

See [validation](../../../VALIDATION.md) for presentation checks, query pairing and harmless YARA fixture results.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| Password spray and successful follow-on | SigninLogs / Entra risk and conditional-access fields; compare source, user diversity and later success (H01) |
| Device-code abuse | Authentication protocol, client application, user agent, IP, device registration and Graph activity (H02–H03) |
| OAuth and service-principal persistence | AuditLogs for credentials, consent, roles and mailbox permissions; preserve initiator and target IDs (H04–H06) |
| Mail collection | OfficeActivity, Graph and EWS audit; baseline application IDs and mailbox scope (H07) |
| RDP-file phishing | Email attachment telemetry and RDP client command lines/configuration; inspect redirection settings (H08) |
| AD FS persistence | File/image-load and configuration change events on federation servers (H11–H12) |
| CornFlake | File/process, registry and service telemetry for path and description bundle (H09–H10) |
| WINELOADER | Process sequence, staging path and adjacent DLL load from a legitimate executable (H13–H14) |
| C2 | DNS/proxy/endpoint network events for dated infrastructure; monitor process and SNI/URI context (H15) |
| ChocoShell collection | PowerShell logging, VSS WMI events, browser DB access, token/credential access and cleanup (H20) |
| Exact samples | File/process/image-load SHA-256 across the retained corpus (H19) |
| TeamCity post-exploitation | Process ancestry on known TeamCity servers; establish whether shell/utility execution belongs to an authorized build (H21) |
| GTG-20006 indicators | Network, file and email telemetry for Anthropic's published campaign corpus; retain the qualified cluster boundary (H22) |
| AWS watering hole | Network and redirect telemetry for the two AWS-published domains; correlate any device-code authorization (H23) |
| GRAPELOADER | `POWERPNT` path/Run value, three-file bundle, exact hashes and associated C2 (H19, H24) |
| Delegated provider access | Cross-tenant sign-ins, partner identities, DAP/AOBO context and customer scope (H25) |
| Azure Run Command pivot | Azure control-plane operation, initiating sign-in, target VM and script/change-ticket context (H26) |
| UNC6293 / UNC7005 | Qualified Google domain, IP and file corpus; do not import UNC5976/HEADRUSH (H27) |
| WINELOADER 2025 | Proxy user agent combining Windows 7 with Edge 119; correlate C2 and exact `vmtools.dll` (H28) |
