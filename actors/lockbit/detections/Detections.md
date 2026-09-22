# LockBit — Detections and Hunting

**Presentation reviewed:** 2026-09-17.

## Content

- [KQL queries](KQL.md): 40 copyable entries.
- [Splunk searches](Splunk.md): 40 paired investigative entries.
- [YARA rules](LockBit-Hunting.yar): four public CISA signatures and ten local artifact rules.
- [ATT&CK mapping](../technical/mitre-attack.md).
- [Indicator provenance](../iocs/IOCs.md).
- [Executable analyses](../intelligence/encryptor/README.md).

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | L01, L02, L03, L04 | L01, L02, L03, L04 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 2. Active Directory and Network Discovery | L05, L06, L07 | L05, L06, L07 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 3. Persistence and Remote Administration | L08, L09, L10, L11 | L08, L09, L10, L11 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 4. Tunneling and C2 | L12, L13, L14 | L12, L13, L14 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 5. Defense Evasion and Impairment | L15, L16, L17, L18, L19, L20 | L15, L16, L17, L18, L19, L20 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 6. Collection and Exfiltration | L21, L22, L23 | L21, L22, L23 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 7. Recovery Inhibition | L24, L25 | L24, L25 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 8. Deployment and Impact | L26, L27, L28, L29 | L26, L27, L28, L29 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 9. Multi-Stage Correlation | L30 | L30 | Baseline legitimate activity; use the entry's required source and tuning notes |
| 10. Campaign Artifact Hunts | L31, L32, L33, L34, L35, L36, L37, L38, L39, L40 | L31, L32, L33, L34, L35, L36, L37, L38, L39, L40 | Baseline legitimate activity; use the entry's required source and tuning notes |

## Query Organization

Each query has the same ordered fields as Akira: origin, telemetry, review / tuning, then one code block. IDs pair KQL and Splunk by investigative intent.

Most KQL entries use Defender tables; L19 and L36 explicitly require Sentinel WindowsEvent and Syslog. Splunk uses a documented EDR normalization contract, with separate Windows and ESXi indexes for those entries. Field mapping is required before local execution.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| CISA_10478915_01 | Published CISA YARA | a.bat credential-collection wrapper | Exact public strings; actor/family metadata remains n/a |
| CISA_10478915_02 | Published CISA YARA | a.exe loader sample | PE imports/code-size condition; not a universal encryptor detector |
| CISA_10478915_03 | Published CISA YARA | a.dll credential-dump sample | PE structure and strings; not family-wide attribution |
| CISA_10478915_04 | Published CISA YARA | a.py WinRM script | Static script strings; execution and authorization require separate evidence |
| LOCKBIT_5_Published_Payloads_Exact | Local exact SHA-256 artifact rule | Published Windows and Linux-family 5.0 artifacts | Historical exact match; evidence repositories can match; file identity does not establish execution or service membership. |
| LOCKBIT_Black_Published_Payloads_Exact | Local exact SHA-256 artifact rule | Black published payloads; leaked-builder use prevents service attribution | Historical exact match; evidence repositories can match; file identity does not establish execution or service membership. |
| LOCKBIT_Native_4_Published_Payloads_Exact | Local exact SHA-256 artifact rule | Native 2025 4.0 sample set | Historical exact match; evidence repositories can match; file identity does not establish execution or service membership. |
| LOCKBIT_NGDev_Published_Sample_Exact | Local exact SHA-256 artifact rule | NG-Dev development sample; not a universal 4.0 identifier | Historical exact match; evidence repositories can match; file identity does not establish execution or service membership. |
| LOCKBIT_Possible_Impostors_2024_Exact | Local exact SHA-256 artifact rule | Unit 42 possible 4.0 impostor files; separate attribution | Historical exact match; evidence repositories can match; file identity does not establish execution or service membership. |
| LOCKBIT_Black_Builder_Resources_Exact | Local exact SHA-256 artifact rule | Black builder, key generator and embedded resources; mixed artifact roles | Historical exact match; evidence repositories can match; file identity does not establish execution or service membership. |
| LOCKBIT_5_Note_Triage | Local static triage heuristic | LockBit 5.0-branded note content; branding does not prove actor | Text heuristic; documentation, restored notes and independent impostors can match. Not an executable signature. |
| LOCKBIT_Black_Note_Triage | Local static triage heuristic | LockBit 3.0-branded note context | Brand plus negotiation context; copied notes and reports match. Not a service attribution. |
| LOCKBIT_NGDev_Configuration_Triage | Local static triage heuristic | NG-Dev configuration key cluster in extracted configuration or memory | Requires recovered plaintext configuration/memory; packed disk payload may not match. Source code and reports match. |
| LOCKBIT_Impairment_Transfer_Script_Triage | Local static triage heuristic | Generic recovery-impairment and transfer-script triage | Generic multi-family text heuristic; admin/IR scripts and documentation match. Does not detect temporal execution. |

## Review Notes

CISA rules are reproduced from the public advisory with their predicates and metadata retained; formatting is normalized and the required PE module import is supplied. Local exact-hash rules match historical artifacts. Local heuristics are triage aids, not vendor-certified detections.

A 16-hex suffix is not exclusive to 5.0, and invisible operation can suppress notes and renaming. The note-or-suffix search preserves note-only hits; it does not apply a later regex that accidentally discards them.

No KQL or Splunk service was connected for runtime validation. YARA compilation and harmless fixtures test syntax and selected positive/negative boundaries; they do not establish production sensitivity or false-positive rates.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| Internal ETW modification / reflective payload | EDR memory inspection, executable private regions and API provenance; command-line strings cannot directly prove these routines |
| Direct service-control APIs | SCM state/configuration events plus process-level EDR data; sc.exe-only hunts are incomplete |
| Direct shadow-copy deletion | WMI/VSS and backup-system records, correlated with process and privilege context |
| Invisible file encryption | File-integrity/storage telemetry and recoverable originals; Defender file events are not an entropy sensor |
| GPO modification | Directory changes, SYSVOL audit and scheduled-task registration; an executable write alone does not establish policy application |
| ESXi impact | Forward shell, hostd/vpxa and VM power/storage events off host before impact |
| NetScaler session reuse | Appliance session logs, source-IP changes and downstream identity context; endpoint queries alone cannot establish the initial exploit |
| Financial attribution | Source-specific address roles and dates; do not merge impostor or affiliate wallets with a sanctioned administrator |

