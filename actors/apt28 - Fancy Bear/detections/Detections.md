# APT28 — Detections

This directory contains published defensive detections and hunting material based on the APT28 activity documented in this dossier.

> **Important:** review sensor coverage, product dependencies and local administrative baselines before deployment. A match supports investigation; it does not establish APT28 attribution.

## Content

- [Published YARA](APT28-Hunting.yar) — Four official HEADLACE / MASEPIE hunting rules
- [KQL](KQL.md) — Three published Microsoft GooseEgg queries
- [Splunk](Splunk.md) — Four published Splunk Outlook searches

## September 2026 Review

**Last updated:** 2026-09-14. Rules and queries retain publisher logic; no new detection rule is attributed to a vendor. Public source status does not establish production suitability. Neither a matching string nor an ATT&CK technique proves APT28 attribution.

**APT28_HEADLACE_SHORTCUT.** Type: YARA Coverage: Internet shortcut dropper Source: [A21](../References.md#a21), pp. 19–20 Publication / revision: 2025-05-21 Notes: Hunt; contextual triage required

**APT28_HEADLACE_CREDENTIALDIALOG.** Type: YARA Coverage: Credential-dialog script Source: [A21](../References.md#a21), p. 20 Publication / revision: 2025-05-21 Notes: Five matching strings; no execution required

**APT28_HEADLACE_CORE.** Type: YARA Coverage: HEADLACE batch core Source: [A21](../References.md#a21), pp. 20–21 Publication / revision: 2025-05-21 Notes: Generic command overlap possible

**APT28_MASEPIE.** Type: YARA Coverage: Python backdoor text Source: [A21](../References.md#a21), p. 21 Publication / revision: 2025-05-21 Notes: Static content coverage

**GooseEgg driver-store / registry queries.** Type: KQL Coverage: File and registry telemetry Source: [A17](../References.md#a17) Publication / revision: 2024-04-22 Notes: Schema and string representation need tenant validation

**NotDoor analytic story.** Type: SPL Coverage: Outlook macro file and registry changes Source: [A50](../References.md#a50)–[A54](../References.md#a54) Publication / revision: 2026-05-13 revision Notes: Requires CIM and publisher macros; see upstream limitations

**New Outlook Macro Created.** Type: Sigma Coverage: Outlook-created VbaProject.OTM Source: [A75](../References.md#a75) Publication / revision: 2023-02-08 revision Notes: Status test; generic macro creation, not a NotDoor signature

**Jaguar Tooth, SIDs 230418000–230418006.** Type: Snort Coverage: Cisco SNMP exploitation / implant traffic Source: [NCSC published rules](https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jaguar-Tooth-snort.txt), [A48](../References.md#a48) Publication / revision: 2023-04-18 Notes: Sensor placement matters; Suricata compatibility not asserted

**AUTHENTIC ANTICS / Jaguar Tooth signatures.** Type: YARA Coverage: NCSC malware analysis artifacts Source: [A49](../References.md#a49) Publication / revision: Catalog reviewed 2026-09-14 Notes: Linked originals; downloads not locally compiled

## Additional Telemetry Opportunities

These hypotheses summarize investigations and recommendations in the cited publications. They are not newly invented rule bodies.

| Opportunity | Evidence | Collection and decision |
|---|---|---|
| Detect router DNS changes and selective redirection | [A32](../References.md#a32), [A33](../References.md#a33) | Router configuration history, resolver responses, TLS warnings, identity logs. Compare approved resolvers; correlate targeted Microsoft authentication traffic with token misuse |
| Identify exploitation of Outlook NTLM handling | [A16](../References.md#a16) | Email properties, outbound SMB/NTLM, Windows authentication events. Investigate unexpected external authentication; distinguish scanners and sanctioned test accounts |
| Find Outlook macro persistence | [A25](../References.md#a25), [A50](../References.md#a50) | File creation, registry writes, Outlook process ancestry, mail audit. Validate macro owner, signing and management policy before containment |
| Investigate GooseEgg escalation | [A17](../References.md#a17) | Driver-store changes, COM registration, scheduled tasks, process hashes. Correlate artifacts on one host; approved printer servicing can match |
| Detect cloud-backed implants | [A28](../References.md#a28) | Endpoint process-to-network mapping, proxy and cloud access logs. Investigate unapproved account / app / process relationships; do not block a whole cloud provider from a domain match |
| Examine lateral access through nearby Wi-Fi | [A18](../References.md#a18) | Wireless-controller authentication, endpoint adapter history, VPN and identity records. Trace account and endpoint provenance across organizations; ordinary roaming is not malicious |
| Identify logistics reconnaissance and theft | [A21](../References.md#a21) | Mailbox access, remote service logons, archive creation and transfer records. Correlate source-linked indicators with unusual access to shipment and support information |
| Review OAuth/token theft | [A23](../References.md#a23), [A33](../References.md#a33) | Sign-ins, token use, Outlook module loads and network telemetry. Revoke affected sessions and investigate the endpoint; password change alone may not remove stolen-token access |

Apply vendor patch guidance, phishing-resistant MFA, restricted external SMB, router management isolation and centralized logging according to the cited advisories. Prioritize identity and edge-device evidence alongside endpoint collection. Validation here cannot establish recall against live campaigns or replace deployment testing.
