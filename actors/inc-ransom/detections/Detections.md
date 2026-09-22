# INC Ransom — Detection Opportunities

**Presentation reviewed:** 2026-09-22.

## Content

- [KQL](KQL.md): 30 copyable Microsoft Defender XDR hunts.
- [Splunk](Splunk.md): 30 paired searches with collection assumptions.
- [YARA](INC-Hunting.yar): five local artifact rules.
- [ATT&CK mapping](../technical/mitre-attack.md) and [source/provenance register](../References.md).

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 3 | 3 | Required telemetry and local baselines stated per entry |
| 2. Active Directory and Network Discovery | 3 | 3 | Required telemetry and local baselines stated per entry |
| 3. Persistence and Remote Administration | 4 | 4 | Required telemetry and local baselines stated per entry |
| 4. Tunneling and C2 | 2 | 2 | Required telemetry and local baselines stated per entry |
| 5. Defense Evasion and Impairment | 3 | 3 | Required telemetry and local baselines stated per entry |
| 6. Collection and Exfiltration | 4 | 4 | Required telemetry and local baselines stated per entry |
| 7. Recovery Inhibition | 2 | 2 | Required telemetry and local baselines stated per entry |
| 8. Deployment and Impact | 4 | 4 | Required telemetry and local baselines stated per entry |
| 9. Multi-Stage Correlation | 1 | 1 | Required telemetry and local baselines stated per entry |
| 10. Campaign Artifact Hunts | 4 | 4 | Required telemetry and local baselines stated per entry |

## Query Organization

The files share I01–I30 and the repository's numbered families. Queries cover credentials, discovery, RMM, network pivots, impairment, exfiltration, recovery changes, impact and incident artifacts.

The index contains coverage rather than duplicated query code. Each query has origin, telemetry and tuning fields. Generic behavioral hunts and exact artifact matches are labeled separately.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| INC_Classic_Windows_Hunt | Local string/PE hunt | Classic command-line and branding/PDB conjunction | Related families can share strings |
| INC_Rust_Windows_Hunt | Local string/PE hunt | Rust, note and crypto labels | Does not prove exact cryptographic wiring; sample validation needed |
| INC_Rust_Linux_Hunt | Local string/ELF hunt | Note branding and ESXi operation strings | Does not cover every historical Linux build |
| INC_Ransom_Note_Hunt | Local artifact hunt | Note text with INC and negotiation markers | Research copies and embedded text can match |
| INC_Published_Encryptor_SHA256 | Local exact-hash rule | Published Windows/Linux artifacts | No auxiliary-tool hashes; newly built samples will not match |

## Review Notes

No rule is described as vendor-authored. Published Acronis/Google rule locations and Huntress's Sigma discussion are retained in References for provenance and comparison. Local implementations here use their own conditions.

Syntax and harmless fixtures can test implementation consistency, not production sensitivity. No malware was executed and no live KQL/SPL backend was available. Driver files do not prove driver loading; note creation does not prove encryption; client execution does not prove exfiltration.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| Backup credential access | PowerShell 4104 and database audits; process text alone misses encoded/file-based scripts |
| Security changes | Defender Operational 5001/5007 and product health events; correlate with the modifying process |
| Driver impairment | Sysmon 6, service installation, signature and product-interruption evidence |
| API-based shadow-copy actions | Endpoint behavioral/storage events; no required vssadmin child process |
| Scheduled-task execution | Task Scheduler Operational and Security task events, including short-lived RPC-created tasks |
| ESXi impact | hostd/shell management logs, VM state and datastore changes; map to local ingestion |
| Financial linkage | Authorized negotiation records plus complete transaction identifiers, not guessed wallet clusters |
