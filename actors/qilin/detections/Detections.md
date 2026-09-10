# Qilin — Detection Engineering

The hunts below are derived from **Qilin-specific source cases**, while recognizing that most behaviors are shared with legitimate administration and other intruders. Detection confidence and actor-attribution confidence are separate.

- [KQL hunts](KQL.md)
- [Splunk hunts](Splunk.md)
- [YARA artifact-triage rules](Qilin-Hunting.yar)
- [ATT&CK evidence mapping](../technical/mitre-attack.md)

## Coverage

| IDs | Investigation question | Primary evidence |
|---|---|---|
| Q01–Q02 | Were malicious logon scripts and credential outputs distributed/staged through SYSVOL? | Sophos July 2024 [Q11](../References.md#q11) |
| Q03–Q04 | Did an attacker enable WDigest retention or orchestrate the credential toolkit? | Talos 2025 [Q15](../References.md#q15) |
| Q05, Q07 | Was a trusted RMM session used to deploy another instance or enumerate the domain? | Sophos MSP [Q22](../References.md#q22), Trend [Q23](../References.md#q23) |
| Q06 | Did Cyberduck contact Backblaze in a relevant case? | Talos transfer history [Q15](../References.md#q15) |
| Q08 | Are sample-associated restoration task/Run commands present? | Talos samples [Q15](../References.md#q15) |
| Q09–Q10 | Were recovery and virtualization controls modified? | Go, MSP and vCenter evidence [Q12](../References.md#q12), [Q22](../References.md#q22), [Q15](../References.md#q15) |
| Q11–Q12 | Were note and worker-log artifacts created? | Note archives / sample evidence [Q31](../References.md#q31), [Q15](../References.md#q15) |
| Q13 | Were reported driver components dropped or loaded? | Talos / Trend [Q15](../References.md#q15), [Q23](../References.md#q23) |
| Q14 | Can telemetry resolve the proposed WSL/RMM execution path? | Hypothesis, not confirmed WSL usage [Q23](../References.md#q23) |

## YARA Scope

YARA scans artifact bytes, not events. The rules recognize note content, scripts or PE configuration clues; they cannot prove execution, credential theft, exfiltration or an operator's identity. Research documents and restored notes can match. No broad tool-name signature is labelled definitive Qilin malware detection. The PE configuration rule is heuristic and requires binary validation before operational use.

## Unimplemented Sensor-Specific Opportunities

1. **AiTM/MSP entry:** correlate identity-provider and ScreenConnect control-plane session creation, phishing-domain navigation and new customer-agent instance identifiers. Endpoint logs alone cannot confirm MFA relay.
2. **VPN compromise:** normalize appliance account/source/result/MFA fields; correlate spray, successful access and privilege changes. No universal VPN sourcetype is assumed.
3. **Domain policy change:** DC Security Event 5136 with object DN/attribute auditing can corroborate changed logon policy. SYSVOL writes alone do not prove policy application.
4. **Central share encryption:** correlate file-server auditing, SMB writer identity, rename/write rate and note creation. A single encryptor can damage many shares; a process-count threshold will miss this path.
5. **Hypervisors:** preserve vCenter tasks, ESXi SSH/syslog, changed root credentials, VM shutdown and datastore writes. Windows PowerShell commands are partial clues, not coverage of direct ESXi execution.
6. **Exfiltration:** combine archive history, Cyberduck/WinSCP session logs, SMTP metadata, proxy bytes and cloud object audit. A connection to a legitimate cloud service is insufficient.

## Validation and Deployment

Rules are UTF-8, source-linked and statically reviewed. YARA is compiled and checked with harmless positive/negative fixtures; these tests do not estimate malware recall or field false-positive rates. KQL/SPL require execution against the deployment's schemas, representative benign periods and approved simulations before promotion to alerts. [Validation report](../../../VALIDATION.md).

Technical references: [MDE process schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [MDE registry schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table), [Sysmon event definitions](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows).
