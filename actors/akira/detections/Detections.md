# Akira — Detections

This directory contains defensive detection and threat-hunting content based on Akira-associated tradecraft documented in this repository.

> **Important:** these queries and rules are starting points and must be reviewed and tuned for each environment before production use. Akira frequently abuses legitimate administration, RMM, tunneling, backup, compression and security tools, so expected software, service accounts, jump hosts, red-team activity and normal administrative workflows must be baselined to avoid false positives.

## Content

- [KQL](KQL.md) — Microsoft Defender XDR / Advanced Hunting queries.
- [Splunk](Splunk.md) — Windows/Sysmon-oriented hunting searches; indexes and field names may require adaptation.
- [YARA](Akira-Hunting.yar) — file, script and artifact triage rules. YARA is not intended to replace event-level behavioral detection.

Detection should prioritize **behavioral correlation** over individual tool names. The strongest signals generally come from combinations such as suspicious remote access → credential access → AD/network discovery → lateral movement → defense impairment → exfiltration → recovery inhibition → ransomware deployment.

## September 2026 Review

The original KQL, Splunk and YARA collection is retained and refined. MiniDump queries accept numeric PIDs, SSH forwarding respects option case, canonical and variant note names are covered, and the YARA multi-family rule now actually requires different string families. New hunts cover AnyDesk SafeBoot registration, S3 transfer, AD exports, WinRM, Veeam credentials, ESX Admins changes and driver/service co-occurrence.

Each query file has a coverage/tuning register and campaign-specific review notes. Generic existing tool-name hunts remain broad ransomware investigation leads. None is an Akira attribution rule. YARA scans bytes in artifacts; it cannot observe a reboot, execution sequence or exfiltration. Research documents containing the same strings can match it.

## Additional Telemetry Opportunities

| Opportunity | Evidence | Collection and decision |
|---|---|---|
| VPN spray then successful session | Huntress [A11](../References.md#a11) | Normalize vendor username, source IP, authentication result and MFA state; count distinct targets before success. Exclude health checks and mistyped saved credentials. No universal VPN field schema is assumed. |
| Certificate request, PKINIT, U2U and WinRM | Darktrace [A10](../References.md#a10) | Correlate CA request/issuance audits, DC Kerberos logs and network RPC/WinRM telemetry. This supports a credential-abuse investigation; U2U alone is not UnPAC proof. |
| Offline DC disk mounting | [A01](../References.md#a01) | Hypervisor datastore/mount events plus NTDS and SYSTEM access; endpoint-only detection may miss the operation. Authorized recovery is an alternative. |
| ESXi/AHV disruption | [A01](../References.md#a01), [A04](../References.md#a04) | Preserve remote hypervisor audit/syslog and backup logs; mass VM shutdown, disk writes and identity changes. A Windows query cannot claim hypervisor coverage. |

See [validation](../../../VALIDATION.md) for compiled YARA checks and the limits of static query review.
