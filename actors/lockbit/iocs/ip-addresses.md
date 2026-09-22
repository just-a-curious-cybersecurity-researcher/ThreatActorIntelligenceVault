# LockBit — IP Addresses

**Presentation reviewed:** 2026-09-17.

Historical observations are retained with their published role. No live probing was performed. Article dates are publication context, not invented first_seen/last_seen values.

## Campaign Infrastructure

| Indicator | Role and context | Observation | Confidence / use |
|---|---|---|---|
| 81.19.135[.]219 | HTA delivery in the Citrix campaign | 2023-11-21 CISA publication | High in historical campaign context |
| 81.19.135[.]220 | Outbound destination in the Citrix campaign | 2023-11-21 CISA publication | Historical observation; revalidate ownership |
| 81.19.135[.]226 | Outbound destination in the Citrix campaign | 2023-11-21 CISA publication | Historical observation; revalidate ownership |
| 193.201.9[.]224 | FTP traffic from a compromised system | 2023-11-21 CISA publication | High in historical case context |
| 62.233.50[.]25 | Campaign HTTP endpoints | 2023-11-21 CISA publication | High in historical case context |
| 168.100.9[.]137 | SSH port-forwarding infrastructure | 2023-11-21 CISA publication | Case-specific tunnel endpoint |
| 206.188.197[.]22 | PowerShell reverse-shell destination | 2023-11-21 CISA publication | Case-specific connection |
| 141.98.9[.]137 | Remote IP associated with Citrix Bleed | 2023-11-21 CISA publication | Association, not proof of current control |
| 205.185.116[.]233 | Reported exposed server; SmokeLoader infrastructure overlap | 2025 Acronis investigation | Overlap only; not a universal 5.0 C2 or proof of a shared operator |

Shared hosting and legitimate RMM delivery addresses in the source advisory are not promoted to actor-owned infrastructure. Revalidate tenant and time before using an old IP as a blocking indicator.

