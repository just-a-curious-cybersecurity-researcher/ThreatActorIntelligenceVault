# Lynx — Vulnerabilities and Exposed Infrastructure

**Presentation reviewed:** 2026-10-07.

## Supported Associations

Microsoft reported Storm-2113 affiliates gaining initial access through exploits, and CERT Polska observed vulnerable unpatched software in a mixed INC/Lynx case population. Neither publication supplied a Lynx-specific CVE-to-incident chain. The supported finding is therefore exploitation of exposed software without an exact public CVE; inventing a product mapping would reduce analytical quality.

Two 2026 Triskele Labs engagements add a configuration-led route: SSL-VPN authentication was bound permissively to LDAP, allowing any domain user to authenticate, and MFA was absent. PacketWatch separately reported VPN password attacks and access to older ESXi hosts exposed through SSH. These findings strengthen the exposed-edge assessment but still do not identify an exact exploited CVE.

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| CVE-2023-3519 / Citrix NetScaler | Documented for INC ransomware reporting; not promoted to Lynx without case-specific evidence. |
| CVE-2024-54085 / AMI MegaRAC | Appears in broad Lynx profiles without a reviewed IR chain tying exploitation to a Lynx deployment. |
| CVE-2024-0769 / D-Link DIR-859 | Generic edge-device association; excluded from supported Lynx findings. |
| CVE-2019-6693 / FortiOS | Generic credential-disclosure association; excluded without victim telemetry. |
| 2026 “FortiBleed” reporting | Secondary reporting alleges harvested FortiGate credentials and INC/Lynx infrastructure links. Treat as a collection lead until primary incident evidence and affected CVEs are available. |
| Valid RDP credentials | Confirmed initial access in the detailed 2025 case; a credential-based entry, not a CVE. |
| SSL-VPN LDAP without MFA | Confirmed in two 2026 IR cases; an authentication/configuration weakness, not a CVE. |
| Older ESXi with exposed SSH | Reported in 2026 Lynx IR preceding `.vmdk` encryption; product exposure without a published exploit chain. |

## Operational Interpretation

Prioritize MFA, exposed-service inventory, patch state and remote-logon anomalies rather than a speculative Lynx CVE list. When a claimed CVE appears, require exploit telemetry, affected version, initial-access chronology and later Lynx sample identity before calling the association confirmed.
