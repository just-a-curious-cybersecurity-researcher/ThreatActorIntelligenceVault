# Qilin — Exploited Vulnerabilities and Access Conditions

Reviewed **2026-09-10**. Product exposure, valid-account login and a malicious tool's presence do not independently prove exploitation. The confidence below concerns reporting of use in a specified campaign; patch/build details should be obtained from the vendor for the deployed product.

| CVE | Product / vulnerability | Stage and prerequisites | Actor-use evidence | Confidence / limitation |
|---|---|---|---|---|
| CVE-2024-21762 | FortiOS/FortiProxy SSL-VPN out-of-bounds write | Internet-exposed affected SSL-VPN; remote code execution path | Italian 2026 campaign bulletin; Group-IB broader 2026 review [Q30](../References.md#q30), [Q17](../References.md#q17) | High Confidence in official campaign reporting; per-victim raw requests not supplied. [Vendor Q34](../References.md#q34) |
| CVE-2024-55591 | FortiOS/FortiProxy authentication bypass on management interface | Exposed vulnerable administrative interface; unauthorized elevated management access | Same Italian bulletin and Group-IB reporting [Q30](../References.md#q30), [Q17](../References.md#q17) | High Confidence in reported use. Do **not** describe this as the same SSL-VPN memory-corruption flaw. [Vendor Q33](../References.md#q33) |
| CVE-2026-1281 | Ivanti Endpoint Manager Mobile code injection | Exposed affected EPMM service; unauthenticated code execution per bulletin | Italian incident analysis published May 2026 [Q30](../References.md#q30) | Moderate Confidence in actor-use association: authoritative incident bulletin but no individual exploit traces available here |
| CVE-2026-1340 | Ivanti Endpoint Manager Mobile code injection | Exposed affected EPMM component | Same May 2026 bulletin [Q30](../References.md#q30) | Moderate Confidence; do not conflate EPMM with Ivanti Connect Secure |
| CVE-2023-27532 | Veeam Backup & Replication / Cloud Connect credential disclosure | Access to backup service, TCP 9401 by default; commonly post-compromise | `veeam.exe` in January 2025 MSP case and Italian 2026 reporting [Q22](../References.md#q22), [Q30](../References.md#q30) | High Confidence in reported tool/use. Veeam defines retrieval of **encrypted** stored credentials; extraction/decryption tools can subsequently expose plaintext. [Q32](../References.md#q32) |

## Access Paths That Must Not Become Invented CVEs

- **Citrix 2022:** Trend assesses valid-account access to a public-facing server; no exact Citrix CVE proven. [Q12](../References.md#q12)
- **VPN July 2024 / Talos 2025:** stolen credentials and missing MFA; timing of leaked credentials does not prove their source or an appliance exploit. [Q11](../References.md#q11), [Q15](../References.md#q15)
- **ScreenConnect January 2025:** AiTM phishing and MFA relay against the administrator, followed by legitimate service control. No evidence in that case justifies attaching CVE-2024-1709 or another ScreenConnect flaw. [Q22](../References.md#q22)
- **Veeam SQL credential query:** authenticated database extraction is not automatically CVE-2023-27532 exploitation. [Q23](../References.md#q23)
- **BYOVD / driver-based impairment:** determine the actual driver and vulnerable operation before assigning a CVE; suspicious `fnarw.sys` use was not confirmed. [Q23](../References.md#q23)
- **ESXi/Nutanix:** deployment, platform checks, root changes and disabling execution restrictions are not proof of a hypervisor CVE. [Q15](../References.md#q15), [Q23](../References.md#q23)

## Defensive Priorities

Separate internet-facing management from user VPN services, correlate appliance changes with new authentication sessions, protect backup credentials and retain management-plane logs outside the affected infrastructure. Patch status alone does not invalidate stolen sessions or remove accounts created before remediation. These are defensive implications of the documented chains, not a statement that a query can confirm a particular exploit.
