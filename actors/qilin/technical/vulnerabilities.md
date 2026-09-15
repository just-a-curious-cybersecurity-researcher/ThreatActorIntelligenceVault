# Qilin — Vulnerabilities and Exposed Infrastructure

**Presentation reviewed:** 2026-09-15.

Reviewed **2026-09-11**. Product exposure, valid-account login and a malicious tool's presence do not independently prove exploitation. The confidence below concerns reporting of use in a specified campaign; patch/build details should be obtained from the vendor for the deployed product.

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2024-21762 | FortiOS/FortiProxy SSL-VPN out-of-bounds write | Internet-exposed affected SSL-VPN; remote code execution path | Italian 2026 campaign bulletin; Group-IB broader 2026 review | High Confidence in official campaign reporting; per-victim raw requests not supplied. |
| CVE-2024-55591 | FortiOS/FortiProxy authentication bypass on management interface | Exposed vulnerable administrative interface; unauthorized elevated management access | Same Italian bulletin and Group-IB reporting | High Confidence in reported use. Do **not** describe this as the same SSL-VPN memory-corruption flaw. |
| CVE-2026-1281 | Ivanti Endpoint Manager Mobile code injection | Exposed affected EPMM service; unauthenticated code execution per bulletin | Italian incident analysis published May 2026 | Moderate Confidence in actor-use association: authoritative incident bulletin but no individual exploit traces available here |
| CVE-2026-1340 | Ivanti Endpoint Manager Mobile code injection | Exposed affected EPMM component | Same May 2026 bulletin | Moderate Confidence; do not conflate EPMM with Ivanti Connect Secure |
| CVE-2023-27532 | Veeam Backup & Replication / Cloud Connect credential disclosure | Access to backup service, TCP 9401 by default; commonly post-compromise | `veeam.exe` in January 2025 MSP case and Italian 2026 reporting | High Confidence in reported tool/use. Veeam defines retrieval of **encrypted** stored credentials; extraction/decryption tools can subsequently expose plaintext. |

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| Citrix 2022 | Trend assesses valid-account access to a public-facing server; no exact Citrix CVE proven. |
| VPN July 2024 / Talos 2025 | stolen credentials and missing MFA; timing of leaked credentials does not prove their source or an appliance exploit. |
| ScreenConnect January 2025 | AiTM phishing and MFA relay against the administrator, followed by legitimate service control. No evidence in that case justifies attaching CVE-2024-1709 or another ScreenConnect flaw. |
| Veeam SQL credential query | authenticated database extraction is not automatically CVE-2023-27532 exploitation. |
| BYOVD / driver-based impairment | determine the actual driver and vulnerable operation before assigning a CVE; suspicious `fnarw.sys` use was not confirmed. |
| ESXi/Nutanix | deployment, platform checks, root changes and disabling execution restrictions are not proof of a hypervisor CVE. |
| Adobe Acrobat, October 2024 | Symantec assessed possible exploitation without naming a CVE. |
| SharpZeroLogon / CVE-2020-1472 | Reported tool capability; the public case does not establish the successful exploit transaction. |

## Operational Interpretation

Separate internet-facing management from user VPN services, correlate appliance changes with new authentication sessions, protect backup credentials and retain management-plane logs outside the affected infrastructure. Patch status alone does not invalidate stolen sessions or remove accounts created before remediation. These are defensive implications of the documented chains, not a statement that a query can confirm a particular exploit.
