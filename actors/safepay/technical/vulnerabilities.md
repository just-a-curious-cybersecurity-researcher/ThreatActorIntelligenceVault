# SafePay — Vulnerability Associations

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| No CVE assigned | Fortinet FortiGate VPN policy | Local-account authentication bypassed the MFA policy intended for LDAP groups; weak credentials then enabled access | NCC IR, published 2026 | High; configuration failure, not a software vulnerability |
| No CVE identified | Fortinet FortiGate SSL VPN / administrative-account configuration | Sygnia observed a weak, non-MFA, VPN-enabled, domain-enabled administrative account and described a firewall flaw/misconfiguration | Sygnia IR, 2025 incident / 2026 publication | High for the access condition; no basis for a named CVE |
| CVE-2024-21762 | Fortinet FortiOS/FortiProxy SSL-VPN | Listed by Halcyon and FortiGuard as a SafePay access association | Vendor actor profiles | Moderate-low; no reviewed case artifacts |
| CVE-2023-27997 | Fortinet FortiOS/FortiProxy SSL-VPN | Listed by Halcyon in SafePay initial-access context | Halcyon profile | Moderate-low; no reviewed case artifacts |

These are the only SafePay-specific associations found outside FortiGuard’s broad catalog. The NCC and Sygnia routes must not be rewritten as exploitation of either Fortinet CVE. Both demonstrate that a patched appliance can still expose the environment through weak credentials, policy scope or account design.

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| CVE-2025-53770, CVE-2025-53771 — Microsoft SharePoint Server | FortiGuard catalog association; no reviewed SafePay IR chain established |
| CVE-2025-31161 — CrushFTP | FortiGuard catalog association; no reviewed SafePay IR chain established |
| CVE-2025-31324 — SAP NetWeaver Visual Composer | FortiGuard catalog association; no reviewed SafePay IR chain established |
| CVE-2025-61882 — Oracle E-Business Suite | FortiGuard catalog association; no reviewed SafePay IR chain established |
| CVE-2025-8088 — WinRAR | FortiGuard catalog association. SafePay uses WinRAR legitimately as a utility, but that does not prove exploitation of this flaw |
| CVE-2024-40766 — SonicWall SonicOS | FortiGuard catalog association; ransomware use exists broadly, but no reviewed SafePay case established |
| CVE-2024-37085 — VMware ESXi | FortiGuard catalog association; no SafePay-native ESXi sample or incident-level exploit evidence located |
| CVE-2024-3400 — Palo Alto PAN-OS GlobalProtect | FortiGuard catalog association. Public Ingram reporting mentioned GlobalProtect access, but the victim did not confirm this CVE |
| CVE-2024-55591 — Fortinet FortiOS/FortiProxy | FortiGuard catalog association; no reviewed SafePay IR chain established |
| CVE-2023-4966 — Citrix NetScaler (“CitrixBleed”) | FortiGuard catalog association; no reviewed SafePay IR chain established |
| CVE-2021-40539 — Zoho ManageEngine ADSelfService Plus | FortiGuard catalog association; no reviewed SafePay IR chain established |
| CVE-2021-27877, CVE-2021-27878 — Veritas Backup Exec Agent | FortiGuard catalog association; relevant to backup exposure but no reviewed SafePay IR chain established |
| CVE-2019-6693 — Fortinet configuration password protection | FortiGuard catalog association; no reviewed SafePay IR chain established |

FortiGuard also lists its actor card as RaaS while its narrative describes a closed group. The same aggregation caution applies to the CVE buttons: they are collection leads, not a victim-by-victim exploit record.

## Operational Interpretation

Patch internet-facing VPN, firewall, file-transfer, SharePoint, SAP and remote-management products according to vendor guidance, but investigate identity and configuration paths at equal priority. For SafePay, the strongest cases began with a valid account, password spraying or an MFA policy gap.

After any edge remediation, revoke sessions, rotate local and domain credentials, verify MFA policy scope, inspect RDP/SMB activity, review new RMM services, and hunt for share discovery and recovery-inhibition events. Patching alone does not remove QDoor, ScreenConnect or stolen administrative credentials.
