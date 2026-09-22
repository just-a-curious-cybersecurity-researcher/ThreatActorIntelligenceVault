# INC Ransom — Vulnerabilities

**Presentation reviewed:** 2026-09-22.

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2023-3519 | Citrix NetScaler ADC/Gateway | Public-facing exploitation associated with INC in collected reporting | Historical association repeated by Acronis/Picus | Moderate; report-level association |
| CVE-2023-4966 | Citrix NetScaler ADC/Gateway | Possible initial access in a GOLD IONIC incident | Secureworks 2024 incident response | Moderate; original report says “may” |
| CVE-2023-48788 | Fortinet FortiClient EMS | Initial-access association in later reporting | Acronis 2026 | Moderate; do not infer exploitation in every case |
| CVE-2024-57727 | SimpleHelp | Remote-management initial-access association | Acronis 2026 | Moderate; report-level association |
| CVE-2025-5777 | Citrix NetScaler ADC/Gateway | Later edge-access association | Acronis 2026 | Moderate; separate from CVE-2023-4966 |

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| CVE-2023-35082 labeled SimpleHelp | Product mismatch: this identifier concerns Ivanti EPMM; excluded from the supported INC exploit list |
| CVE-2024-4885 | Concerns Progress WhatsUp Gold; supplied mention alone does not establish an INC incident |
| CVE-2026-15409 / CVE-2026-15410 | SonicWall SMA1000 leads retained for review; mass-exploitation reporting and a ransomware claim do not by themselves prove that INC operated the full exploit campaign |
| Vulnerable driver filenames | Kept as artifacts; no CVE assigned from a filename alone |

## Operational Interpretation

Prioritize actual exposed product/version combinations and evidence of access. A vendor patch confirms remediation for a vulnerability; it does not establish attribution. Appliance compromise can also predate payload deployment.

Preserve authentication, configuration and management logs before rebuilding affected edge systems. The supported table describes association strength, not an exploit recipe or an assertion that every listed vulnerability occurred in one chain.
