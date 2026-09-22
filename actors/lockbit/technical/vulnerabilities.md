# LockBit — Vulnerabilities

**Presentation reviewed:** 2026-09-21.

Vulnerabilities belong to dated affiliate access or escalation procedures. They are not features of the encryption algorithm, and the version of a recovered payload does not prove which vulnerability was used.

## Supported Associations

| CVE | Vendor / product / component | Observed or reported context and stage | Period / evidence | Confidence |
|---|---|---|---|---|
| CVE-2018-13379 | Fortinet FortiOS SSL VPN | File-disclosure vulnerability associated with affiliate access | AA23-165A, 2023-06 | High in advisory association; incident confirmation required |
| CVE-2019-0708 | Microsoft Remote Desktop Services | Remote-service exploitation listed for affiliates | AA23-165A, 2023-06 | High in published association |
| CVE-2020-1472 | Microsoft Netlogon | Privilege escalation after network access; not a generic internet-facing login vector | AA23-165A, 2023-06 | High in published association |
| CVE-2021-22986 | F5 BIG-IP / BIG-IQ iControl REST | Public-facing management interface exploitation | AA23-165A, 2023-06 | Advisory cites secondary reporting for this association |
| CVE-2021-44228 | Apache Log4j2 | Application exploitation associated with affiliate intrusions | AA23-165A, 2023-06 | High in advisory association; not proof for every LockBit case |
| CVE-2023-0669 | Fortra GoAnywhere MFT | Reported affiliate access association | AA23-165A explicitly references secondary sources | Moderate; distinguish service membership from payload family |
| CVE-2023-27350 | PaperCut MF/NG | Reported exploitation followed by ransomware activity | AA23-165A secondary-source context | Moderate; leaked-builder use complicates organizational attribution |
| CVE-2023-4966 | Citrix NetScaler ADC / Gateway | Session-material disclosure and authenticated-session reuse | AA23-325A, 2023-11-21, incident artifacts | High in the documented affiliate campaign |

## Qualified and Disputed Entries

| Entry | Disposition |
|---|---|
| CVE-2023-46604 — Apache ActiveMQ | The DFIR Report documents exploitation in a February 2024 intrusion, published 2026-02-23, followed by Black-family ransomware. Researchers assess independent use of the leaked builder; this supports a family-level incident association, not confirmed membership of the LockBit service |
| CVE-2023-3824 as the Cronos entry vector | The supplied notes rely on secondary explanations of law-enforcement access. Not presented as a confirmed LockBit affiliate exploit or verified Cronos mechanism |
| ScreenConnect CVE-2024-1708 / CVE-2024-1709 | Tool use and vulnerable-product presence do not independently prove exploitation in a particular 4.0 campaign; not added to the confirmed table |
| Unresolved FortiGuard CVE list in supplied notes | Exact incident provenance was not supplied; excluded from supported associations |
| A vulnerable appliance followed by a 5.0 note | Temporal co-occurrence does not prove the vulnerability was exploited; inspect appliance and identity evidence |

## Operational Interpretation

Prioritize exposed appliances and remote access, but retain the distinction between patching a vulnerability and invalidating already stolen sessions. Citrix campaign response requires reviewing sessions and downstream persistence as well as software remediation.

Use exact firmware/product applicability and vendor remediation guidance at response time. The table is a historical CTI association register, not a live vulnerability-scanning result.
