# Akira — Intelligence Overview

**Presentation reviewed:** 2026-09-15.

## Background

Akira emerged around March-April 2023 as a financially motivated ransomware operation. The collected reporting describes the group as operating under a **Ransomware-as-a-Service (RaaS)** model, while also characterizing the ecosystem as relatively closed compared with highly open affiliate programs.

CrowdStrike tracks the threat actor as **PUNK SPIDER**.

Initial activity primarily affected Windows environments. During 2023 the operation expanded into Linux targeting. **Megazord is a Windows encryptor**; co-deployment with the Linux/ESXi Akira_v2 variant demonstrates an operation spanning platforms, not a cross-platform Megazord binary.

## Targeting and Victimology

The collected reporting identifies significant activity in the **United States, Canada, Germany and Italy**, with broader targeting across North America, Europe and other regions including Australia.

Frequently affected sectors include:

- industrial and manufacturing organizations;
- professional services;
- technology;
- education;
- finance;
- critical infrastructure.

The overall victimology is consistent with a financially motivated ransomware operation seeking organizations where access to enterprise infrastructure, sensitive information or business-critical systems can support high-value extortion.

## Operational Model

Akira combines data theft with ransomware deployment. A typical reported intrusion may involve:

1. gaining access through valid credentials, remote services, phishing or exploitation of public-facing infrastructure;
2. harvesting additional credentials;
3. mapping the victim's network and Active Directory environment;
4. expanding privileges and moving laterally;
5. weakening EDR, antivirus, firewalls or recovery mechanisms;
6. establishing remote access and/or tunneling;
7. collecting and exfiltrating sensitive data;
8. deploying ransomware across accessible Windows or Linux systems;
9. demanding payment in exchange for decryption and/or non-publication of stolen information.

Akira has also reportedly conducted **extortion without encryption**, using exfiltrated information as leverage when encryption is unnecessary or unsuccessful.

## Ransomware Development

Early Akira variants were written in **C++** and commonly appended the `.akira` extension to encrypted files. Later variants such as **Megazord** used **Rust** and have been associated with the `.powerranges` extension.

Collected technical notes describe similarities between the ransomware structure and **Conti v2**, including use of ChaCha-family encryption and comparable implementation choices. The cipher must be tied to the build: Talos describes ChaCha8 in renewed C++ samples in September 2024, while earlier samples use other ChaCha-family implementations with RSA protection.

Akira ransomware also attempts to hinder recovery, including by targeting filesystem snapshots and deleting Windows Volume Shadow Copies.

## Data Leak Site

Akira operates Tor-based leak infrastructure. The collected notes indicate that its data leak site has used **magnet links** rather than directly hosting all stolen data, requiring torrent-compatible software to retrieve published material.

## Current Evolution in the Collected Research

Recent material in the dossier includes:

- continued targeting of SonicWall SSL-VPN environments;
- reuse of previously stolen credentials and possible exploitation of configuration weaknesses even where devices have been patched;
- an observed affiliate attempt to reboot a compromised host into **Safe Mode with Networking** to disable EDR and Defender protections;
- **GLIMPS reports** ClickFix followed by SectopRAT, but supplies no incident timeline or primary citation: **Low Confidence** in generalizing this as an established Akira initial-access chain.

## Intelligence Gaps

The collected research does not conclusively establish:

- the exact organizational structure of Akira administrators and affiliates;
- the identity or location of core operators;
- the degree of direct organizational continuity with Conti;
- the proportion of incidents attributable to each initial-access vector;
- whether all blockchain laundering infrastructure is directly controlled by Akira or partly supplied by external laundering services;
- the full set of currently active infrastructure used by individual affiliates.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| March–June 2023 | March emergence; Avast publicly analyzed a Linux sample in June. CISA describes Linux deployment in April. These refer to different visibility points, not a resolved exact release date. The unrelated 2017 “Akira” is excluded. |
| August 2023–March 2024 | Rust Megazord and later Akira_v2 appear. Co-deployment is documented by Talos. |
| September 2024 | Talos observed renewed C++ Windows/Linux payloads and ChaCha8. A linear “C++ permanently replaced by Rust” history is inaccurate. |
| June 2025 | CISA reports Nutanix AHV disk encryption, broadening the hypervisor scope; it does not establish exploitation of an AHV vulnerability. |
| July–September 2025 | Arctic Wolf observed rapid SonicWall-related intrusions, including cases under an hour. Credential acquisition and reuse may be separated in time. |
| August 2026 publication | Huntress documented an unsuccessful Safe Mode encryption attempt after successful data theft. One failed payload does not imply reduced extortion capability. |

**Assessment — High Confidence:** prioritize identity, backup and virtualization control planes alongside endpoint protection. Their compromise can expose many workloads without installing an encryptor on each guest.

Victim lists overrepresent disclosed and non-paying organizations. Early Arctic Wolf reporting included approximately 80% SMBs in a 63-victim sample; that is historical evidence against a large-enterprise-only model, not a current size distribution. Manufacturing and service businesses recur across independent IR and leak-site analyses.

TRM's approximately 980 posts for part of 2025, GLIMPS's more than 500 organizations, and other vendors' totals cannot be reconciled without underlying records. They may reflect different capture, deduplication or date rules. Do not present any as an independently verified global incident census.

## Law-Enforcement Development

The May 2026 Zolotarjovs sentencing adds official evidence concerning historical Conti-linked organizational use of the Akira brand. See [attribution](attribution.md#official-organizational-evidence-and-limits) for the exact period and limits; this is not evidence of a complete Akira takedown.
