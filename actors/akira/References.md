# Akira — References

**Presentation reviewed:** 2026-09-15.

Sources support specific statements, not every claim made by the same publisher. Review date: **2026-09-10**. Publication and observation dates are kept separate. Original vendor-only references have been resolved below.

## Source Register

### A01

**FBI / CISA and partners — AA24-109A** — 2024-04-18; revised 2025-11-13.
[FBI / CISA and partners — AA24-109A](https://www.dc3.mil/Portals/100/Documents/DC3/DC3_Home/aa24-109a-stopransomware-akira-ransomware_3.pdf)
31-page revision, read through official DC3 mirror; CISA endpoint blocked. Distinguish French Office Anti-Cybercriminalite (OFAC), a co-author, from US Treasury OFAC.

### A02

**TRM Labs — Akira profile** — 2026-03-20.
[TRM Labs — Akira profile](https://www.trmlabs.com/resources/intel-library/akira)
Four laundering phases; provider assessments, not independently reproduced transaction graphs.

### A03

**Cisco Talos — Akira ransomware continues to evolve** — 2024-10-21.
[Cisco Talos — Akira ransomware continues to evolve](https://blog.talosintelligence.com/akira-ransomware-continues-to-evolve/)
IR and binary analysis. CVE-2023-20263 product mismatch is retained as a source conflict.

### A04

**Microsoft — ESXi hypervisor exploitation** — 2024-07-29.
[Microsoft — ESXi hypervisor exploitation](https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/)
Post-compromise ESX Admins abuse; multiple deployment clusters, not aliases for one organization.

### A05

**Sophos — VEEAM exploit and Frag** — 2024-11-07.
[Sophos — VEEAM exploit and Frag](https://www.sophos.com/en-us/blog/veeam-exploit-seen-used-again-with-a-new-ransomware-frag)
STAC5881 activity cluster spans different payload brands; browser text consulted after direct-fetch timeout.

### A06

**Arctic Wolf — Fog and Akira / SonicWall** — 2024-10-24.
[Arctic Wolf — Fog and Akira / SonicWall](https://arcticwolf.com/resources/blog-uk/arctic-wolf-labs-observes-increased-fog-akira-ransomware-activity-linked-to-sonicwall-ssl-vpn/)
Direct incident reporting explicitly does not prove CVE exploitation in each case.

### A07

**Check Point — Akira overview** — Undated; reviewed 2026-09-10.
[Check Point — Akira overview](https://www.checkpoint.com/es/cyber-hub/threat-prevention/ransomware/akira-ransomware/)
General overview. Uncorroborated claim of typical demands in hundreds of millions is not adopted.

### A08

**GLIMPS — Akira identity sheet** — Undated PDF; URL path 2026/07.
[GLIMPS — Akira identity sheet](https://www.glimps.re/wp-content/uploads/2026/07/fiche-didentite-AKIRA-EN.pdf)
Two-page document retrieved directly. Statistics lack consistent denominators; ClickFix/SectopRAT lead remains single-source.

### A09

**Ransomware.live — Akira** — Dynamic; reviewed 2026-09-10.
[Ransomware.live — Akira](https://www.ransomware.live/group/akira)
Full HTML retrieved after browser failure; leak claims and artifacts, not confirmed unique incidents.

### A10

**Darktrace — Inside Akira’s SonicWall campaign** — 2025-10-09; incident 2025-08-20.
[Darktrace — Inside Akira’s SonicWall campaign](https://www.darktrace.com/es/blog/inside-akiras-sonicwall-campaign-darktraces-detection-and-response)
Network evidence including certificate/Kerberos sequence, WinRM and exfiltration. Actor linkage is an assessment.

### A11

**Huntress — Akira hits Safe Mode** — 2026-08-12.
[Huntress — Akira hits Safe Mode](https://www.huntress.com/blog/akira-hits-safe-mode-ransomware-rebooting-around-edr)
IR reconstruction; S3 transfer, SafeBoot service registration and failed encryption. Publication date is not incident first-seen.

### A12

**Stairwell — Pulling on the chains of ransomware** — 2023-08-23; data recovered June 2023.
[Stairwell — Pulling on the chains of ransomware](https://stairwell.com/blog/akira-pulling-on-the-chains-of-ransomware/)
Resolved original vendor-only reference. Observed Fortinet scripts; reconftw use appeared limited to testing.

### A13

**Qualys — Akira analysis** — Page displays 2025-05-06; URL dated 2024-10-02.
[Qualys — Akira analysis](https://blog.qualys.com/vulnerabilities-threat-research/2024/10/02/threat-brief-understanding-akira-ransomware)
Resolved original vendor-only reference; overview-level CVE claims need incident evidence.

### A14

**RansomLook — Akira cryptocurrency observations** — Dynamic; reviewed 2026-09-10.
[RansomLook — Akira cryptocurrency observations](https://www.ransomlook.io/crypto/akira)
15 Bitcoin addresses; underlying source ransomwhe.re. Mirroring is not independent corroboration.

### A15

**KELA — Akira and Black Basta negotiations** — 2024-03-18; sampled negotiations from 2023.
[KELA — Akira and Black Basta negotiations](https://www.kelacyber.com/wp-content/uploads/2024/03/A-deep-dive-into-Akira-and-Black-Basta-negotiations-.pdf)
26 PDF pages; Akira material pp. 8–16 and appendix p. 26. One 64-hex entry is not a Bitcoin address.

### A16

**Avast / Gen — Decrypted: Akira ransomware** — 2023-06-29.
[Avast / Gen — Decrypted: Akira ransomware](https://www.gendigital.com/blog/insights/research/decrypted-akira-ransomware)
Early binary analysis, note screenshot, sample hashes and version-limited decryptor.

### A17

**Arctic Wolf — Conti and Akira: Chained Together** — 2023-07-26.
[Arctic Wolf — Conti and Akira: Chained Together](https://arcticwolf.com/resources/blog-uk/conti-akira-chained-together/)
Financial evidence and explicit vendor attribution; figures are historical.

### A18

**Arctic Wolf — September campaign update** — 2025-09-26.
[Arctic Wolf — September campaign update](https://arcticwolf.com/resources/blog/september-2025-update-ongoing-akira-ransomware-campaign/)
Rapid intrusions and stolen-credential hypothesis; no proven MySonicWall-backup connection.

### A19

**Cisco Talos — Q1 2024 IR trends** — 2024-04-25.
[Cisco Talos — Q1 2024 IR trends](https://blog.talosintelligence.com/talos-ir-quarterly-trends-q1-2024/)
Observed Megazord + Akira_v2 deployment; initial access undetermined in that engagement.

### A20

**CrowdStrike — PUNK SPIDER** — Undated; reviewed 2026-09-10.
[CrowdStrike — PUNK SPIDER](https://www.crowdstrike.com/en-us/adversaries/punk-spider/)
Public profile excerpt and community identifiers only; full profile not publicly available.

### A21

**Unit 42 — Howling Scorpius threat assessment** — 2024-12-02.
[Unit 42 — Howling Scorpius threat assessment](https://unit42.paloaltonetworks.com/threat-assessment-howling-scorpius-akira-ransomware/)
Variant-specific notes, VM abuse and hashes; some observations explicitly cite other researchers.

### A22

**SentinelOne — Megazord anthology** — 2023-09-20; updated 2025-09-17.
[SentinelOne — Megazord anthology](https://www.sentinelone.com/anthology/megazord/)
Alternative Tox/Telegram notes; do not collapse all samples into one operator.

### A23

**Cisco PSIRT — HyperFlex open redirect** — 2023-09-06.
[Cisco PSIRT — HyperFlex open redirect](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hyperflex-redirect-UxLgqdUF)
Authoritative product definition for CVE-2023-20263; excludes presumed ASA/FTD RCE mapping.

### F03

**TRM Labs — AudiA6 laundering pipeline** — 2026-06-11.
[TRM Labs — AudiA6 laundering pipeline](https://www.trmlabs.com/resources/blog/international-operation-dismantles-eur-336-million-ransomware-laundering-pipeline-audia6)
Provider-estimated actor flows; not publicly reproducible address-level tracing.

### F04

**Europol — AudiA6 disruption** — 2026-06-11.
[Europol — AudiA6 disruption](https://www.europol.europa.eu/media-press/newsroom/news/ransomware-gangs-cut-eur-336-million-audia6-crypto-laundering-pipeline)
Official operation against a service; direct download returned challenge, browser article consulted.

### F05

**US OFAC — Tornado Cash designation removal** — 2025-03-21.
[US OFAC — Tornado Cash designation removal](https://ofac.treasury.gov/recent-actions/20250321)
Official removal including listed addresses; no automatic Akira address attribution.

### F06

**US Treasury — Tornado Cash delisting** — 2025-03-21.
[US Treasury — Tornado Cash delisting](https://home.treasury.gov/news/press-releases/sb0057)
Regulatory status must be dated; historical designation is not current status.

### F07

**US Treasury — Ransomware infrastructure providers** — 2026-07-13.
[US Treasury — Ransomware infrastructure providers](https://home.treasury.gov/news/press-releases/sb0559)
FirstVPN/cryptor action, not an Akira treasury designation.

### F08

**US OFAC — Sanctions List Search** — Dynamic; reviewed 2026-09-10.
[US OFAC — Sanctions List Search](https://ofac.treasury.gov/sanctions-list-search-tool)
Search mechanism and scope. See financial review limitations.

### M01

**MITRE — official ATT&CK STIX data** — Retrieved 2026-09-10.
[MITRE — official ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data)
Live Enterprise snapshot used to resolve names, tactics and revoked techniques.

### M02

**MITRE — Akira S1129** — Live version reviewed 2026-09-10.
[MITRE — Akira S1129](https://attack.mitre.org/software/S1129/)
Software object; not a one-to-one mapping of every affiliate operation.

## Review Coverage

The individual review and disposition of all 15 original entries is recorded in [Source Review](intelligence/source-review.md). For analytical standards see the [repository README](../../README.md).

### A24

**US DOJ — Zolotarjovs sentencing**, 2026-05-04; updated 2026-07-22. [Official release](https://www.justice.gov/opa/pr/member-prolific-russian-ransomware-group-sentenced-prison). Court-derived reporting links several brands, including Akira, to a Conti-leadership organization in a bounded historical period; it does not identify every current Akira affiliate.

### A25

**Chainalysis — 2025 ransomware payment analysis**, 2025-02-05; observations from 2024. [Analysis and financial graph](https://www.chainalysis.com/blog/crypto-crime-ransomware-victim-extortion-2025/). Independent provider supports Akira/Fog cash-out overlap. Its September 2024 wording for Fog emergence is not adopted as the family's first-seen date.

### A26

**Zscaler ThreatLabz — archived Akira notes**, collected versions; reviewed 2026-09-10. [Three text artifacts](https://github.com/ThreatLabz/ransomware_notes/tree/main/akira). Archive suffixes are not necessarily on-disk filenames or chronological variant numbers.

### A01-ORIGINAL

**FBI IC3 — original April 2024 AA24-109A**, [14-page PDF](https://www.ic3.gov/CSA/2024/240418.pdf). Used to verify original hash-table provenance; distinct from November 2025 revision A01.

### D01

**Microsoft Learn — Defender XDR schema**, reviewed 2026-09-10. [Process events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [registry events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table), [identity directory events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table). Sensors and ActionType availability are tenant-dependent.

### D02

**Splunk — streamstats reference**, reviewed 2026-09-10. [Command documentation](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/streamstats). Ordered intervals require sorting, configured memory/window limits and deployment testing.

## Detection Implementation Provenance

The repository-authored defensive hunts translate the procedures documented in this source register into telemetry-based investigation hypotheses. A publisher's reporting supports the procedure; it does not make the repository's query or heuristic a vendor-published rule. Source-specific interpretation is retained in the source review and query notes.
