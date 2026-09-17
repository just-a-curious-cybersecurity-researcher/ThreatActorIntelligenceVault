# The Gentlemen — Source Review

**Presentation reviewed:** 2026-09-17.

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| Microsoft, duplicated URL | Full sample analysis reread: worker flag, target processes/services, file access, footer, .umc16h, independent remote routes and optional wipe. | Encryptor; operations; artifacts; detections |
| ransomware.live | Profile and all three notes read; 85 supplied hashes matched. | IOCs; ransom-note index |
| ESET WeLiveSecurity | Synthesis, regional claims and early chronology. Its June-30 first-listing claim differs from the attachment's July-30 date; neither becomes a confirmed incident date. | Overview; evidence decisions |
| Trend Micro | Original article reread directly: PDC discovery, GPO consoles, internal data directory, WebDAV and NTLM/RDP edits. Entry/exfiltration qualifications retained. | Operations; tools; hunts; hashes |
| SOCRadar profile | Browser text now accessible despite direct 403. Early-2023 origin conflicts with 2025 evidence; the page also has a September-2025 first-seen field. CVE stages reviewed independently. | Source register; overview |
| CUHK | Institutional warning; broad CVE associations qualified. | Vulnerabilities |
| COLCERT | Public PDF text reviewed; TLP and attribution qualifiers retained. | Attribution; advisories |
| FortiGuard | Direct HTML read after browser 403; broad profile inventory. | Vulnerabilities |
| BMSP | Browser text accessible despite direct 406. Its CloudSEK summary says public affiliates are not established, conflicting with primary research. Generic entry claims/community IP not promoted. | Source register |
| Check Point internal chats | Full shared-tool and infrastructure inventory, recruitment, roles, negotiation and reuse of stolen consultancy material. Discussion remains distinct from proven per-host execution. | Attribution; tools; operations; finance; hunts |
| SOCRadar leak | Browser text now accessible. ArmCorp/commission-dispute chronology reviewed against Unit 42; primary chat analysis retained for operational claims. | Attribution; financial context |

## Analytical Decisions

The primary name is The Gentlemen. Storm-2697 identifies Microsoft's platform operator cluster. Mid-2025 activity and September recruitment are distinct. The undated 320-victim/17-country combination is not presented as a current total.

CVE-2025-7771 concerns ThrottleStop, not Fortinet. The August 2025 case does not establish an exact initial-access exploit. Not every CVE discussed or listed was successfully exploited.

Small-file full encryption corrects the supplied “all files partially encrypted” wording. A password gate is not the recovery key or proof of comprehensive sandbox evasion. Claimed guaranteed recovery and complete trace removal are not adopted as outcomes.

Microsoft and Check Point disagree on the cryptographic key/nonce assignment. Microsoft's sample-specific explanation is used in the narrative, and the competing description is identified explicitly. This does not establish either a decryption opportunity or a version change.

The platform portfolio is also separated more precisely: reported Go builds for several operating systems versus the dedicated C/ELF ESXi analysis. A native API, command-line utility and operator action are distinct evidence types. The wallpaper API and ESXi popen/system calls are identified only where the original analysis names them.

ESET's June-30, the supplied July-30 and SOCRadar's September first-seen field describe incompatible early chronology. The overview uses a 2025 emergence and separately dated publications. Dated claim totals are retained with their population and cutoff; 1,570 SystemBC clients are not promoted to 1,570 confirmed encrypted organizations.

Hash lengths validate. Source roles distinguish lockers, KILLAV, PowerRun and SystemBC. Tox and Session strings are contact identifiers. Sources and collection dates are retained without invented first_seen/last_seen values.

## Additional Findings After Original-Source Review

Added Unit 42, Check Point's SystemBC/platform study, Kaspersky driver research and TRM financial analysis. Following CUHK's references also recovered original Huntress, Group-IB and Kaspersky GReAT research. These add the Windows C development branch, packet capture, PowerShell Web Access, proxy-task artifacts and source-classified hashes. Historical case IPs and one companion hash extend the supplied inventory. Aggregate financial attribution is not transformed into a fabricated wallet.

The expanded package contains 54 KQL and 54 paired SPL hunts, and 11 YARA rules. H47–H48 require Sentinel/forwarded ESXi logs rather than Defender process tables. Tool hypotheses, observed artifacts, generic behavior, encrypted-output triage and exact file identity retain separate labels. Three external note links continue to replace local transcripts.

YARA includes a scoped file-footer heuristic and exact hashes for 24 classified SHA-256 lockers, the Trend Micro locker SHA-1 and Kaspersky's Windows C locker MD5. Supporting PowerRun/KILLAV identifiers and unclassified tracker hashes are not silently converted into ransomware binaries. Synthetic tests cover positive and negative conditions; they cannot establish real-world malware recall.
