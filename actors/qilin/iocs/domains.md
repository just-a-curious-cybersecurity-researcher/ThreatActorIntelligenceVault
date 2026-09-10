# Qilin — Domains and External Services

| Indicator | Role / date context | Source | Confidence and caution |
|---|---|---|---|
| `ikea0[.]com` | Likely Cobalt Strike C2 in 2024 probable Qilin-related case | [Q09](../References.md#q09) | Moderate Confidence; historical attribution |
| `lebondogicoin[.]com` | Likely Cobalt Strike C2, same case population | [Q09](../References.md#q09) | Moderate Confidence; shared tooling does not identify operator |
| `cloud.screenconnect[.]com.ms` | AiTM phishing domain for January 2025 MSP intrusion | [Q22](../References.md#q22) | High Confidence in observed phishing role; distinct from legitimate `cloud.screenconnect.com` |
| `regsvchst[.]com`, `holapor67[.]top` | Talos 2025 companion IOC list | [Q29](../References.md#q29) | Moderate Confidence in case association; exact role unresolved |
| `mimikatzlogs@anti[.]pm`, `mimikatz@anti[.]pm` | Credential-collection/exfiltration mailboxes in Talos toolkit context | [Q15](../References.md#q15), [Q29](../References.md#q29) | High Confidence in published artifacts; not ransom-negotiation contacts |
| `pub-959ff112c2eb41ce8f7b24e38c9b4f94[.]r2.dev`, `pub-2149a070e76f4ccabd67228f754768dc[.]r2.dev` | Fake CAPTCHA hosting in October 2025 report | [Q23](../References.md#q23) | Moderate Confidence in observed hosting; infostealer-to-Qilin access causality is assessed |
| Backblaze, MEGA, EasyUpload, Cloudflare R2 | Legitimate services abused for storage/delivery in separate incidents | [Q15](../References.md#q15), [Q09](../References.md#q09), [Q22](../References.md#q22), [Q23](../References.md#q23) | **Do not block entire service domains solely from this dossier**; account, object path, direction and bytes matter |

Reviewed 2026-09-10. The note-advertised publication mirrors are in [onion infrastructure](onion-infrastructure.md); they are not presumed C2. Source mailbox names do not prove Mimikatz executed successfully on a victim. No live attacker contact was attempted.
