# SafePay — IP Addresses

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24

## Campaign Infrastructure

| Indicator | Role and context | Observation | Confidence / use |
|---|---|---|---|
| `88.119.167[.]239` | QDoor C2 on TCP/443 | Hard-coded endpoint recovered in NCC incident; custom unencrypted protocol | High, incident-scoped |

| Indicator | Published role | Observation / limitation |
|---|---|---|
| `45.91.201[.]247` | SafePay-associated C2 | Published by Halcyon/Microsoft; role and lifetime not fully exposed |
| `77.37.49[.]40` | SafePay-associated C2 | Published by Halcyon/Microsoft; validate recency before blocking |
| `80.78.28[.]63` | SafePay-associated C2 | Published by Halcyon/Microsoft; validate recency before blocking |
| `199.232.192[.]193` | IP observed with Imgur-hosted wallpaper retrieval | Shared CDN infrastructure; do not block or attribute from the IP alone |

### Sygnia 2025 Incident — Access and Exfiltration

| Indicator | Role and context | Observation | Confidence / use |
|---|---|---|---|
| `185.243.96[.]9` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; VPN/provider infrastructure may be reassigned |
| `23.234.70[.]67` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; validate observation time |
| `68.235.46[.]80` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; also reproduced by secondary SafePay bulletins |
| `155.1.191[.]82` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; not a family-wide C2 |
| `208.131.130[.]45` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; not a locker indicator |
| `208.131.130[.]65` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; not a locker indicator |
| `23.234.70[.]46` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; validate provider reuse |
| `23.234.68[.]67` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; validate provider reuse |
| `23.234.90[.]68` | Source observed in SSL-VPN sessions | Sygnia 2025 incident | High for one incident; validate provider reuse |
| `192.166.225[.]69` | Destination in FileZilla traffic blocked before the actor pivoted to OneDrive | Sygnia 2025 incident | High for one incident; exfiltration to this IP was not completed |

Triskele also observed SafePay operators use Proton VPN and Mullvad. Their shared exit nodes are intentionally omitted: provider-wide address lists would create low-quality indicators and could affect legitimate privacy traffic.

The Tor addresses in [onion infrastructure](onion-infrastructure.md) are extortion services, not established malware C2 endpoints. Preserve the original log timestamp and provider/ASN enrichment when using the VPN-session IPs because they are disposable access infrastructure.
