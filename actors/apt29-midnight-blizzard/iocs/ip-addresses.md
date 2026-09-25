# APT29 — IP Addresses

**Presentation reviewed:** 2026-09-25.

## Campaign Infrastructure

| Indicator | Role and context | Observation | Confidence / use |
|---|---|---|---|
| 31.57.243[.]154 | CaptiveCrunch AitM infrastructure | first_seen: 2026-07-16; Microsoft publication 2026-07-31; also Anthropic GTG-20006 | High for dated campaign; current control not asserted |
| 38.146.28[.]75 | CaptiveCrunch infrastructure | first_seen: 2026-07-01; also Anthropic GTG-20006 | High for dated campaign |
| 38.146.28[.]132 | CaptiveCrunch DNS resolver | first_seen: 2026-07-15; also Anthropic GTG-20006 | High for dated campaign |
| 104.194.159[.]150 | CaptiveCrunch AitM infrastructure | first_seen: 2026-04-28 | High for dated campaign |
| 107.189.26[.]194 | ChocoShell C2 / CaptiveCrunch DNS resolver | first_seen: 2026-02-27 | High for dated campaign |
| 213.145.86[.]112 | ChocoShell C2 | first_seen: 2026-07-01; Microsoft URI-path reporting; also Anthropic GTG-20006 | High for dated campaign |
| 104.145.210[.]184 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching; current control not asserted |
| 104.194.151[.]133 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 104.194.159[.]55 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 144.172.114[.]192 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 2.26.53[.]194 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 148.135.195[.]111 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 185.198.234[.]26 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 185.198.234[.]101 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 149.54.42[.]106 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 104.194.149[.]228 | GTG-20006 campaign infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 | High for exact retrospective matching |
| 185.225.69[.]69 | GoldMax and GoldFinder C2/test destination | Microsoft publication 2021 | Historical; ownership can change |
| 91.190.191[.]117 | Residential proxy used by UNC6293 application-specific-password campaigns | Google 2025 | Qualified ICE RELIC initial-access tier; shared/proxy nature limits blocklisting value |
| 107.189.18[.]7 | VIDAR C2 in UNC7005 operation | Google 2026 | Campaign association; commodity malware and hosting reuse require context |
| 196.251.107[.]171 | ATOMIC second-payload C2 in UNC7005 operation | Google 2026 | Qualified cluster tier |

| Indicator | Published role | Observation / limitation |
|---|---|---|
| 103.216.221[.]19 | WellMail malware infrastructure | NCSC 2020; historical |
| 119.81.184[.]11 | APT29-operated infrastructure using a GlobalSign certificate; not necessarily WellMail C2 | NCSC 2020; keep role qualification |
| 185.225.226[.]16 | Same certificate-linked infrastructure category | NCSC 2020; historical |
| 188.241.68[.]137 | Same certificate-linked infrastructure category | NCSC 2020; historical |
| 45.129.229[.]48 | Same certificate-linked infrastructure category | NCSC 2020; historical |

Residential proxies, VPN exits, Tor nodes and victim-local cloud IP addresses are intentionally absent unless a primary source assigned a stable campaign role. Their shared or transient nature makes unspecific blocklisting unsafe.
