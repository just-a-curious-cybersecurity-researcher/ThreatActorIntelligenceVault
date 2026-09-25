# APT29 — Domains and External Services

**Presentation reviewed:** 2026-09-25.

| Indicator | Role / date context | Confidence and caution |
|---|---|---|
| ms365-device[.]com | CaptiveCrunch device-code-flow redirect; first_seen: 2026-07-23; published: 2026-07-31 | Microsoft Storm-2945; also published by Anthropic for GTG-20006; current control not asserted |
| ms365-live[.]com | CaptiveCrunch device-code-flow redirect; first_seen: 2026-05-14 | Microsoft; also published by Anthropic for GTG-20006 |
| teams[.]ms365-live[.]com | GTG-20006 Microsoft/Teams-themed infrastructure | Anthropic 2026; campaign period 2025-12–2026-08 |
| m365-owa[.]com | CaptiveCrunch AitM infrastructure; first_seen: 2026-07-20 | Microsoft; also published by Anthropic for GTG-20006 |
| owa-ms365[.]com | CaptiveCrunch AitM infrastructure; first_seen: 2026-07-16 | Microsoft; also published by Anthropic for GTG-20006 |
| mslivetest[.]duckdns[.]org | GTG-20006 dynamic-DNS infrastructure | Anthropic 2026; dated campaign IOC |
| my-invite[.]org | GTG-20006 phishing/delivery infrastructure | Anthropic 2026; dated campaign IOC |
| chamber-ua[.]org | GTG-20006 target-themed infrastructure | Anthropic 2026; dated campaign IOC |
| chathamhouse[.]eu | GTG-20006 target-themed infrastructure | Anthropic 2026; lookalike context required |
| ukrinform-share[.]net | GTG-20006 Ukraine-themed infrastructure | Anthropic 2026; dated campaign IOC |
| statistic-ms[.]live | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| static-ms[.]live | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| ad-g[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| docs-viewer[.]org | GTG-20006 document-themed infrastructure | Anthropic 2026; dated campaign IOC |
| wa-connect[.]eu | GTG-20006 WhatsApp-themed infrastructure | Anthropic 2026; dated campaign IOC |
| mygreatmarket[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| mygreatmarket[.]com | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| cdncounter[.]net | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| static[.]cdncounter[.]net | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| stuseamandesilt[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| api[.]stuseamandesilt[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| cdn[.]stuseamandesilt[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| update[.]stuseamandesilt[.]org | GTG-20006 update-themed infrastructure | Anthropic 2026; dated campaign IOC |
| itechx[.]tel | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| pdfviewer2024[.]b-cdn[.]net | GTG-20006 delivery infrastructure on a shared CDN | Anthropic 2026; do not block the provider root |
| meridian-protocol[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| meridiangroup-corp[.]com | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| projectnightcrawler[.]dev | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| metricwave[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| mgsend[.]org | GTG-20006 infrastructure | Anthropic 2026; dated campaign IOC |
| wa-meeting[.]com | GTG-20006 WhatsApp/meeting-themed infrastructure | Anthropic 2026; dated campaign IOC |
| russianearabroad[.]com | GTG-20006 lure/infrastructure domain | Anthropic 2026; dated campaign IOC |
| russianearabroad[.]org | GTG-20006 lure/infrastructure domain | Anthropic 2026; dated campaign IOC |
| russianearabroad[.]net | Domain used in a published GTG-20006 email indicator | Anthropic 2026; retain the full email for higher specificity |
| anna.manager@russianearabroad[.]net | Exact GTG-20006 email indicator | Anthropic 2026; preserve headers and authentication results |
| events@embassy-protocol[.]int | Exact GTG-20006 email indicator | Anthropic 2026; preserve raw-message context |
| findcloudflare[.]com | Fake Cloudflare verification in 2025 watering-hole device-code campaign | AWS attribution to APT29; infrastructure disrupted; current control not asserted |
| cloudflare[.]redirectpartners[.]com | Replacement watering-hole redirect infrastructure after disruption | AWS 2025; do not confuse with Cloudflare-owned service infrastructure |
| bakenhof[.]com | 2025 diplomatic phishing sender and `wine.zip` download host | Check Point APT29 assessment |
| silry[.]com | 2025 diplomatic phishing sender and `wine.zip` download host | Check Point APT29 assessment |
| ophibre[.]com | GRAPELOADER HTTPS C2 at `/blog.php` | Check Point 2025 |
| bravecup[.]com | WINELOADER 2025 HTTPS C2 at `/view.php` | Check Point 2025 |
| rediruri[.]app | UNC6293 OAuth redirect domain | Google 2025; then-low-confidence APT29/ICECAP link, later upgraded to moderate-confidence ICE RELIC subcluster relationship |
| dosportal[.]app | UNC6293 phishing domain | Google 2026; moderate-confidence ICE RELIC initial-access relationship |
| foreignrelations[.]us | UNC6293 phishing domain | Google 2026; moderate-confidence ICE RELIC initial-access relationship |
| fewfwfwfwfwf[.]info | VIDAR C2 associated with UNC7005 delivery | Google 2026; commodity-malware infrastructure; qualified cluster tier |
| miov2iaiaoubqosiqoiajwowiwjso[.]online | ATOMIC second-stage C2 | Google 2026; qualified UNC7005 campaign association |
| mioisiskwowiwjowuwjwolab[.]club | ATOMIC second-stage C2 | Google 2026; qualified UNC7005 campaign association |
| wa-connect[.]net | UNC7005 WhatsApp-themed phishing | Google 2026; qualified cluster tier |
| wa-invite[.]com | UNC7005 WhatsApp-themed phishing | Google 2026; qualified cluster tier |
| wa-device[.]com | UNC7005 WhatsApp-themed phishing | Google 2026; qualified cluster tier |
| shopinvite[.]org | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| globsec[.]net | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| finishoperations[.]com | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| finishoperations[.]org | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| foc-share[.]com | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| share-foc[.]com | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| internal-share[.]com | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| foc-share[.]org | UNC7005 phishing domain | Google 2026; qualified cluster tier |
| waterforvoiceless[.]org | Compromised WordPress site hosting ROOTSAW/WINELOADER chain; observed: 2024-02 | Compromised site; do not treat the owner as the actor |
| siestakeying[.]com | WINELOADER C2 `/auth.php`; 2024 campaign | Mandiant-published campaign C2 |
| srfnetwork[.]org | GoldMax/GoldFinder infrastructure; published 2021 | Historical; Microsoft notes some domains were acquired or compromised after prior legitimate use |
| reyweb[.]com | GoldMax C2; published 2021 | Historical; current ownership requires validation |
| onetechcompany[.]com | GoldMax C2; published 2021 | Historical; current ownership requires validation |
| megatoolkit[.]com | GoldMax C2; added 2021-04-15 | Historical; do not block by age/reputation alone |
| nikeoutletinc[.]org | GoldMax/GoldFinder C2; added 2021-04-15 | Historical; current ownership requires validation |

Dropbox, Google Drive, GitHub, Trello, Microsoft Graph, Reddit, Twitter, Imgur and Notion are documented services used in specific campaigns. Their service roots are excluded from the indicator table because global blocking would create substantial false positives. UNC5976 domains such as `drive.google.verify-drive[.]com` and `mail.kiis[.]co[.]uk` are also excluded because Google treats that cluster as distinct.
