# SafePay — Domains and Alternate Namespaces

**Presentation reviewed:** 2026-09-24.

| Indicator | Role / date context | Confidence and caution |
|---|---|---|
| `i[.]imgur[.]com/zhCjntO[.]png` | Wallpaper image referenced by Microsoft SafePay behavior | High for the historical resource; Imgur is legitimate shared hosting |
| `safepay[.]ton` | TON-network leak-site mirror advertised with SafePay extortion infrastructure | High for published service name; it is not a conventional DNS domain or malware C2 |
| `jjvq-sharepoint[.]com` | Attacker-controlled SharePoint Online/OneDrive tenant used for completed exfiltration in Sygnia IR | High, incident-scoped; shared Microsoft hosting means tenant identity matters more than Microsoft IP space |

Sygnia also displayed the tenant in browser artifacts as `jjvq-my-sharepoint[.]com`; its published IOC table records `jjvq-sharepoint[.]com`. Both strings are retained for hunting because the article exposes this naming discrepancy.

No standalone actor-controlled clearnet malware domain with primary-source provenance was located. The SharePoint/OneDrive tenant is a cloud-service artifact from one incident; do not block Microsoft 365 globally.
