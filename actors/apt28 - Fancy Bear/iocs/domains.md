# APT28 — Domains and External Services

**Reviewed:** 2026-09-14. Recent means recently published, not independently confirmed active. Blank observation dates are intentional.

| Indicator | Role / date context | Source | Confidence and caution |
|---|---|---|---|
| freefoodaid[.]com | Neusploit delivery; 2026-02-02; recent published; first_seen: ; last_seen:  | [A29](../References.md#a29) | Published role; ownership/current activity requires validation |
| wellnesscaremed[.]com | Neusploit infrastructure; 2026-02-02; recent published; first_seen: ; last_seen:  | [A29](../References.md#a29) | Published role; ownership/current activity requires validation |
| mvband[.]net | GAMEFISH infrastructure; 2017; historical; first_seen: ; last_seen:  | [A15](../References.md#a15) | Published role; ownership/current activity requires validation |
| mvtband[.]net | GAMEFISH infrastructure; 2017; historical; first_seen: ; last_seen:  | [A15](../References.md#a15) | Published role; ownership/current activity requires validation |
| a.matti444@proton[.]me | NotDoor exfiltration address; not a lure sender; 2025-09-03; published; first_seen: ; last_seen:  | [A25](../References.md#a25) | Published role; ownership/current activity requires validation |

Microsoft 365 domains targeted by DNS hijacking are legitimate destinations, not attacker-owned C2. Likewise OneDrive, Filen, Icedrive and webhook services require account, URL and process context; do not block their entire service domains based on attribution alone. [A28](../References.md#a28) [A32](../References.md#a32) [A33](../References.md#a33)
