# APT29 — Ransomware Extensions

**Presentation reviewed:** 2026-09-25.

| Extension | Variant / period | Evidence / confidence |
|---|---|---|
| `.rdp` | Midnight Blizzard phishing, 2024 | Delivery/configuration artifact; not an encryption extension |
| `.hta` | ROOTSAW / WINELOADER chain, 2024 | Script delivery artifact |
| `.iso` / `.vhdx` | Historical APT29 delivery | Container used to evade Mark-of-the-Web in reported campaigns |
| `.dll` / `.exe` | Multiple malware families | Executable artifact types; path, hash and signer determine value |
| `.txt` / `.zip` | WINELOADER and GRAPELOADER staging | Encoded intermediate or delivery archive; not encrypted victim output |

No public source reviewed here documents an APT29 ransomware suffix or mass file-renaming pattern.
