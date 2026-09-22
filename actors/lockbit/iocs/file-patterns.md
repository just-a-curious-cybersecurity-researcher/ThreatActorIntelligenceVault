# LockBit — File and Execution Patterns

**Presentation reviewed:** 2026-09-17.

| Pattern | Context / period | Source / confidence |
|---|---|---|
| `Restore-My-Files.txt` | Original / Red and a native 4.0 specimen | NHS, Red and native 4.0 analyses; filename alone does not distinguish branches |
| `<nine-character ID>.README.txt` | Black / 3.0 | Black-era reporting and archived notes |
| `ReadMeForDecrypt.txt` | 5.0 output | Trend Micro 2025; filename configurable/omitted in invisible operation |
| `\.[a-fA-F0-9]{16}$` | Generated hexadecimal suffix | Local hunt based on published 4.0/5.0 output; require creation/rename context and volume |
| Launch-password argument in a protected payload | Black generated builds | Anti-analysis gate; generic `-pass` is not an attribution signature |
| `locked_for_LockBit` and date-window configuration | NG-Dev | Trend technical appendix; configuration evidence is stronger than suffix alone |
| `UpdateAdobeTask`, `Mag.dll`, `123.ps1` | Citrix Bleed affiliate campaign / 2023 | CISA; require matching path, hash or process relationship |
| `a.png`, `a.cab`, `em.cab`, `am.cab` | Credential-collection artifacts / 2023 | CISA sample analysis; generic names require directory and process context |
| Hash-based service selection and direct `EvtClearLog` | Native 4.0/5.0 samples | Reverse-engineered routines; not directly visible as shell commands |
| `Solstice Google Photos` with `Corteva` version metadata | RansomLook 5.0-generation specimen / 2026-06-21 | Publisher-observed masquerade; legitimate brand is not implicated |

The 16-character extension regex is case-insensitive for hunting robustness; uppercase matching is a local adaptation rather than a claim about every emitted suffix.

