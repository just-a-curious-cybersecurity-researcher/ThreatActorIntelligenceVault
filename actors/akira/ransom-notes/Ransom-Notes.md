# Akira — Ransom Notes

This collection distinguishes **textual templates**, **encryptor families** and **filenames known only from reporting**. A collector's suffix is not a malware version. Reviewed 2026-09-10. Threats and recovery promises in notes are attacker claims, not validated facts or advice.

| Document | Variant / evidence | Approximate observation |
|---|---|---|
| [Canonical Akira](akira.md) | Redacted text archive and early C++ screenshot; `akira_readme.txt` | Canonical template publicly documented June 2023 |
| [Akira file-handling warning](akira-warning.md) | Archive `_2`; adds `.arika`/`.akira` instructions and victim path | Exact incident date unavailable |
| [Akira impersonation warning](akira-contact-warning.md) | Archive `_3`; adds exclusive-chat and recovery-agency warnings | Exact incident date unavailable |
| [Megazord / Akira portal](megazord.md) | Rust Windows; `powerranges.txt`; vendor screenshot/report | From August 2023 |
| [Megazord messaging alternative](megazord-messaging.md) | Telegram/Tox instead of Tor in some samples; operator uncertain | Reported September 2023 / December 2024 |
| [Akira_v2](akira-v2.md) | Rust Linux/ESXi; `akiranew.txt`; body not collected | 2024 |
| [Other filenames](other-filenames.md) | `fn.txt`, dot-form and generic readme leads | 2024 advisory / undated sheet |

Available archived text is retained in the local variant files. Short excerpts, paraphrases and absence statements below are deliberately distinguished. No missing text, victim password, negotiation code or unobserved contact endpoint has been reconstructed. See [infrastructure roles](../iocs/onion-infrastructure.md), [negotiation analysis](../intelligence/operations.md) and [file patterns](../iocs/file-patterns.md).
