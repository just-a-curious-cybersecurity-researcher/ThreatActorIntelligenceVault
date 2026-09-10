# Qilin — File and Ransom-Note Patterns

| Pattern | Evidence and period | Confidence |
|---|---|---|
| `<company_id>-RECOVER-README.txt` | Go analysis August 2022; Agenda archived `DtMXQFOCos-RECOVER-README.txt` [Q12](../References.md#q12), [Q31](../References.md#q31) | High Confidence |
| `README-RECOVER-<company_id>.txt` | Darktrace case artifacts June 2022–May 2024; Qilin archived notes [Q09](../References.md#q09), [Q31](../References.md#q31) | High Confidence in naming, Moderate Confidence in retrospective case attribution |
| `README-RECOVER-[rand]_2.txt` | ThreatLabz collection filename | High Confidence in archive name, **not proof of `_2` on victim systems** |
| `%TEMP%\QLOG\ThreadId(<number>).LOG` | Talos 2025 sample logging [Q15](../References.md#q15) | High Confidence in sample; not sufficient actor attribution |

See [ransom-note catalog](../ransom-notes/Ransom-Notes.md). Reviewed 2026-09-10. No ransom text is inferred from a filename.
