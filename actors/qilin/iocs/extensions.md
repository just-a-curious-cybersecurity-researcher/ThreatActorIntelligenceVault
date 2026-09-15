# Qilin — Ransomware Extensions

Qilin uses configurable, often victim-specific extensions. **No universal `.qilin` extension is established** by these sources.

| Extension | Variant / period | Evidence / confidence |
|---|---|---|
| `.DtMXQFOCos` | Agenda-branded historical note; exact incident date unknown | Agenda-branded redacted note states this value; Historical archive, exact incident date unknown; High Confidence in text |
| `.MmXReVIxLV` | Early Windows Rust sample, December 2022 | Extension emitted by analyzed early Rust sample; December 2022; High Confidence |
| `.2ir53sQQAU` | Qilin media-pressure note; exact incident date unknown | Qilin media-pressure note states this value; Historical archive, exact incident date unknown; High Confidence in text |
| `.<company_id>` / variable strings | Go/Rust sample reporting, 2022–2025 | Go and Rust configuration supports per-victim extension; 2022–2025 sample reporting |

Character length is not an actor signature. Generic random-extension alerts need note, process, volume and file-server context. Textual mention is weaker than sample-confirmed emitted behavior. Reviewed 2026-09-10.
