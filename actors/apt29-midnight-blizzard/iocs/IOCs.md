# APT29 — Indicators of Compromise

**Presentation reviewed:** 2026-09-25.

## Contents

- Hash provenance — [Publication provenance](hash-provenance.md)
- Hashes — [Selected public hashes](hashes.md)
- Domains — [Campaign domains](domains.md)
- IP addresses — [Campaign infrastructure](ip-addresses.md)
- File artifacts — [Contextualized artifacts](file-artifacts.md)
- Patterns — [File and path patterns](file-patterns.md)
- Extensions — [Artifact applicability](extensions.md)

No blockchain-address or onion-hostname file is present because the reviewed sources did not provide an APT29-attributed wallet or actor-operated `.onion` hostname. Tor transport remains documented in operations.

## Blockchain-Specific Caveat

No public wallet, mixer flow, ransom-payment address or on-chain cluster was validated for APT29. The 2024 FBI/NSA/CNMF/NCSC advisory says SVR operators use cryptocurrency, fake identities and low-reputation email accounts to lease infrastructure, but it publishes no address or transaction. OFAC actions against the SVR or supporting companies are legal and attribution evidence; they are not wallet identifiers.

## Publication Provenance

Reviewed **2026-09-25**. Indicators are defanged where appropriate and deduplicated by type. Campaign dates, publication dates and first-seen dates are kept separate. Most entries are historical and may have been reassigned, remediated or sinkholed. Exact matches support investigation; they do not establish current hostile control or actor attribution without surrounding evidence.

The newest register is Anthropic's 2026-09-10 GTG-20006 corpus. Several entries overlap Microsoft CaptiveCrunch, while the additional domains, IP addresses, filenames and two email indicators remain tied to Anthropic's qualified cluster assessment. They are not promoted to universal APT29 infrastructure.

Google's 2026 UNC6293/UNC7005 register is a separate qualified tier because Google assigns only moderate confidence to the ICE RELIC initial-access relationship. UNC5976 network and HEADRUSH indicators are deliberately absent. Check Point's 2025 GRAPELOADER/WINELOADER corpus remains directly attributed by that publisher and is separated from the qualified Google tier in hash provenance and detections.
