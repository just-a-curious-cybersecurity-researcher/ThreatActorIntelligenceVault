# Akira — Indicators of Compromise

**Presentation reviewed:** 2026-09-15.

This directory contains indicators collected from the Akira research in this repository, separated by indicator type for easier review, enrichment and hunting.

> **Caution:** IOCs age quickly and should not be treated as sufficient attribution evidence on their own. Validate indicators against source date, prevalence, environment context and surrounding behavior before using them for blocking or incident attribution.

## Contents

- [IP Addresses](ip-addresses.md)
- [Blockchain Addresses](blockchain-addresses.md)
- [File Artifacts](file-artifacts.md)
- [Hashes](hashes.md)
- [Ransomware Extensions](extensions.md)
- [File / Note Patterns](file-patterns.md)
- [Onion / Data Leak Infrastructure](onion-infrastructure.md)

## Blockchain-Specific Caveat

Blockchain indicators require additional care. Most publicly attributable Akira wallets are **victim payment addresses**, not necessarily the group's main treasury or long-term operational wallets.

Once funds leave a documented payment address, they may move through intermediary wallets, bridges, DeFi protocols, swaps, exchanges, VASPs, mixers or other laundering services. Attribution confidence can therefore decrease rapidly as the transaction graph expands.

See [Blockchain Addresses](blockchain-addresses.md) and [Blockchain & Financial Intelligence](../intelligence/blockchain.md) for the full analytical context.

Behavioral evidence and temporal correlation should generally be weighted more heavily than a single static IOC.

## Publication Provenance

- [Per-hash provenance and unresolved leads](hash-provenance.md)
- [Ransom-note variants and source limitations](../ransom-notes/Ransom-Notes.md)

Each indicator category records source, role, date context and confidence. “Unresolved” entries preserve the original research without promoting it to a verified blocking list.
