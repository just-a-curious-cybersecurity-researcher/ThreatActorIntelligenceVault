# Qilin — Indicators of Compromise

This directory separates indicators by type for enrichment, investigation and hunting. Each value must retain its source, observation period, role and confidence. These are historical pivots, not a current universal blocking list.

> **Caution:** a hash, IP, filename or legitimate tool alone does not establish Qilin attribution. Check prevalence, ownership interval, account, process and surrounding activity.

## Contents

- [IP Addresses](ip-addresses.md)
- [Domains](domains.md)
- [Blockchain Addresses](blockchain-addresses.md)
- [File Artifacts](file-artifacts.md)
- [Hashes](hashes.md)
- [Ransomware Extensions](extensions.md)
- [File / Note Patterns](file-patterns.md)
- [Onion / Data Leak Infrastructure](onion-infrastructure.md)

## Blockchain-Specific Caveat

The five listed addresses belong to officially attributed **FirstVPN service infrastructure**. Qilin's reported use of the service does not establish control of all five addresses or identify the exact purchase transfer.

See [Blockchain Addresses](blockchain-addresses.md) and [Blockchain & Financial Intelligence](../intelligence/blockchain.md) for provenance, dates and the limits of downstream attribution.

## Publication Provenance

- [Per-hash provenance](hashes.md#provenance-and-newly-sourced-artifacts)
- [Ransom-note variants and source limitations](../ransom-notes/Ransom-Notes.md)
- [Source review](../intelligence/source-review.md)

Indicators are defanged where applicable. No victim credentials, stolen documents or malware binaries are included.
