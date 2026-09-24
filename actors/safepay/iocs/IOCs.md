# SafePay — Indicators of Compromise

**Presentation reviewed:** 2026-09-24.

This directory separates SafePay indicators by type and preserves whether each item belongs to the locker, a supporting intrusion tool, extortion infrastructure or an unverified DLS claim.

> **Caution:** static indicators age quickly. Do not infer SafePay attribution from a dual-use tool, an isolated IP address or an onion URL without behavioral and temporal context.

## Contents

- [IP Addresses](ip-addresses.md)
- [Domains and Alternate Namespaces](domains.md)
- [Blockchain Addresses](blockchain-addresses.md)
- [File Artifacts](file-artifacts.md)
- [Hashes](hashes.md)
- [Ransomware Extensions](extensions.md)
- [File / Note Patterns](file-patterns.md)
- [Onion / Data Leak Infrastructure](onion-infrastructure.md)

## Blockchain-Specific Caveat

The notes request cryptocurrency payment and public reporting identifies Bitcoin as the settlement asset, but no primary source reviewed at cutoff exposed a SafePay-controlled address. A shared VASP deposit address mentioned by TRM Labs is not published and would not by itself prove common control with INC or Qilin.

See [Blockchain Addresses](blockchain-addresses.md) and [Blockchain & Financial Intelligence](../intelligence/blockchain.md) for the evidence boundary.

## Publication Provenance

- [Per-hash provenance](hash-provenance.md)
- [Ransom-note variants](../ransom-notes/Ransom-Notes.md)
- [Complete source register](../References.md)

The hash register now contains 20 SHA-256, 18 SHA-1 and 17 MD5 values. Only two SHA-256 values are publicly identified as SafePay Windows payloads and three as QDoor-chain components; the rest retain advisory-level labeling.

Sygnia's 2025 incident contributes ten network indicators, an attacker-controlled OneDrive/SharePoint tenant and a named discovery/staging artifact set. These values are case-scoped. Locker hashes, QDoor components and aggregate advisory indicators remain separately labelled. Current blocking decisions should be made only after prevalence and first-seen checks in the defender's own environment.
