# Lynx — Indicators of Compromise

**Presentation reviewed:** 2026-10-07.

IOC use must distinguish exact malware identity, one-incident affiliate infrastructure, legitimate services and extortion infrastructure. Historical IPs and onions are investigation pivots, not timeless block rules.

## Contents

- [Hashes](hashes.md) and [provenance](hash-provenance.md)
- [File artifacts](file-artifacts.md), [patterns](file-patterns.md) and [extensions](extensions.md)
- [IP addresses](ip-addresses.md) and [domains/contact identifiers](domains.md)
- [Onion infrastructure](onion-infrastructure.md)
- [Blockchain addresses](blockchain-addresses.md)

## Blockchain-Specific Caveat

No public Lynx-specific wallet was validated. Do not treat 64-hex SHA-256 values as transaction identifiers or import INC addresses without a Lynx transaction link.

## Publication Provenance

Primary locker hashes come from Nextron, Unit 42, CIS and the DFIR Report. NetScan and NetExec hashes belong to legitimate/dual-use tools in one incident and are separated from locker hashes. RansomLook supplies infrastructure and note snapshots; tracker presence does not verify actor control at the current date.
