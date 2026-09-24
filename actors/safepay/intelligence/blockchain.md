# SafePay — Blockchain and Financial Intelligence

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Overview

SafePay is financially motivated. Bitdefender reports that the Tor negotiation flow supplies instructions for a Bitcoin payment after the victim authenticates with a unique ID. The reviewed public sources do not expose a victim payment address, transaction ID or operator treasury cluster that can be safely published as a SafePay wallet set.

## Blockchain Attribution and Visibility Limitations

RansomLook’s SafePay crypto page returned “No wallet found.” OFAC searches produced no direct SafePay designation or SafePay-labeled address. Chainalysis did not publish a SafePay-specific public wallet trace in the reviewed material. Absence from those public registers is not evidence that no payments occurred.

Addresses are normally delivered per negotiation and can be single-use. A DLS count cannot be converted into revenue, and payment totals from the broader ransomware economy cannot be assigned to SafePay.

### Evidence-Based Payment and Cash-Out Model

1. The ransom note sends the victim to a Tor chat and identifies the case with a victim-specific ID; the public note does not contain a reusable address.
2. Bitcoin payment instructions are delivered during negotiation. No reviewed source establishes a fixed SafePay address, standard address type, reuse interval or universal demand.
3. Microsoft reports demands often near one to three percent of annual revenue. That describes demand calibration, not confirmed receipts.
4. TRM observed an unnamed global VASP deposit address also used in flows attributed to SafePay, INC and Qilin. The article exposes neither the address nor the SafePay transaction path leading to it.
5. No public evidence demonstrates a SafePay-specific mixer, bridge, swap service, peel chain, consolidation wallet or final fiat off-ramp. Those stages must be derived from a victim transaction, not copied from another ransomware family.

## Financial Evidence Timeline

- **2024–2025:** ransom notes offer data deletion and decryption in exchange for payment but do not expose a reusable address in the public archive.
- **2025:** Microsoft reported demands often calibrated near one to three percent of annual revenue; this is an observed range, not a universal rate card.
- **2025 year-end:** TRM recorded 452 SafePay claims and noted that high publication volume did not imply proportionate ransom revenue.
- **2025–2026:** TRM observed a global VASP cash-out address used by SafePay, INC and Qilin in a broader analysis of Kairos flows. The public article does not reveal the address, so it cannot populate the IOC register.

## Deviations from Phase IV

No public SafePay wallet cluster, transaction graph, mixer route, seized wallet or payment ledger was available for the actor-specific financial workflow used elsewhere in this repository. The dossier therefore records the evidence boundary instead of generating an address list from note text or generic ransomware wallets.

## Financial Relationships

TRM's shared cash-out observation may reflect a common affiliate, broker, negotiator, laundering service or exchange deposit rather than joint ownership of the ransomware brands. TRM describes SafePay, INC and Qilin as interlinked in the context of shared endpoints, while its own explanation also points to a likely common affiliate. Because the address and SafePay transaction context are not public, the overlap is an analytical lead only and does not override the closed-team evidence.

SafePay’s claimed closed model would allow the core to retain proceeds, but the public record does not show whether brokers, negotiators, hosting providers or money-laundering services receive separate fees.

## Cash-Out Timing

No actor-specific timing evidence is public. Investigators should preserve the negotiation address, requested asset/network, amount, timestamps, transaction ID and any replacement address. Those victim-provided records are required to determine consolidation, peel-chain, exchange, swap or mixer behavior.

## Intelligence Gaps

- Negotiation-linked BTC or other cryptocurrency addresses.
- Confirmed ransom-payment transaction IDs and payment amounts.
- Public attribution of exchange deposits or laundering services beyond the unnamed TRM overlap.
- Revenue split between core operators and any brokers or service providers.
- Seized infrastructure or legal records tying wallets to people.

## Analyst Note

Do not add an address because it appears in a generic ransomware feed or a SafePay-branded note screenshot. Require a primary negotiation record, regulator/law-enforcement publication or named blockchain-analysis attribution. Record the network as well as the address because identical-looking strings on different chains can create screening errors.

## Independent Corroboration and Financial-Service Disruption

TRM independently recognizes SafePay as a closed, high-volume ransomware operation and reports a shared VASP cash-out point without exposing the address. No SafePay-specific public seizure, exchange freeze, recovery action or law-enforcement wallet cluster was located. General ransomware payment disruption is relevant context but not actor-specific evidence.

## Regulatory and Judicial Review

SafePay, Safepay and “SafePay Ransomware Group” did not return a direct actor designation in the reviewed OFAC material. The current UK Cyber designations and EU cyber-sanctions timeline also contained no SafePay-named listing, and no public DOJ indictment naming a SafePay operator was located. This is an actor-name result, not clearance for a payment. The supplied address, exchange, broker, infrastructure provider or beneficial owner can be separately designated, so case-specific screening remains necessary.

### Address Collection and Screening Record

For every negotiation, record the exact asset, network, address, requested amount, address-issue time, expiry or replacement messages and transaction ID. Screen the literal address and the known counterparties against current OFAC, UK and EU lists, then preserve the result and list version. If funds move, trace change outputs, consolidation, co-spends and VASP deposits without assuming that a shared deposit address is owned by the ransomware operator.

## Multi-Chain Research and Next Collection Priorities

Collection should begin with victim negotiation records, then test the supplied address against current sanctions lists and reputable blockchain analytics. Preserve BTC script type and transaction graph, and record any requested switch to Monero, stablecoins or another chain. Do not infer SafePay use of a mixer or bridge until a trace demonstrates it.
