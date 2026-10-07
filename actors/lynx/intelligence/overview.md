# Lynx — Intelligence Overview

**Presentation reviewed:** 2026-10-07.

## Background

Lynx appeared publicly in July 2024 and advertised an affiliate program on RAMP on 2024-08-08 under the handle `silencer`. It combines data theft, encryption and publication threats. Direct panel access documented by Group-IB confirms a structured service rather than only a leak-site brand.

The brand markets itself as “ethical” and claims exclusions for the CIS, Ukraine, China, Iran, North Korea and several protected sectors. Public claims against healthcare, government, education and nonprofit organizations contradict a reliable ethical boundary. Treat the rules as recruitment language, not enforceable policy.

## Targeting and Victimology

Targeting is broad and opportunity-driven. BreachSense's 2026-09-24 snapshot classified 235 entries: manufacturing 56, construction 38, finance 21, legal services 20, logistics 19, healthcare 13, hospitality 10 and government 9. Of 196 entries with country data, the United States accounted for 78, followed by Canada 18, the United Kingdom 14, Germany 12, Australia 11, Italy 8, and France and Spain 6 each. Tracker classification is incomplete and leak claims are not confirmed intrusions.

The 2024 Electrica incident shows interest in critical infrastructure while also showing operational segmentation: Romania's DNSC attributed the attack to Lynx, but reported that critical power and SCADA systems were not affected. A 2025 incident reconstructed by The DFIR Report targeted backup and file servers after nine days of interactive access.

## Operational Model

The panel separates company records, victim chats, sub-affiliate “stuffers,” leak scheduling and payload delivery. Affiliates reportedly retain 80 percent, control their payment wallet and conduct negotiation; the service takes 20 percent. Optional call harassment and storage services can change the economic split.

Recruitment emphasizes experienced penetration-testing teams. That design creates affiliate variation: one intrusion can use RDP, AnyDesk, NetScan and NetExec while another uses an initial-access broker or exploited edge device. The platform supplies infrastructure and payloads; it does not make every intrusion technically identical.

## Ransomware Development

The Windows branch is C++ and uses AES-128 CTR with Curve25519-derived key material. It supports four encryption modes: fast 5%, medium 15%, slow 25% and entire 100%. Earlier analyses observed the medium-like pattern as 1 MB encrypted followed by 5 MB skipped.

Later affiliate bundles contain Windows, Linux, ESXi and NAS-oriented builds for x86, x64, ARM, MIPS, PPC64LE, RISC-V and s390x, including musl-linked builds. Group-IB had not seen the Linux build deployed in the wild at publication time; availability in a panel must remain separate from confirmed deployment.

## Data Leak Site

The extortion infrastructure has moved from early `lynxblog[.]net` and a single onion portal to multiple blog, chat, storage, guest and administration mirrors. RansomLook listed 418 posts at review time, with no posts in its last-30-day window and a latest visible entry dated 2026-08-29. BreachSense recorded 391 victims and a most-recent date of 2026-08-31 in its 2026-09-24 snapshot. The difference is methodological, not evidence that one total is the number of confirmed breaches.

## Current Evolution in the Collected Research

By 2025 the service had expanded its cross-platform builder and panel. Public reporting also identified Sinobi, which shares code and infrastructure characteristics with Lynx and INC. The evidence supports a lineage and possible operator continuity but does not resolve whether Sinobi replaced Lynx, split from it or used the same acquired code.

RansomLook still recorded Lynx claims in 2026. Low recent post volume can reflect operational pauses, parser visibility, private settlements or migration; it does not alone prove closure.

## Intelligence Gaps

- No stable legal identity or operator location has been established publicly.
- No public Lynx builder source, affiliate contract corpus or complete version history is available.
- Public reporting does not expose a validated Lynx wallet set or the 20% operator settlement addresses.
- Linux/ESXi availability is established; public in-the-wild deployment evidence remains thinner than Windows evidence.
- Tracker claims rarely reveal whether encryption, theft, negotiation or payment actually occurred.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| 2024-07 | First public samples and claims; Windows encryptor analyses begin. |
| 2024-08-08 | `silencer` advertises the RaaS affiliate program on RAMP. |
| 2024-09 to 2024-10 | Rapid7 and Nextron document Windows behavior and INC code similarity. |
| 2024-12-09 | Electrica reports a ransomware incident later attributed by DNSC to Lynx; critical operational systems reportedly unaffected. |
| 2025 | Group-IB documents the affiliate panel and multi-architecture bundle; tracker activity expands. |
| 2025-03 incident / 2025-12 publication | DFIR reconstruction documents valid-RDP access, domain-account persistence, NetScan/NetExec discovery, 7-Zip staging, `temp[.]sh` exfiltration and `w.exe` deployment. |
| 2025-06 onward | Sinobi emerges with Lynx/INC code and infrastructure overlap; organizational interpretation remains qualified. |
| 2026-08 to 2026-10 | Trackers retain hundreds of claims; latest visible claims fall in late August, with differing counts and dates. |

## Law-Enforcement Development

No Lynx-specific takedown, indictment or OFAC designation was validated in the reviewed public sources. General ransomware enforcement and sanctions can affect affiliates, exchanges and infrastructure providers without constituting a Lynx designation.
