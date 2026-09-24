# SafePay — Hash Provenance Register

**Presentation reviewed:** 2026-09-24.

| Hash | Algorithm | Publication provenance | Context / observation | Confidence |
|---|---|---|---|---|
| `a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526` | SHA-256 | Huntress; Microsoft; DCSO; Halcyon; Acronis; Bitdefender; ThreatLocker; KPMG; TEHTRIS | Windows locker/DLL with victim-password and partial-encryption arguments | High |
| `327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917` | SHA-256 | Bitdefender; KPMG; ThreatLocker; TEHTRIS | SafePay Windows payload; branch detail not public | High for association, moderate for role |
| `921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae` | SHA-256 | NCC Group; Quorum; KPMG; ThreatLocker | QDoor `soc.dll` loader from a SafePay intrusion | High, incident-scoped |
| `6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a` | SHA-256 | NCC Group; Quorum; KPMG | DLL stored inside the QDoor loader | High, incident-scoped |
| `e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346` | SHA-256 | NCC Group; Quorum; KPMG | Final PE stage injected into `WerFault.exe` | High, incident-scoped |
| `07353237350c35d6dc2c8f143b649cd07c71f62b` | SHA-1 | NCC Group; KPMG | `1.exe` deployment artifact; exact component role unresolved | Moderate, incident-scoped |
| 15 additional SHA-256 values | SHA-256 | KPMG; subsets independently in ThreatLocker and TEHTRIS | SafePay-associated samples without component-level labeling | Moderate |
| 17 additional SHA-1 values | SHA-1 | KPMG CTIP | Advisory-associated samples without component-level labeling | Moderate-low for role |
| 17 MD5 values | MD5 | KPMG CTIP | Advisory-associated samples; retained for legacy telemetry | Moderate-low for role |

The full literal lists are in [hashes.md](hashes.md). Hashes with only advisory-level context remain separate from exact locker and QDoor roles. A match establishes a published association; it does not by itself prove that the process encrypted files or that the host was operated by SafePay.
