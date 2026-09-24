# DragonForce — RansomBay Panel Builder Revision

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

This file covers the Conti-derived Windows and Linux builds generated from the RansomBay affiliate panel examined by S2W in early 2026. It is separated from the earlier 534-byte Windows build because the panel revision changed the configuration schema and file footer. The revision preserves the same cryptographic and process-termination core; it is not a new ransomware family.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| RansomBay standard builder, observed 2026 | Windows PE and Linux ELF; Conti-derived core | Configurable scope, exclusions, BYOVD-backed termination, full/header/partial encryption | Generated settings vary by client and affiliate |
| RansomBay beta builder, observed 2026 | Windows PE and Linux ELF | Adds per-extension `encryption_rules`; expands ratio field from one to four bytes; 537-byte footer | Footer/config schema distinguishes this revision from the earlier 534-byte build |
| ESXi beta output | Linux ELF with virtualization handling | Same core as Linux/NAS/RHEL plus VM shutdown and ESXi/user collection | ESXi-only behavior must not be assigned to NAS or RHEL builds |

## Executable Analysis

### 1. Builder input becomes embedded configuration

The affiliate does not edit source code. The RansomBay panel generates a client-specific payload from choices such as encryption scope, paths, exclusions, note, extension, target platform and encryption mode. The resulting binary decrypts its embedded configuration with ChaCha8 when it starts.

This design changes the evidentiary value of visible artifacts. A note name, suffix, selected paths or exclusion list can differ between two payloads that share the same executable core. Configuration values identify a build and victim context more reliably than the service as a whole.

### 2. Panel evolution

Group-IB observed the earlier panel offering both the native/Conti-derived and LockBit-derived Windows builders, a selectable EDR/XDR termination driver, Windows and ESXi output, client tracking, test decryption, publication scheduling and team permissions. S2W found two material changes in the 2026 panel:

- the LockBit 3.0-derived builder was no longer available;
- the panel no longer exposed driver selection, although generated binaries still contained BYOVD-backed process termination.

The removal of a user-interface option therefore did not remove the underlying impairment capability. Defenders should continue to collect driver loads and security-process exits for payloads generated after the panel change.

### 3. Configuration schema

The beta schema retains the earlier configuration fields and adds `encryption_rules`. Without a rule, the payload chooses full, header or partial encryption from the default build mode and size thresholds. With a rule, the configured file extension receives its assigned mode regardless of size.

Conceptual flow:

```text
decrypt embedded configuration with ChaCha8
build default scope and exclusion lists
for each eligible file:
  if extension has an encryption_rules override:
    use the configured full / header / partial mode
  else:
    use the default mode and size logic
```

An extension-specific override allows an affiliate to fully encrypt a high-value database type while applying a faster mode to large virtual disks. It also means that file size alone cannot reconstruct how a beta payload handled a given file.

### 4. Windows execution path

The panel-generated Windows build preserves the established order:

1. decode strings and decrypt configuration;
2. parse runtime parameters and initialize logging/time state;
3. enforce single execution and prepare scheduled work where enabled;
4. terminate configured processes, including the retained BYOVD path;
5. traverse local paths and discover eligible network shares;
6. generate per-file ChaCha8 material and select the configured encryption mode;
7. protect recovery material with RSA-4096, append metadata and rename the file;
8. write the configured note/visual artifacts and inhibit recovery.

The core encryption and BYOVD routines were unchanged from the earlier S2W-analyzed build. The useful revision markers are the additional configuration field and expanded footer rather than a new algorithm.

### 5. 537-byte footer

The earlier Windows build stored the encryption ratio in one byte and appended 534 bytes. The beta builder expands that field to four bytes, increasing the footer by three bytes to 537. The footer continues to carry RSA-protected ChaCha8 recovery material, encryption type/ratio information and original file size.

```text
earlier build: RSA-protected material + 1-byte mode + 1-byte ratio + 8-byte size = 534 bytes
beta revision: same logical fields, ratio expanded to 4 bytes                  = 537 bytes
```

The 537-byte layout is also consistent with the victim-specific Windows decryptor S2W analyzed for `.RNP` files. That decryptor and the beta report establish a real layout revision; 534 and 537 must not be treated as interchangeable offsets.

### 6. Linux, NAS, RHEL and ESXi outputs

S2W reported the Linux, NAS, RHEL and ESXi outputs as sharing configuration decryption and encryption logic with the Windows core. The Linux path parses arguments, optionally daemonizes with `-d`, initializes logging and delay, collects system information, encrypts selected content, encodes filenames and modifies the message-of-the-day file.

The ESXi output adds VM shutdown and collection of ESXi environment/user data. Those virtualization functions are absent from the NAS and RHEL outputs. This is the first public analysis in the dossier that supports NAS and RHEL as generated platform variants rather than only as service advertising, but it does not expose enough sample-level detail to assign unique hashes or recovery offsets.

### 7. Affiliate-panel and recovery implications

Each client record binds victim, ransom, build creator, negotiation state, leak size and publication status. Earlier Group-IB reporting also describes a configurable payment/test-decrypt period and automatic delivery of victim-specific files. Keys are client-specific; neither a recovered beta config nor a decryptor from another victim supplies a universal recovery key.

The panel supports delegated team accounts and access rights. A generated binary can therefore be operated by an affiliate team while the builder, negotiation and publication infrastructure remains service-controlled. Binary attribution should record the payload lineage, the client-specific configuration and the intrusion affiliate separately.

## Linking Host Activity to the Executable

A defensible beta-revision assessment combines:

1. a Conti-derived DragonForce binary or exact sample lineage;
2. decoded configuration containing `encryption_rules`;
3. per-extension mode behavior that overrides normal size selection;
4. encrypted files with a structurally valid 537-byte footer;
5. a configured DragonForce/RansomBay note, suffix or negotiation value;
6. process termination, share traversal or impact activity from the same executable.

Footer length alone is insufficient. The victim-specific `.RNP` recovery branch also reads 537 bytes, and compatible code may appear in white-label builds. Pair the layout with configuration, process behavior and note/recovery context.
