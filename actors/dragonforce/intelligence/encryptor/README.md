# DragonForce — Encryptor Analysis Index

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

DragonForce has used more than one ransomware code base. This index separates the early LockBit 3.0 builder derivative, the later Conti-derived Windows implementation, the 2026 RansomBay builder revision and the Linux/ESXi branch. The files describe binary behavior in execution order and preserve build-specific differences.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| [LockBit-derived](lockbit-derived.md), 2023–2024 | Windows PE produced from leaked LockBit 3.0 builder | LockBit-like arguments, Safe Mode and GPO options, fixed/removable/network targets, `.locked` in the analyzed build | Code similarity identifies lineage; customized samples do not prove LockBit operator involvement |
| [Conti-derived](conti-derived.md), 2024 onward | Windows PE reimplemented from Conti lineage | ChaCha8 configuration and file encryption, RSA-4096 key protection, three modes, Base32 names, 534-byte footer, BYOVD option | Detailed values belong to the analyzed build; affiliate builders can alter note, extension and configuration |
| [RansomBay panel builder revision](panel-builder-beta.md), observed 2026 | Windows PE and Linux ELF outputs | Per-extension mode overrides, four-byte ratio field, 537-byte footer; LockBit builder removed from panel | Core remains Conti-derived; panel revision and client configuration are separate from affiliate identity |
| [Linux / ESXi](linux-esxi.md), observed 2024 onward | ELF encryptor for Linux/VMware ESXi | `vim-cmd` VM enumeration/shutdown, `/vmfs/volumes` targeting, thread/delay configuration, `.dragonforce_encrypted` or `.RNP_esxi` | Linux and ESXi reports describe more than one build; metadata and suffixes are not universal |

S2W later confirmed panel-generated NAS and RHEL outputs share the Linux cryptographic core, but the public report does not expose enough sample-level detail for separate executable reconstructions.

## Executable Analysis

All branches follow the same operational objective but not the same internal code:

1. Load embedded or operator-supplied configuration.
2. Establish execution state and optional elevated/persistent context.
3. Impair recovery or security controls when the build/configuration enables it.
4. Select local, network or virtualization targets.
5. Avoid system-critical paths and files that could prevent the host from completing encryption or displaying the note.
6. Encrypt content using the branch-specific algorithm and mode.
7. rename affected files, write recovery metadata and create the note or visual artifacts.
8. Optionally remove the payload or leave operational logs.

The individual documents provide API-level and event-level detail. They do not assume that a command seen in one lineage exists in another.

## Linking Host Activity to the Executable

The strongest payload attribution combines:

- a published sample hash or branch-specific YARA match;
- process ancestry and command-line mode;
- mutex, scheduled task, driver or recovery-control events;
- branch-specific extension, note, wallpaper/icon or footer;
- a dense file-modification burst from the same executable;
- network-share or ESXi-management activity immediately before impact.

An extension or ransom note alone is insufficient because the service supports customization and white-label deployment. The [detection index](../../detections/Detections.md) implements behavior and exact-artifact hunts for each branch.
