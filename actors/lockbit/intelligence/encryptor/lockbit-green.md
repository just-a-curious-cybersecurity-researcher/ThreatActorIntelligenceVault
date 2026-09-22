# LockBit — LockBit Green Branch

**Presentation reviewed:** 2026-09-22.

## Scope

Green refers here to the Conti-derived branch reported in early 2023. Later authors also use “Green” for some 2025 4.0 samples; those labels must be resolved by date and sample, not silently treated as either identical or necessarily unrelated.

This is a synthesis of published reverse engineering, not a claim that malware was executed or independently disassembled for this repository. Destructive mockups describe events and are deliberately non-executable. Bibliographic provenance is centralized in [References](../../References.md#executable-analysis-provenance).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Green / early 2023 | Conti-derived Windows encryptor | Reuse of a different code lineage alongside Black | A source's Green label requires a publication date and sample anchor |

## Executable Analysis

### Branch selection

The service's adoption of Conti-derived code provided an alternative encryption product. The international advisory records Green alongside Red, Black and the Linux-ESXi Locker rather than describing a clean replacement of all other branches.

This changes what an analyst should compare. A Green-labelled binary should first be checked against the relevant Conti-derived sample lineage; Black's password gate, COM sequence and builder resources cannot simply be copied into its analysis.

### File processing and output

Public reporting describes a modified encryptor rather than a new initial-access system. The payload acts on accessible files; credentials, remote execution and exfiltration remain separate intrusion stages. A LockBit-branded note can accompany code inherited from another family.

Record the recovered executable, configuration, encrypted-file structure and emitted note together. A note colour or the word “Green” in a marketing article is insufficient to select a cryptographic implementation.

#### 1. Initialization, process discovery and target selection

Sangfor's `LBG64.malz` analysis describes runtime API resolution, the shared mutex `hsfjuukjzloqu28oajh727190`, drive enumeration and process snapshots. `CreateToolhelp32Snapshot`, `Process32FirstW` and `Process32NextW` enumerate processes; the article's description of the latter functions as directory traversal is incorrect. The mutex is also reported in Conti-related samples and is not unique attribution evidence.

The sample examines SMB-accessible resources and excludes selected system paths, executable extensions and its own note. Reachable shares are file targets; their enumeration alone does not demonstrate execution on another host. Shadow-copy removal is described through a child WMIC process.

#### 2. File transformation and output

Sangfor reports full-file, selected-block and initial-1-MiB modes, chosen by file size/type, and describes AES-256 with XChaCha20. That algorithm description remains attributed to this sample report; it is not a verified cryptographic specification for every Conti-derived Green build. The displayed output uses `.fb7c204e` and `!!!-Restore-My-Files-!!!.txt`.

Those modes produce different observable damage. Full-file processing transforms the whole content; selected-block processing leaves readable intervals; first-region processing concentrates damage near the start. All can make a file unusable. The extent of encryption and the importance of the affected region are separate measurements: a small changed fraction can still contain a database's essential metadata.

```text
MOCK FILE-EVENT SEQUENCE — descriptive, not executable
green-A -> initialize resolved APIs -> check instance mutex
green-A -> discover volumes/shares -> apply exclusions
green-A -> request shadow-copy removal through a child process
worker-B -> select full / block / initial-region handling for <file>
worker-B -> modify file -> append sample-specific suffix
```

The sequence describes the published capabilities, not a guaranteed order on every machine. Process discovery also does not establish that every enumerated process was terminated. An analyst should connect a specific termination to its caller and compare the affected files with that process's open resources.

#### 3. Size-dependent regions in EQST's early Green comparison

EQST's March 2025 retrospective describes full processing below 1 MiB and an initial 1 MiB region for files from 1–5 MiB. Above 5 MiB, its examined early Green implementation selects either beginning/middle/end regions or percentage-controlled blocks. The percentage switch actually selects a fixed 50% pattern, irrespective of the requested number.

The important distinction is between parsing an option and honoring its value. A recovered command line cannot establish the changed fraction without the implementation or an affected-file comparison. The following map illustrates region selection, not exact offsets for an arbitrary sample.

```text
MOCK REGION MAP — conceptual, not executable
small file        [entire content selected]
medium file       [initial region selected][remaining content]
large file        [selected][remaining][selected][remaining][selected]
```

Processing fewer bytes shortens the amount of work per large file. It does not guarantee that the unmodified intervals remain independently usable: application indexes can refer to structures in the changed intervals.

#### 4. Key handling: two reports with different descriptions

EQST describes a 32-byte ChaCha20 key, RSA protection and tail metadata for early Green. Sangfor instead reports AES-256 and XChaCha20. These descriptions are not combined into an invented multi-cipher pipeline. Each remains attached to its analyzed sample/report; the Green label alone cannot resolve the discrepancy.

In either description, content transformation and protection of recovery material have different roles. A public asymmetric key protects a small secret rather than efficiently replacing every byte of a large virtual disk. Identifying an asymmetric primitive in a PE therefore does not establish that it is the bulk file cipher.

#### 5. Selection artifacts and option behavior

EQST's early sample excludes `CONTI_LOG.txt`, its note and selected executable extensions. Its mutex-disabling behavior is effectively unconditional. This qualifies the earlier mutex description: the presence of a known string does not prove that a running specimen enforces single-instance operation.

Exclusions are evaluated during selection; they do not undo a prior service stop or shadow-copy deletion. Conversely, an excluded executable can remain readable alongside damaged business data. This is consistent with keeping the operating environment functional while denying access to selected content.

### Relationship to 2025 4.0

The Singapore advisory calls its 2025 release 4.0 / Green, and Chuong Dong also uses Green when discussing the native 4.0 sample. This is a naming overlap in the literature. The earlier supplied note that this must simply be a labeling error is too strong.

The detailed native 2025 routine analysis is in [LockBit 4.0](lockbit-4.md). It remains separate from this early branch to avoid importing later API, footer and encryption details into a 2023 sample.

## Linking Host Activity to the Executable

Use sample-level similarity and output artifacts to establish the branch. The [variant index](README.md) separates naming periods; it is not a claim that the brand maintained a single linear source tree.

Return to the [encryptor index](README.md).
