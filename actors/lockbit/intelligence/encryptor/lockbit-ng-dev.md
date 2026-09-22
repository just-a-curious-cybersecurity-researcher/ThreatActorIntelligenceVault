# LockBit — LockBit-NG-Dev Executable

**Presentation reviewed:** 2026-09-22.

## Scope

Trend Micro published this development-sample analysis in 2024-02 around Operation Cronos. It is a .NET implementation, possibly compiled with CoreRT, rather than an established alias for every later 4.0 sample.

This is a synthesis of published reverse engineering, not a claim that malware was executed or independently disassembled for this repository. Destructive mockups describe events and are deliberately non-executable. Bibliographic provenance is centralized in [References](../../References.md#executable-analysis-provenance).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| NG-Dev / 2024-02 analysis | Windows .NET / possible CoreRT; MPRESS-packed sample | Date-gated JSON configuration; AES/RSA; per-extension encryption modes | Prospective 4.0 naming is an assessment, not demonstrated equivalence with 2025 native code |

## Executable Analysis

### Configuration-driven execution

#### 1. Unpacking and settings

After the packed layer is removed, the analyzed program decrypts its embedded JSON. The configuration contains the execution window, mutex identifier, public key, note settings, target filters and switches controlling service/process termination and recovery inhibition.

This makes configuration recovery central to explaining a run. A routine's existence does not mean its switch was enabled.

#### 2. Instance and date checks

The program uses the configured ID for its mutex, then checks whether the current date falls within its permitted interval. Expiry can stop a sample before encryption. The interpretation that the interval limits affiliate reuse is the vendor's assessment; the date comparison itself is observed behavior.

#### 3. Process and service preparation

The `StopProcesses` and `StopServices` settings control whether their corresponding lists are applied. Entries identify targets for termination or service stops. An empty or disabled list changes the visible host sequence without changing the branch identity.

#### 4. Shadow copies and Windows backups

The configuration separately controls shadow-copy removal and Windows backup removal. Trend's appendix shows PowerShell launching the respective administrative utilities. Its displayed shadow-copy command contains a spelling error in one argument, so the exact publication should not be silently “fixed” and treated as evidence of successful deletion.

```text
MOCK PROCESS TRACE — descriptive, not executable
ngdev-A -> powershell.exe -> vssadmin.exe [shadow-deletion request]
ngdev-A -> powershell.exe -> wbadmin.exe [backup-deletion request]
Expected evidence: parent/child records plus VSS or backup outcome records.
A launch request alone does not demonstrate that deletion succeeded.
```

#### 5. Selection, rename and encryption

The configuration chooses included or excluded files/directories and regular-expression filters. It can include network shares; accessing those shares is not equivalent to propagating a new executable to another machine.

Fast mode processes an initial portion, intermittent mode processes separated regions, and full mode covers the file. The supplied sample settings distinguish text files from CSV/SQL files. AES keys are generated per file and protected with the embedded RSA public key.

Optional random renaming preserves original-name information in the resulting file structure. The `locked_for_LockBit` suffix is a configuration value, not a universal fixed suffix for the service.

#### 6. File modes and the resulting bytes

Trend Micro specifies a default fast region of `0x1000` bytes, with `BufferSize` controlling extensions in `FastSet`. `Percent` and `Segmentation` govern intermittent processing; `FullSet` selects complete processing. The analyzed configuration places `.txt` in full mode and `.csv`/`.sql` in intermittent mode. These are the specimen's settings, not fixed rules for those formats across LockBit.

The inclusion switches change the meaning of the accompanying lists. A directory list cannot be interpreted as an exclusion list without reading its controlling flag. Regex-based selection introduces a further distinction between the displayed path and the matching expression. Recovering the JSON is therefore more informative than extracting a few recognizable directory strings.

Original-name storage also depends on the mode: the appendix describes name information appended in partially processed outputs and protected within the RSA-encrypted buffer for full mode. The JSON's RSA public key protects per-file AES material; it is not a password that an analyst can use to decrypt the content.

```text
MOCK CONTENT MAP — conceptual, not executable
Fast:         [changed initial region][remaining content]
Intermittent: [changed][remaining][changed][remaining]
Full:         [changed content across the complete file]
Output also retains mode-dependent name/key information.
```

This explains why visual inspection at a single offset can be misleading. Sampling only the end may miss an initial-region transformation; sampling only the start may overstate the damage to an intermittently processed file. A complete assessment records changed regions, whether the final metadata is present, and whether a valid pre-incident copy exists.

#### 7. Evaluating configuration as a sequence of decisions

Trend's configuration pairs `IncludeFiles` with `FileSet`, `IncludeDirectories` with `DirectoryList`, and `IncludeExtensions` with `NoneSet`. The controlling Boolean determines whether a list includes or excludes its members. Regex switches further change matching, while `SkipHiddenFiles` uses the hidden-file attribute.

Consider a directory whose name appears in the recovered JSON. That string alone says neither “encrypt this directory” nor “preserve this directory.” The corresponding inclusion flag must be evaluated first. Next, file and extension filters can alter which entries proceed. Only admitted files reach mode selection and transformation. A dot-prefixed Windows filename also does not, by itself, establish the hidden attribute used by this setting.

```text
MOCK CONFIGURATION WALK — descriptive, not executable
candidate path -> directory-list meaning -> file/name filters
selected file -> extension/mode selection -> chosen content regions
file context -> fresh symmetric material -> protected recovery material
output context -> configured name handling and note placement
```

This is a reading order for the published settings, not recovered source code or a precedence specification for overlapping expressions. It prevents interpreting every string in a configuration as a guaranteed target.

#### 8. Per-file secrets and name handling

The per-file AES material means that several outputs can belong to one run without sharing a single plaintext file key. RSA protection links the smaller recovery container to the embedded public key. A full-mode original name placed inside that protected buffer cannot be recovered merely by decoding a random suffix.

Name loss and content loss are separate problems. A recovered path from filesystem metadata can restore context without restoring the document; conversely, a usable backup can restore content while the original directory placement must be reconstructed elsewhere. Preserve the container and filesystem metadata together.

#### 9. Note placement and self-removal

Note content and destination are configurable. `DropNoteBeforeEncryption`, `DropNoteInEveryDirectory` and the specific-directory settings control different placement decisions. A setting can place notes before file encryption, so note creation alone does not establish that data was encrypted. A directory selected for a note is not automatically evidence that every file within it passed the encryption filters.

The cleanup path described in the appendix combines process termination and overwriting the payload's contents. A zeroed executable can be an effect of this routine, but backup restoration, cleanup tools and administrative truncation are alternatives.

The reported helper uses PowerShell and `fsutil` for this final phase. Zeroing file contents differs from removing its directory entry, and neither observation proves secure erasure of all historical copies. An extant zero-length or zero-filled path can coexist with earlier executable bytes in independent evidence.

```text
MOCK CLEANUP TRACE — descriptive, not executable
cleanup helper -> request termination of <payload PID>
cleanup helper -> request zeroing of <payload file>
```

## Linking Host Activity to the Executable

Correlate the exact NG-Dev hash and recovered configuration with the observed execution date, child processes and file output. Preserve the distinction between a published command string, a captured process invocation and a successful host-side effect.

Return to the [encryptor index](README.md).
