# LockBit — Encryptor Analysis Index

**Presentation reviewed:** 2026-09-22.

## Scope

This directory replaces the single `intelligence/encryptor.md` used by the other ransomware actors. Each document retains its section order and variant-register columns while separating the major LockBit branches.

Analyses summarize published sample examination and distinguish executable internals from affiliate scripts. No malware was downloaded or executed. References are centralized in the actor's [source register](../../References.md).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| [Original / ABCD](lockbit-1.md), 2019–2020 | Windows | Original suffixes; evolving elevation and file processing | A 2020 analysis does not describe every 2019 sample |
| [Red / 2.0](lockbit-2.md), 2021 | Windows and separate Linux-ESXi Locker | Automated deployment capabilities; StealBit service tooling | Separate operator scripts, transfer client and encryptor |
| [Black / 3.0](lockbit-3.md), 2022 onward | EXE and DLL output forms | Password gating and configurable impact; leaked builder | Family membership is insufficient for organizational attribution |
| [Green](lockbit-green.md), early 2023 | Conti-derived branch | Alternative lineage offered alongside Black | Date and sample resolve later reuse of the Green label |
| [NG-Dev](lockbit-ng-dev.md), 2024 | .NET / possible CoreRT | Date-window configuration and per-extension modes | Distinct from the native 2025 samples |
| [Possible 4.0 impostors](lockbit-4-impostors.md), 2024 | Unit 42's five Windows artifacts | Separate note/payment artifacts | Identification note, not a fabricated binary disassembly |
| [Native 4.0](lockbit-4.md), 2025 | Windows sample sets | Quiet operation, API hashing and direct log clearing | Different researchers analyze different builds |
| [5.0](lockbit-5.md), 2025–2026 | Windows, Linux and ESXi | Cross-platform updates and visibility controls | 16-hex output alone is not exclusive to this version |

## Executable Analysis

Read the branch matching the recovered hash, executable format and configuration. Each analysis follows initialization, preparation, file processing and output where supported, with API names and non-executable event mockups.

The expanded narratives cover loader and configuration handling, privilege context, process/service interaction, file selection and worker scheduling, symmetric encryption, protection of recovery material, partial-processing modes and final artifacts. Windows, Linux and ESXi routines are separated within the relevant branches. Diagrams distinguish selected file ranges and key-protection layers without turning them into executable implementations.

The original branch explains its AES/RSA hierarchy and footer; Red follows completion states and separates share access from deployment. Green compares size policies and conflicting sample descriptions. NG-Dev follows configuration decisions and name/key handling. Native 4.0 details worker pools and file-layout differences; 5.0 separates Windows VSS/key handling from Linux startup and ESXi's two-stage processing. The possible-impostor entry remains an identification document.

The [operations lifecycle](../operations.md) explains how affiliates obtain access, establish a foothold, gather credentials, discover the environment, move between hosts, maintain access and prepare deployment. These intrusion activities are distinct from routines observed inside the encryptor.

Major corrections to the supplied narrative are recorded in [source review](../source-review.md): early UAC behavior, Black note/suffix conventions, NG-Dev lineage, sample-specific cryptography, 4.0 output and the separate 2024 possible-impostor set.

## Linking Host Activity to the Executable

A child command inherits a parent process in telemetry; an internal API call may have no corresponding command line. An affiliate script can perform the same administrative action as the binary. Correlate process identity and creation time, code/image evidence, service and task records, and the resulting files.

Use [KQL](../../detections/KQL.md), [Splunk](../../detections/Splunk.md) and the [YARA inventory](../../detections/Detections.md#yara-coverage) to pivot from host observations. Hunting matches support triage; they do not automatically attribute the incident to the LockBit service.
