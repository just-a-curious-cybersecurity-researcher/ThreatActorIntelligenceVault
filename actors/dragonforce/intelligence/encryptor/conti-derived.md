# DragonForce — Conti-Derived Windows Encryptor

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

This file reconstructs the execution flow of the 534-byte-footer Windows branch analyzed by S2W. The principal sample is MD5 `ada4e228e982a7e309bb6a3308e4872d`, SHA-256 `451a42db9c514514ab71218033967554507b59a60ee1fc3d88cbeb39eec99f20`. A second API-resolving variant is `410db536a57c511b0ccac2639e0eb3320f303fc5c90242379ab43364c51ef321`. The code derives from Conti lineage but uses DragonForce configuration, note and branding. The later [RansomBay builder revision](panel-builder-beta.md) is documented separately.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Conti-derived DragonForce, 2024 onward | Windows PE; Conti-derived multithreaded encryptor | ChaCha8 config/files, RSA-4096 metadata protection, fixed mutex in analyzed sample, local/network modes, `.dragonforce_encrypted` | Detailed thresholds and artifacts apply to analyzed build |
| API-resolving variant | Windows PE with runtime API resolution | MurmurHash2-style API lookup and obfuscated strings | Same family evidence; exact behavior must be confirmed per sample |
| Victim-customized RNP build | Windows PE from affiliate builder | `.RNP` extension and victim-specific keys | Suffix reflects configuration, not a new algorithm by itself |
| RansomBay beta revision | Windows/Linux panel output | Adds `encryption_rules`; expands ratio field and footer to 537 bytes | Same Conti-derived core with a revised configuration/metadata layout |

## Executable Analysis

### 1. String and configuration preparation

The program does not expose its operational strings and configuration as plain text. It decodes custom-obfuscated strings as needed and decrypts an embedded configuration with ChaCha8. Some builds resolve Windows APIs by hashing names rather than importing them directly, reducing stable strings and import-table visibility.

The decrypted configuration controls local/network scope, filename encryption, note data, process/service targets, wallpaper/icon changes, logging and task behavior. Consequently, two binaries from the same branch can have different visible artifacts.

The default log path in the analyzed configuration was `C:\Users\Public\log.log`. Logging occurs even without a `-log` argument. When `-log [path]` is supplied, the selected log is encrypted with ChaCha8. Plain log entries use the format `[HH:MM:SS] [Th: <Thread ID>] Message`, so the default file can expose decoded configuration and progress information.

The sample supports five runtime arguments, including `-m`, `-log` and `-nomutex`. The `-m` selector exposes four modes; `all`, `net` and `local` produce active target sets, while the reported `backups` mode did not execute a separate routine in the analyzed sample. That inert branch is preserved as a build-specific observation rather than claimed as backup deletion.

The configuration also creates a random eight-byte `instance_key` and writes it to the log, but the analyzed code does not otherwise consume it. S2W proposed a possible relationship with the negotiation SID; no direct use was demonstrated, so the value should not be treated as a recovery key.

### 2. Single-instance guard

The analyzed build creates mutex `hsfjuukjzloqu28oajh727190`. If creation indicates another instance already owns it, the process exits instead of starting a second encryption pass. The mutex is inherited from Conti lineage and can therefore collide with related/reused code.

Host-level meaning:

```text
CreateMutex("hsfjuukjzloqu28oajh727190")
  -> newly created: continue
  -> already exists: terminate current instance
```

### 3. Privilege and scheduled execution

The executable checks whether it is elevated. When the relevant configuration is enabled, it creates a scheduled task under SYSTEM. If a task with the selected name exists, it replaces it before launching the privileged path. This gives defenders three connected events: task deletion/creation, SYSTEM task start and the encryptor’s file activity.

The task name is configurable and should not be converted into a family-wide IOC. Hunt for an uncommon executable registered to run as SYSTEM immediately before high-volume file modification.

### 4. Security and application process termination

The binary has two termination paths.

**Driver path.** It can deploy/load `truesight.sys` or `rentdrv2.sys` and communicate with the device through `DeviceIoControl` to kill processes that resist user-mode termination. The observed control codes were `0x22E044` for `truesight.sys` and `0x22E010` for `rentdrv2.sys`. This is BYOVD: a legitimately signed but vulnerable driver supplies kernel capability.

**User-mode path.** It calls `NtQuerySystemInformation` to enumerate processes, compares names against the decrypted configuration and calls process-termination APIs. Published targets include Microsoft Defender, database engines, backup software and Office applications. The practical goals are to impair defenses and release locked data files.

Event mockup:

```text
[locker]
  -> write/load vulnerable driver
  -> open driver device
  -> DeviceIoControl(target PID)
  -> security/database process exits
  -> encryption worker opens previously locked files
```

Driver load telemetry is more useful than a filename alone. Capture file hash, signer, service key, device name and the initiating process.

### 5. Recovery inhibition

The code enumerates shadow-copy objects through WMI and can start a WMIC child process to delete them. The distinction matters: an EDR may show COM/WMI activity without a visible `vssadmin.exe` command, or may show the WMIC child depending on build and code path.

```text
[locker] -> WMI query for shadow-copy instances
[locker] -> [optional WMIC child] shadowcopy delete
```

The branch can also change desktop and file-icon settings, but those are impact presentation rather than recovery inhibition.

### 6. Local and network target construction

Local mode enumerates mounted drives and directory trees. Network mode reads the ARP table, selects private-address candidates, tests TCP/445 and calls `NetShareEnum` against reachable hosts. `ADMIN$` is excluded; eligible user/data shares are queued.

The worker count is calculated separately. “All” mode uses the logical processor count, while dedicated local or network operation uses approximately twice that count in the analyzed implementation. The thread model explains a sudden fan-out of file operations and SMB connections from one process.

### 7. Exclusion handling

Before encryption the program compares paths, names and extensions with decrypted exclusion lists. System-critical content, the note and already-encrypted files are skipped. Database file extensions receive special treatment because unlocked database content is high value: the analyzed build forced full encryption for configured database types even when large-file partial processing was enabled.

### 8. Key generation and encryption mode

For every eligible file, the process obtains fresh key/nonce material through `CryptGenRandom` and encrypts data with ChaCha8. It then protects the per-file recovery material with the embedded RSA-4096 public key.

Three modes are available:

- **Full:** encrypt all content. The analyzed build used this below roughly 2 MB and for selected database extensions.
- **Header:** encrypt the beginning of the file. The published analysis describes the first 3 MB for the applicable range.
- **Partial:** encrypt three distributed regions in a large file, preserving gaps to improve speed. Each chunk is `(file size / 100) * ratio`; the two skipped intervals are `(file size - (chunk size * 3)) / 2`.

The sample used approximately 2 MB and 10 MB decision thresholds. These are configuration/build facts, not universal family constants.

The per-file flow is:

```text
open eligible file
generate ChaCha8 key + nonce
select full / header / partial mode
encrypt selected byte ranges
RSA-4096-wrap recovery material
append mode + ratio + original-size metadata
rename using configured filename policy and extension
```

### 9. Footer and recovery metadata

S2W describes 534 bytes appended to each Windows-encrypted file:

- 524 bytes of RSA-protected recovery material;
- one byte identifying encryption mode;
- one byte carrying the partial-encryption ratio/configuration;
- eight bytes storing original file size.

Mode values in the analyzed branch were `0x24` for full, `0x25` for partial and `0x26` for header encryption. The footer is required by the decryptor to recover key material and reconstruct the original length.

The victim-specific `.RNP` Windows decryptor reads 537 bytes, and S2W later confirmed that the RansomBay beta builder expanded the ratio field from one to four bytes, producing that 537-byte layout. ESXi recovery analysis uses an additional eight-byte build key plus a 512-byte protected metadata region. Analysts should parse by branch/sample and validate offsets, not force one size across all builds.

### 10. Filename transformation

When `encrypt_file_name` is enabled, the original name is encoded with a custom Base32 alphabet:

```text
gwfn6l3bk45o2zecvi7xtyqrpsudmahj
```

The configured extension is then appended. `.dragonforce_encrypted` is documented for the principal build; `.RNP` appears in a victim-specific build. If filename encoding is disabled, the original base name may remain with only the suffix added.

### 11. Note, icon and wallpaper

The binary writes the configured ransom note into processed directories. Optional visual behavior creates `C:\Users\Public\icon.ico` and `wallpaper_white.png`, associates the encrypted extension with the custom icon under HKCR/HKCU and changes wallpaper values beneath the current user SID. Published registry settings used wallpaper style `10`.

These artifacts are valuable because they tie file impact to the encryptor even after the original binary is deleted. They are optional builder features.

### 12. Decryption implications

S2W produced a victim-specific decryptor from leaked recovery material. It is not a universal key. The decryptor must identify the encryption mode, unwrap file key material with the corresponding victim private key, decrypt the correct ranges and truncate the appended footer. A valid footer without the matching private key does not provide general recovery.

Published decryptor hashes: MD5 `a368564c74d7f288fa01e4c7241082fe`, SHA-256 `dc7e706587d4897789cc4a5f7cccbb539646b58aa9c86272728c8c1e6ec2a529`. It is a recovery utility, not an encryptor, and is labeled separately in the IOC register.

## Linking Host Activity to the Executable

A high-confidence Conti-derived sequence contains several of:

1. The mutex appears in memory/handle telemetry.
2. `C:\Users\Public\log.log`, icon or wallpaper artifacts are written by the same process.
3. A SYSTEM scheduled task is created or replaced for an uncommon PE.
4. `truesight.sys`/`rentdrv2.sys` loads and protected processes terminate, or the locker directly terminates configured names.
5. WMI shadow-copy enumeration/deletion occurs.
6. One process scans private hosts on TCP/445 and enumerates shares.
7. File writes expand across local and network paths with `.dragonforce_encrypted` or a victim-specific suffix.
8. Encrypted files end with a footer consistent with the build and mode marker.

This behavior is more discriminating than the DragonForce brand string. Conti-derived reuses require the mutex/footer/configuration combination plus a DragonForce note or exact hash before family attribution.
