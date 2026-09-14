# APT28 — Microsoft Defender XDR / KQL Hunting Queries

**Reviewed:** 2026-09-14. Published Microsoft queries are reproduced without changing their logic. No Defender backend was connected. The publisher uses TimeGenerated; verify the target schema, string escaping and FolderPath representation before execution. These are historical GooseEgg hunts, not attribution signatures.

## Coverage, Telemetry and Tuning Register

| Query family | Evidence | Required interpretation / false positives |
|---|---|---|
| Driver-store JavaScript modification | [A17](../References.md#a17), 2024-04-22 | DeviceFileEvents. Driver servicing can match |
| COM server / protocol registration | [A17](../References.md#a17), 2024-04-22 | DeviceRegistryEvents. Correlate with payload and process evidence |

## 1. Credential Access

See the published campaign hunts below and the [telemetry register](Detections.md); no new query is synthesized for this category.

## 2. Active Directory and Network Discovery

See the published campaign hunts below and the [telemetry register](Detections.md); no new query is synthesized for this category.

## 3. RMM / RAT and Remote Administration

See the published campaign hunts below and the [telemetry register](Detections.md); no new query is synthesized for this category.

## 4. Tunneling and C2

See the published campaign hunts below and the [telemetry register](Detections.md); no new query is synthesized for this category.

## 5. Defense Impairment / Evasion

See the published campaign hunts below and the [telemetry register](Detections.md); no new query is synthesized for this category.

## 6. Collection and Exfiltration

See the published campaign hunts below and the [telemetry register](Detections.md); no new query is synthesized for this category.

## 7. Recovery Inhibition

Not applicable to the documented espionage model; no ransomware query is supplied.

## 8. Ransomware Deployment / Impact

Not applicable to the documented espionage model; no ransomware query is supplied.

## 9. Multi-Stage Ransomware Correlation

Not applicable to the documented espionage model; no ransomware query is supplied.

## 10. Source-Linked Campaign Hunts

See the published campaign hunts below and the [telemetry register](Detections.md); no new query is synthesized for this category.

### 10.1 GooseEgg: driver-store modification

**Evidence:** [Microsoft original query](https://www.microsoft.com/en-us/security/blog/2024/04/22/analyzing-forest-blizzards-custom-post-compromise-tool-for-exploiting-cve-2022-38028-to-obtain-credentials/).

**Telemetry:** MDE DeviceFileEvents; driver-store file creation.

**Review / tuning:** Preserve the published query. Verify TimeGenerated availability and path escaping in the target backend; correlate with process history and approved software changes.

```kusto
DeviceFileEvents
  | where TimeGenerated > ago(60d) // change the duration according to your requirement
  | where ActionType == "FileCreated"
  | where FolderPath startswith "C:\Windows\System32\DriverStore\FileRepository\"
  | where FileName endswith ".js" or FileName == "MPDW-constraints.js"
```

### 10.2 GooseEgg: COM server registration

**Evidence:** [Microsoft](../References.md#a17), 2024-04-22.

**Telemetry:** MDE DeviceRegistryEvents; registry value changes.

**Review / tuning:** Preserve the published query. Verify TimeGenerated availability and path escaping in the target backend; correlate with process history and approved software changes.

```kusto
DeviceRegistryEvents
  | where TimeGenerated > ago(60d) // change the duration according to your requirement
  | where ActionType == "RegistryValueSet"
  | where RegistryKey contains "HKEY_CURRENT_USER\Software\Classes\CLSID\{026CC6D7-34B2-33D5-B551-CA31EB6CE345}\Server"
  | where RegistryValueName has "(Default)"
  | where RegistryValueData has "wayzgoose.dll" or RegistryValueData contains ".dll"
```

### 10.3 GooseEgg: protocol registration

**Evidence:** [Microsoft](../References.md#a17), 2024-04-22.

**Telemetry:** MDE DeviceRegistryEvents; registry value changes.

**Review / tuning:** Preserve the published query. Verify TimeGenerated availability and path escaping in the target backend; correlate with process history and approved software changes.

```kusto
DeviceRegistryEvents
  | where TimeGenerated > ago(60d) // change the duration according to your requirement
  | where ActionType == "RegistryValueSet"
  | where RegistryKey contains "HKEY_CURRENT_USER\Software\Classes\PROTOCOLS\Handler\rogue"
  | where RegistryValueName has "CLSID"
  | where RegistryValueData contains "{026CC6D7-34B2-33D5-B551-CA31EB6CE345}"
```
