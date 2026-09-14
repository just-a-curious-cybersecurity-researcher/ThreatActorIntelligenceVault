# APT28 — Splunk Hunting Queries

**Reviewed:** 2026-09-14. Published Splunk Security Content searches; requires Endpoint CIM data models and upstream macros. No connected Splunk backend was available.

## Coverage, Telemetry and Tuning Register

| Query family | Evidence | Required interpretation / false positives |
|---|---|---|
| Outlook macro / registry | [A50](../References.md#a50) through [A54](../References.md#a54) | NotDoor hunting context. Administrative changes can match; not actor attribution |

## 1. Credential Access

See the published searches in section 10 and the [telemetry register](Detections.md).

## 2. AD and Network Discovery

See the published searches in section 10 and the [telemetry register](Detections.md).

## 3. RMM / RAT

See the published searches in section 10 and the [telemetry register](Detections.md).

## 4. Tunneling / C2

See the published searches in section 10 and the [telemetry register](Detections.md).

## 5. Defense Impairment

See the published searches in section 10 and the [telemetry register](Detections.md).

## 6. Collection / Exfiltration

See the published searches in section 10 and the [telemetry register](Detections.md).

## 7. Recovery Inhibition

Not applicable to the documented espionage model.

## 8. Ransomware Deployment / Impact

Not applicable to the documented espionage model.

## 9. Multi-Stage Detection Strategy

See the published searches in section 10 and the [telemetry register](Detections.md).

## 10. Source-Linked Campaign Hunts

See the published searches in section 10 and the [telemetry register](Detections.md).

### 10.1 Outlook macro security modified

**Evidence:** [windows_outlook_macro_security_modified](https://raw.githubusercontent.com/splunk/security_content/develop/detections/endpoint/windows_outlook_macro_security_modified.yml). Retrieved 2026-09-14. Preserve the publisher macros and tune their filters to local administration.

**Telemetry:** Endpoint.Registry CIM; registry changes such as Sysmon Event 13.

**Review / tuning:** Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Upstream limitations are retained below.

```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry WHERE Registry.registry_path="*\\Outlook\\Security*" Registry.registry_value_name="Level" Registry.registry_value_data="0x00000001" by Registry.action Registry.dest Registry.process_guid Registry.process_id Registry.registry_hive Registry.registry_path Registry.registry_key_name Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type Registry.status Registry.user Registry.vendor_product | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_outlook_macro_security_modified_filter`
```

### 10.2 Outlook macro created by suspicious process

**Evidence:** [windows_outlook_macro_created_by_suspicious_process](https://raw.githubusercontent.com/splunk/security_content/develop/detections/endpoint/windows_outlook_macro_created_by_suspicious_process.yml). Retrieved 2026-09-14. Preserve the publisher macros and tune their filters to local administration.

**Telemetry:** Endpoint.Filesystem CIM; file creation such as Sysmon Event 11.

**Review / tuning:** Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Upstream limitations are retained below.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_create_time) as file_create_time from datamodel=Endpoint.Filesystem where Filesystem.file_path="*Appdata\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM" by Filesystem.action Filesystem.dest Filesystem.file_access_time Filesystem.file_create_time Filesystem.file_hash Filesystem.file_modify_time Filesystem.file_name Filesystem.file_path Filesystem.file_acl Filesystem.file_size Filesystem.process_guid Filesystem.process_id Filesystem.user Filesystem.vendor_product | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_outlook_macro_created_by_suspicious_process_filter`
```

### 10.3 Outlook loadmacroprovideronboot persistence

**Evidence:** [windows_outlook_loadmacroprovideronboot_persistence](https://raw.githubusercontent.com/splunk/security_content/develop/detections/endpoint/windows_outlook_loadmacroprovideronboot_persistence.yml). Retrieved 2026-09-14. Preserve the publisher macros and tune their filters to local administration.

**Telemetry:** Endpoint.Registry CIM; registry changes such as Sysmon Event 13.

**Review / tuning:** Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Upstream limitations are retained below.

```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry WHERE Registry.registry_path="*\\Outlook\\*" Registry.registry_value_name="LoadMacroProviderOnBoot" Registry.registry_value_data="0x00000001" by Registry.action Registry.dest Registry.process_guid Registry.process_id Registry.registry_hive Registry.registry_path Registry.registry_key_name Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type Registry.status Registry.user Registry.vendor_product | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_outlook_loadmacroprovideronboot_persistence_filter`
```

### 10.4 Outlook dialogs disabled from unusual process

**Evidence:** [windows_outlook_dialogs_disabled_from_unusual_process](https://raw.githubusercontent.com/splunk/security_content/develop/detections/endpoint/windows_outlook_dialogs_disabled_from_unusual_process.yml). Retrieved 2026-09-14. Preserve the publisher macros and tune their filters to local administration.

**Telemetry:** Endpoint.Registry CIM; registry changes such as Sysmon Event 13.

**Review / tuning:** Requires publisher macros and CIM field mapping. Baseline approved Outlook policies and macros; correlate with the creating process. Upstream limitations are retained below.

```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry WHERE Registry.registry_path="*\\Outlook\\Options\\General*" Registry.registry_value_name="PONT_STRING" by Registry.action Registry.dest Registry.process_guid Registry.process_id Registry.registry_hive Registry.registry_path Registry.registry_key_name Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type Registry.status Registry.user Registry.vendor_product | `drop_dm_object_name(Registry)`| join process_guid [| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes WHERE NOT (Processes.process_name = "Outlook.exe") by _time span=1h Processes.action Processes.dest Processes.original_file_name Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path Processes.process Processes.process_exec Processes.process_guid Processes.process_hash Processes.process_id Processes.process_integrity_level Processes.process_name Processes.process_path Processes.user Processes.user_id Processes.vendor_product | `drop_dm_object_name(Processes)`] | fields _time parent_process_name parent_process process_name process_path process process_guid registry_path registry_value_name registry_value_data registry_key_name action dest user | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_outlook_dialogs_disabled_from_unusual_process_filter`
```

**Upstream limitations:** the macro-security search formats firstTime/lastTime without aggregating them. The macro-created search selects a macro path without an ancestry predicate despite its title. Investigate process provenance separately. Queries retain their published logic; no local repairs or actor attribution predicates were introduced.
