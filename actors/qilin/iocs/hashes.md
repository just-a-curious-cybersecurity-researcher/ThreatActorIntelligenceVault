# Qilin — Hash Indicators

**Presentation reviewed:** 2026-09-15.

The values below come from explicit publisher IOC sections. No malware was downloaded or executed. A valid hash is an exact-match pivot, not proof of current maliciousness or Qilin attribution. Source roles and uncertainty are preserved in the provenance table.

## Windows Samples — SHA-256

The December 2022 Agenda analysis publishes these Windows sample values. Only the third is specifically identified as the analyzed Rust sample here; the companion samples' precise branches are not inferred.

```text
37546b811e369547c8bd631fa4399730d3bdaff635e744d83632b74f44f56cf6
55e070a86b3ef2488d0e58f945f432aca494bfe65c9c4363d739649225efbbd1
e90bdaaf5f9ca900133b699f18e4062562148169b29cb4eb37a0577388c22527
```

## All SHA-256 Values Collected

```text
37546b811e369547c8bd631fa4399730d3bdaff635e744d83632b74f44f56cf6
55e070a86b3ef2488d0e58f945f432aca494bfe65c9c4363d739649225efbbd1
e90bdaaf5f9ca900133b699f18e4062562148169b29cb4eb37a0577388c22527
38ddde36929a2ddf13b1844973550072c41004187eaa2456f86e20aa93036b18
6ce228240458563d73c1c3cbbd04ef15cb7c5badacc78ce331848f5431b406cc
792182b7c5a56e5ccefd32073dc374e66c6a4e7981075e3804f49a276878e0fb
8fe746dd277e644fa0337db3394f0eadfafe57df029e13df9feef25c536adf4d
912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9
a068f595472c4f94baf1c2a8fba6831a327514e24ec4b38e1eee2cf1646b1591
d1347f4dccebf2fcd672dcef9c66c91b9d3f12b9881e3e390626927718fda616
dbe9ed8e8e8cdff3670e7205cb9f11b5a0fa9d1983a6c6bab67527d8775c4ffd
dd29138bf369863c33402a3fc995458ab5fc015a13a9378022131ab31d940c9f
e129dd5cc80f39b24db489df999c847335d169910bd966814d2f81b0b1bbc365
e705f69afd97f343f3c1f2bc6027d30935a0bfd29ff025c563f6f8c1f9a7478e
```

## Provenance and Newly Sourced Artifacts

| SHA256 | Observed role |
|---|---|
| `37546b811e369547c8bd631fa4399730d3bdaff635e744d83632b74f44f56cf6` | Agenda Windows samples from Rust-analysis IOC table; precise branch of unexamined companion samples unspecified; 2022-12-16 publication; Moderate Confidence in reported sample/case association |
| `55e070a86b3ef2488d0e58f945f432aca494bfe65c9c4363d739649225efbbd1` | Agenda Windows samples from Rust-analysis IOC table; precise branch of unexamined companion samples unspecified; 2022-12-16 publication; Moderate Confidence in reported sample/case association |
| `e90bdaaf5f9ca900133b699f18e4062562148169b29cb4eb37a0577388c22527` | Agenda Windows samples from Rust-analysis IOC table; precise branch of unexamined companion samples unspecified; 2022-12-16 publication; High Confidence in analyzed Rust sample |
| `38ddde36929a2ddf13b1844973550072c41004187eaa2456f86e20aa93036b18` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `6ce228240458563d73c1c3cbbd04ef15cb7c5badacc78ce331848f5431b406cc` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `792182b7c5a56e5ccefd32073dc374e66c6a4e7981075e3804f49a276878e0fb` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `8fe746dd277e644fa0337db3394f0eadfafe57df029e13df9feef25c536adf4d` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `a068f595472c4f94baf1c2a8fba6831a327514e24ec4b38e1eee2cf1646b1591` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `d1347f4dccebf2fcd672dcef9c66c91b9d3f12b9881e3e390626927718fda616` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `dbe9ed8e8e8cdff3670e7205cb9f11b5a0fa9d1983a6c6bab67527d8775c4ffd` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `dd29138bf369863c33402a3fc995458ab5fc015a13a9378022131ab31d940c9f` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `e129dd5cc80f39b24db489df999c847335d169910bd966814d2f81b0b1bbc365` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |
| `e705f69afd97f343f3c1f2bc6027d30935a0bfd29ff025c563f6f8c1f9a7478e` | Talos Qilin case artifact; individual encryptor/tool role not specified in companion list; 2025 cases; October publication; Moderate Confidence in reported sample/case association |

Talos publishes eleven case hashes without individual functional labels. Legitimate utilities and supporting malware may occur alongside encryptors; these values are not all asserted to identify ransomware binaries.

Reviewed **2026-09-11**; original source dates remain unchanged. [Named Artifacts](file-artifacts.md) and [Behavioral Hunts](../detections/Detections.md) provide complementary context.
