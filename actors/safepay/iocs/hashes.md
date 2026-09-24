# SafePay — Hash Indicators

**Presentation reviewed:** 2026-09-24.

> Exact hashes support retrospective triage. They do not cover customized builds. The large KPMG/TEHTRIS/ThreatLocker sets are preserved as published, but most entries do not expose a precise component role.

## Windows Samples — SHA-256

```text
a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526
327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917
921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae
6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a
e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346
```

The first two are published SafePay Windows payloads. The last three are the QDoor loader, its embedded DLL and the PE injected into `WerFault.exe` in one NCC incident.

## All SHA-256 Values Collected

```text
0f23a313f79d54ae2102f193d3de1a6a98791c27921f28a4fab1092bcb43e5ee
12139246b8c5232d6d074df37acddc20f0bc233e42ed8eb00dfe2af5d3de3275
22df7d07369d206f8d5d02cf6d365e39dd9f3b5c454a8833d0017f4cf9c35177
241c3b02a8e7d5a2b9c99574c28200df2a0f8c8bd7ba4d262e6aa8ed1211ba1f
2f49bff45cc091a7bf52dcd061d24f9a7f2cf0ca9b3c12123bd3cf2fac56b481
625abbf876f256662f33a88c122bf787edf74b882c35adbd61562b5bd1b2ac27
654c11935448b3229434ec7d9d165a5f135ae4735d35700cffcb3b84f6a0fbc3
7f33c939f7aaf46945d58ed7fd0d1f5c7e3de1ff6a1a591ecc1992dab2a65078
94244ec2480addeaebb43aebbe48cee94f7f429231aa054f4c26f671653163b0
961346470d15d7795c5e35bc90c17d293fba7a8b811f8f5c26a3dc7c971cdc4e
b3045308a07e46c9f7dd98d352e964f242307ce30df8087dc751488118b5b959
ba1b89023581a0bc7a75f8ede9ec6115d5dda98c0145634f1b98978fbc79c956
f0127e786c9fb7bf2c8c999202d95c977af4c26cc27302a6ee352cfd62869e7b
fa74ac0e05b6209b7691511572386f97464ff5728732de99ddd6b5449ffae386
fd509df74a8d6a9e96762337efd46280ebf8d154c6c5dfbac7b3e8f7bb61f191
```

KPMG publishes all fifteen values in a SafePay advisory. ThreatLocker independently publishes seven of them and TEHTRIS independently publishes eight. Because the public lists do not label each binary, treat them as SafePay-associated samples rather than assuming that every value is an encryptor.

Unique SHA-256 values in this dossier: **20**.

## SHA-1

```text
07353237350c35d6dc2c8f143b649cd07c71f62b
1df73fb6562cce58700ff3edd869023253682a74
254295e7d4273570bcbe84ee1fd7381e22fc0706
4278801d47b15c1e9ef94c28c599c3156fd65812
434b09fd983a212fc12bf44546d8963bf45490cc
4aca527bf665314cadf1ea7390194276de685258
4dfbab34896ab6389289d18f6becb15f6ff62d5d
4e7d4ee41a93cc8c849000b15b791b36c3a8cf9e
5152653cd4505b0de706890969ce659b1c7b8440
8ab2d8a24c06254274f7c03079034985f3b02c93
a634d72a6a85337d31d18a98b112bc7aa8967c41
ad9a2ac64e693ab0ad9a5492d6819a1f1f2e8dfa
b498a2683640c983bb069fa2ea9e67cef4a3797d
c2424478b809d787cc892e7f2ddb3d804b63f788
e08dd7fb682a4536ddbc7bf11b6700727b70cbdb
eb2189d4b64be97fe44eeb2b19b08e7a378f445b
eda6118782d9b4adb244af276372d10247374429
ffc5d071bb58fa7100e60e9a1c754e246332e9bf
```

NCC identifies `073532…f62b` as the incident artifact `1.exe`. KPMG publishes the complete set without per-value roles.

## MD5

```text
2df99337e665965660a1a28553df3cda
48db685ee0a34dba779a84d454b317aa
4b4b1a7e4fbb3357b62e86da706c5997
4f36a08e2004890d79b0e8a7fa3c0ec7
6b7f092ac6cd855f41d49348f5efe970
80261758bde39422b73f7856bfa142e0
892eeff88dcc97d53c43f292c1f325ed
a60d6cfee59a52de25a47f8630ce71fc
a6cf0f89f9c3f002ae15c44c9b0b1f1d
a92e8648403de30a64d654234a8094d8
b0242990818149de592f1dea3f7eb085
b96a4a7952eb04949257e7d8e43757ed
c044d55c71bda30d5983a14cf4d9fa64
cc61f920f85cd380bad8940453215a50
ccd708d9f80ec7af59a496c5e1396377
d1f621b82822b544153f6b531e51a611
e49ab917e87697835852c81c3954010c
```

These 17 MD5 values come from the KPMG advisory and have no public component-level labeling. Prefer SHA-256 where available.

No public Linux or ESXi SafePay sample was located. ESXi consoles and hypervisors were accessed in incident response, but this does not establish a native SafePay ESXi encryptor.

## Provenance and Newly Sourced Artifacts

| SHA256 | Observed role |
|---|---|
| `a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526` | Role-resolved SafePay Windows locker/DLL analyzed by several independent sources |
| `327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917` | SafePay Windows payload; public branch detail remains unresolved |
| `921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae` | QDoor `soc.dll` loader in one NCC SafePay intrusion |
| `6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a` | DLL embedded in the QDoor loader |
| `e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346` | QDoor final PE stage injected into `WerFault.exe` |

The other fifteen SHA-256 values remain exact advisory artifacts with unresolved component roles. Detailed source reconciliation is retained in [hash-provenance.md](hash-provenance.md).
