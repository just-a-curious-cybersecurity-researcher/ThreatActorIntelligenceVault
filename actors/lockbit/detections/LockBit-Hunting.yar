/*
    Presentation reviewed: 2026-09-17.
    LockBit public sample rules and repository-authored artifact hunts.
    CISA_10478915_01..04: public CISA AA23-325A / MAR-10478915-1.v1 rules.
    CISA predicates and source metadata retained; indentation normalized,
    with the required pe import supplied at file scope.
    Remaining rules are local, unvalidated against a representative malware corpus.
    Hash matches identify files; heuristic matches require analyst review.
    Provenance and URLs: ../References.md. No malware was executed.
*/

import "pe"
import "hash"

rule CISA_10478915_01 : trojan installs_other_components
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10478915"
        date = "2023-11-06"
        last_modified = "20231108_1500"
        actor = "n/a"
        family = "n/a"
        capabilities = "installs-other-components"
        malware_Type = "trojan"
        tool_type = "information-gathering"
        description = "Detects trojan .bat samples"
        sha256 = "98e79f95cf8de8ace88bf223421db5dce303b112152d66ffdf27ebdfcdf967e9"
    strings:
        $s1 = { 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 7a 2e 74 78 74 }
        $s2 = { 72 65 67 20 73 61 76 65 20 68 6b 6c 6d 5c 73 79 73 74 65 6d 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73
        5c 65 6d }
        $s3 = { 6d 61 6b 65 63 61 62 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 61 2e 70 6e 67 20 63 3a 5c 77 69 6e 64
        6f 77 73 5c 74 61 73 6b 73 5c 61 2e 63 61 62 }
    condition:
        all of them
}

rule CISA_10478915_02 : trojan installs_other_components
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10478915"
        date = "2023-11-06"
        last_modified = "20231108_1500"
        actor = "n/a"
        family = "n/a"
        capabilities = "installs-other-components"
        malware_type = "trojan"
        tool_type = "unknown"
        description = "Detects trojan PE32 samples"
        sha256 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"
    strings:
        $s1 = { 57 72 69 74 65 46 69 6c 65 }
        $s2 = { 41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 }
        $s3 = { 6f 70 65 72 61 74 6f 72 20 63 6f 5f 61 77 61 69 74 }
        $s4 = { 43 6f 6d 70 6c 65 74 65 20 4f 62 6a 65 63 74 20 4c 6f 63 61 74 6f 72 }
        $s5 = { 64 65 6c 65 74 65 5b 5d }
        $s6 = { 4e 41 4e 28 49 4e 44 29 }
    condition:
        uint16(0) == 0x5a4d and pe.imphash() == "6e8ca501c45a9b85fff2378cffaa24b2" and pe.size_of_code == 84480 and all of
        them
}

rule CISA_10478915_03 : trojan steals_authentication_credentials credential_exploitation
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10478915"
        date = "2023-11-06"
        last_modified = "20231108_1500"
        actor = "n/a"
        family = "n/a"
        capabilities = "steals-authentication-credentials"
        malware_type = "trojan"
        tool_type = "credential-exploitation"
        description = "Detects trojan DLL samples"
        sha256 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
    strings:
        $s1 = { 64 65 6c 65 74 65 }
        $s2 = { 3c 2f 74 72 75 73 74 49 6e 66 6f 3e }
        $s3 = { 42 61 73 65 20 43 6c 61 73 73 20 44 65 73 63 72 69 70 74 6f 72 20 61 74 20 28 }
        $s4 = { 49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 45 78 }
        $s5 = { 46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 }
        $s6 = { 47 65 74 54 69 63 6b 43 6f 75 6e 74 }
    condition:
        uint16(0) == 0x5a4d and pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and pe.size_of_code == 56832 and all of
        them
}

rule CISA_10478915_04 : backdoor communicates_with_c2 remote_access
{
    meta:
        author = "CISA Code & Media Analysis"
        incident = "10478915"
        date = "2023-11-06"
        last_modified = "20231108_1500"
        actor = "n/a"
        family = "n/a"
        capabilities = "communicates-with-c2"
        malware_type = "backdoor"
        tool_type = "remote-access"
        description = "Detects trojan python samples"
        sha256 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"
    strings:
        $s1 = { 70 6f 72 74 20 3d 20 34 34 33 20 69 66 20 22 68 74 74 70 73 22 }
        $s2 = { 6b 77 61 72 67 73 2e 67 65 74 28 22 68 61 73 68 70 61 73 73 77 64 22 29 3a }
        $s3 = { 77 69 6e 72 6d 2e 53 65 73 73 69 6f 6e 20 62 61 73 69 63 20 65 72 72 6f 72 }
        $s4 = { 57 69 6e 64 77 6f 73 63 6d 64 2e 72 75 6e 5f 63 6d 64 28 73 74 72 28 63 6d 64 29 29 }
    condition:
        all of them
}

rule LOCKBIT_5_Published_Payloads_Exact
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "Published Windows and Linux-family 5.0 artifacts"
        origin = "repository-authored exact hash inventory"
        date = "2026-09-17"
    condition:
        filesize < 30MB and (
            hash.sha256(0, filesize) == "7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82" or
            hash.sha256(0, filesize) == "180e93a091f8ab584a827da92c560c78f468c45f2539f73ab2deb308fb837b38" or
            hash.sha256(0, filesize) == "4dc06ecee904b9165fa699b026045c1b6408cc7061df3d2a7bc2b7b4f0879f4d" or
            hash.sha256(0, filesize) == "90b06f07eb75045ea3d4ba6577afc9b58078eafeb2cdd417e2a88d7ccf0c0273" or
            hash.sha256(0, filesize) == "98d8c7870c8e99ca6c8c25bb9ef79f71c25912fbb65698a9a6f22709b8ad34b6" or
            hash.sha256(0, filesize) == "6d0166d181db1f6c381c3ff5fff4fe4106fbc17bc29316e3cf3f65136ee4803c"
        )
}

rule LOCKBIT_Black_Published_Payloads_Exact
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "Black published payloads; leaked-builder use prevents service attribution"
        origin = "repository-authored exact hash inventory"
        date = "2026-09-17"
    condition:
        filesize < 30MB and (
            hash.sha256(0, filesize) == "0d38f8bf831f1dbbe9a058930127171f24c3df8dae81e6aa66c430a63cbe0509" or
            hash.sha256(0, filesize) == "9a34909703d679b590d316eb403e12e26f73c8e479812f1d346dcba47b44bc6e" or
            hash.sha256(0, filesize) == "39c363d01fb5cd0ed3eeb17ca47be0280d93a07dda9bc0236a0f11b20ed95b4c" or
            hash.sha256(0, filesize) == "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce" or
            hash.sha256(0, filesize) == "391a97a2fe6beb675fe350eb3ca0bc3a995fda43d02a7a6046cd48f042052de5" or
            hash.sha256(0, filesize) == "506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51" or
            hash.sha256(0, filesize) == "742489bd828bdcd5caaed00dccdb7a05259986801bfd365492714746cb57eb55" or
            hash.sha256(0, filesize) == "a56b41a6023f828cccaaef470874571d169fdb8f683a75edd430fbd31a2c3f6e" or
            hash.sha256(0, filesize) == "b951e30e29d530b4ce998c505f1cb0b8adc96f4ba554c2b325c0bd90914ac944" or
            hash.sha256(0, filesize) == "c6cf5fd8f71abaf5645b8423f404183b3dea180b69080f53b9678500bab6f0de" or
            hash.sha256(0, filesize) == "d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee" or
            hash.sha256(0, filesize) == "f9b9d45339db9164a3861bf61758b7f41e6bcfb5bc93404e296e2918e52ccc10" or
            hash.sha256(0, filesize) == "fd98e75b65d992e0ccc64e512e4e3e78cb2e08ed28de755c2b192e0b7652c80a" or
            hash.sha256(0, filesize) == "f34dd8449b9b03fedde335f8be51bdc7f96cda29a2dde176c3db667ba0713c6f"
        )
}

rule LOCKBIT_Native_4_Published_Payloads_Exact
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "Native 2025 4.0 sample set"
        origin = "repository-authored exact hash inventory"
        date = "2026-09-17"
    condition:
        filesize < 30MB and (
            hash.sha256(0, filesize) == "563cd800e80253a7051ea8a1bd690d123cf7820c355addeeaaabaa227984d9cb" or
            hash.sha256(0, filesize) == "82d89a75d80e80e4be42c9eb79e401558c9fa3175648cd0c0467f2de1a07a908" or
            hash.sha256(0, filesize) == "3552dda80bd6875c1ed1273ca7562c9ace3de2f757266dae70f60bf204089a4a" or
            hash.sha256(0, filesize) == "20dd91f589ea77b84c8ed0f67bce837d1f4d7688e56754e709d467db0bea03c9" or
            hash.sha256(0, filesize) == "33376f74c2f071ff30bab1c2d19d9361d16ebaa3dee73d3b595f6d789c15f620" or
            hash.sha256(0, filesize) == "2f5051217414f6e465f4c9ad0f59c3920efe8ff11ba8e778919bac8bd53d915c" or
            hash.sha256(0, filesize) == "48e2033a286775c3419bea8702a717de0b2aaf1e737ef0e6b3bf31ef6ae00eb5" or
            hash.sha256(0, filesize) == "21e51ee7ba87cd60f692628292e221c17286df1c39e36410e7a0ae77df0f6b4b" or
            hash.sha256(0, filesize) == "9733092223c428fc0e44a90b01c7f77a97bb1205def8be1224ac68969182638e" or
            hash.sha256(0, filesize) == "a33f21d28bd83a9501257ee727c46486989bdfea6d5cb9f1c12c9a67296b21b1" or
            hash.sha256(0, filesize) == "0ace4e1158ab5b7723493f39d6949309e00e4a71804f0b09e33d5d48a28cb061" or
            hash.sha256(0, filesize) == "36f48ef3776c01d63a2fd594d52dfb7402ea634162fd079b0d942367a2fbed56" or
            hash.sha256(0, filesize) == "4f76df691e2ea292b56812eb3167efcab655382d632048ff63781f5d41f86433" or
            hash.sha256(0, filesize) == "67ac04c1b7526288194e53da33cc0e9661687fd4fbbf12156e5ef6dd2a4108eb"
        )
}

rule LOCKBIT_NGDev_Published_Sample_Exact
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "NG-Dev development sample; not a universal 4.0 identifier"
        origin = "repository-authored exact hash inventory"
        date = "2026-09-17"
    condition:
        filesize < 30MB and (
            hash.sha256(0, filesize) == "f56cba51a4e86f3be5208dfce598d0d6a86cbbc820b214d5d5df7d327e580b82"
        )
}

rule LOCKBIT_Possible_Impostors_2024_Exact
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "Unit 42 possible 4.0 impostor files; separate attribution"
        origin = "repository-authored exact hash inventory"
        date = "2026-09-17"
    condition:
        filesize < 30MB and (
            hash.sha256(0, filesize) == "0447c931bb8efc6dc531f69a891f2a0f28a85a18b25e04366fdb59bf827b2eb1" or
            hash.sha256(0, filesize) == "31208a2640c1f2806d21bb8b40abd47b24dd3be85dedb1fdb9f33dac47b23152" or
            hash.sha256(0, filesize) == "9b5f1ec1ca04344582d1eca400b4a21dfff89bc650aba4715edd7efb089d8141" or
            hash.sha256(0, filesize) == "b3a994f26b694fcfdc68e57fc6aeea2aa4b4906ff50b0319e00c693537a3b25c" or
            hash.sha256(0, filesize) == "f8935a295a316e15f60fadf465383f19cf881a42ba008ed1792cbeecb21580dc"
        )
}

rule LOCKBIT_Black_Builder_Resources_Exact
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "Black builder, key generator and embedded resources; mixed artifact roles"
        origin = "repository-authored exact hash inventory"
        date = "2026-09-17"
    condition:
        filesize < 30MB and (
            hash.sha256(0, filesize) == "a736269f5f3a9f2e11dd776e352e1801bc28bb699e47876784b8ef761e0062db" or
            hash.sha256(0, filesize) == "ea6d4dedd8c85e4a6bb60408a0dc1d56def1f4ad4f069c730dc5431b1c23da37" or
            hash.sha256(0, filesize) == "cc3d006c2b963b6b34a90886f758b7b1c3575f263977a72f7c0d1922b7feab92" or
            hash.sha256(0, filesize) == "03b8472df4beb797f7674c5bc30c5ab74e8e889729d644eb3e6841b0f488ea95" or
            hash.sha256(0, filesize) == "a0db5cff42d0ee0de4d31cff5656ed1acaa6b0afab07d19f9f296d2f72595a56" or
            hash.sha256(0, filesize) == "ae993930cb5d97caa5a95b714bb04ac817bcacbbf8f7655ec43e8d54074e0bd7"
        )
}

rule LOCKBIT_5_Note_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "LockBit 5.0-branded note content; branding does not prove actor"
        origin = "repository-authored heuristic"
        date = "2026-09-17"
    strings:
        $brand = "LockBit 5.0" ascii wide nocase
        $topic1 = "decrypt" ascii wide nocase
        $topic2 = "personal" ascii wide nocase
        $route = ".onion" ascii wide nocase
    condition:
        filesize < 256KB and $brand and all of ($topic*) and $route
}

rule LOCKBIT_Black_Note_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "LockBit 3.0-branded note context"
        origin = "repository-authored heuristic"
        date = "2026-09-17"
    strings:
        $brand = "LockBit 3.0" ascii wide nocase
        $topic = "decrypt" ascii wide nocase
        $route = ".onion" ascii wide nocase
        $id = "personal" ascii wide nocase
    condition:
        filesize < 256KB and all of them
}

rule LOCKBIT_NGDev_Configuration_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "NG-Dev configuration key cluster in extracted configuration or memory"
        origin = "repository-authored heuristic"
        date = "2026-09-17"
    strings:
        $a = "MinDate" ascii wide
        $b = "MaxDate" ascii wide
        $c = "DropNoteBeforeEncryption" ascii wide
        $d = "DirectoriesToDropNoteInRegexQueryString" ascii wide
        $e = "DeleteVolumeShadowCopies" ascii wide
    condition:
        filesize < 30MB and all of them
}

rule LOCKBIT_Impairment_Transfer_Script_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        description = "Generic recovery-impairment and transfer-script triage"
        origin = "repository-authored heuristic"
        date = "2026-09-17"
    strings:
        $r1 = "vssadmin" ascii wide nocase
        $r2 = "shadowcopy" ascii wide nocase
        $e1 = "wevtutil" ascii wide nocase
        $e2 = "DisableRealtimeMonitoring" ascii wide nocase
        $x1 = "rclone" ascii wide nocase
        $x2 = "StealBit" ascii wide nocase
    condition:
        filesize < 2MB and 1 of ($r*) and 1 of ($e*) and 1 of ($x*)
}
