/*
    Presentation reviewed: 2026-09-24.
    Includes two public Google Threat Intelligence Group rules reproduced with attribution,
    plus repository-authored exact-hash and artifact-triage rules.
    Source and sample provenance: ../References.md and ../iocs/hash-provenance.md.
    Research documents and incident notes can match text rules; inspect file context.
*/

import "pe"
import "hash"

rule G_Ransom_SAFEPAY_1
{
    meta:
        author = "Google Threat Intelligence Group (GTIG)"
        source = "SP013"
        publication_date = "2026-03-16"
    strings:
        $hex_asm_snippet = { 10 27 00 00 [0-4] 10 27 00 00 }
    condition:
        pe.imphash() == "ff67c703589f775db9aed5a03e4489b0" and ($hex_asm_snippet)
}

rule G_Ransom_SAFEPAY_2
{
    meta:
        author = "Google Threat Intelligence Group (GTIG)"
        source = "SP013"
        publication_date = "2026-03-16"
    strings:
        $code_string_decode = { 8A C2 32 C1 32 44 0D ?? 34 ?? 88 44 0D ?? 41 83 F9 04 [4-64] B? 4D 5A 00 00 }
        $code_hardware_aes_check = { 0F A2 8B F3 5B 89 07 89 77 ?? 89 4F ?? 89 57 [0-12] ( 00 00 00 02 | C1 ?? 19 ) }
        $code_encrypt_file = { 14 00 10 00 [2-24] 14 00 10 00 [2-32] 00 10 00 5? [0-8] FF ( 15 | D? ) }
        $enc_str1 = { C7 45 ?? 67 4B 3D 49 C7 45 ?? 2F 4F 2F 4D }
        $enc_str2 = { C7 45 ?? 10 3C 51 3E C7 45 ?? 5C 38 4F 3A C7 45 ?? 42 34 58 36 C7 45 ?? 43 30 58 32 66 C7 45 ?? 2D 2C }
        $enc_str3 = { C7 45 ?? A3 8F FF 8D C7 45 ?? EF 8B E4 89 C7 45 ?? E0 87 E0 85 C7 45 ?? E7 83 EC 81 C7 45 ?? FB 9F E8 9D C7 45 ?? FF 9B 98 99 }
        $enc_str4 = { C7 45 ?? 44 40 51 47 C7 45 ?? 51 49 10 10 C7 45 ?? 03 48 43 42 C6 45 ?? 29 }
        $enc_str5 = { C7 45 ?? 77 77 73 74 C7 45 ?? 75 6D 64 70 C7 45 ?? 23 68 63 62 C6 45 ?? 09 }
    condition:
        uint16(0) == 0x5a4d and (all of ($code*) or (any of ($code*) and any of ($enc*)) or (2 of ($enc*)))
}

rule SAFEPAY_Published_Locker_SHA256
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Exact published SafePay Windows payload hashes"
        source = "SP005, SP006, SP010, SP011, SP015, SP047"
        confidence = "exact samples; no family-wide coverage"
    condition:
        filesize > 0 and filesize < 50MB and
        (
            hash.sha256(0, filesize) == "a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526" or
            hash.sha256(0, filesize) == "327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917"
        )
}

rule SAFEPAY_Published_Associated_SHA256
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Vendor-published SafePay-associated hashes whose component role is not exposed"
        source = "SP011, SP015, SP047"
        confidence = "exact advisory artifacts; role unresolved"
    condition:
        filesize > 0 and filesize < 50MB and
        (
            hash.sha256(0, filesize) == "0f23a313f79d54ae2102f193d3de1a6a98791c27921f28a4fab1092bcb43e5ee" or
            hash.sha256(0, filesize) == "12139246b8c5232d6d074df37acddc20f0bc233e42ed8eb00dfe2af5d3de3275" or
            hash.sha256(0, filesize) == "22df7d07369d206f8d5d02cf6d365e39dd9f3b5c454a8833d0017f4cf9c35177" or
            hash.sha256(0, filesize) == "241c3b02a8e7d5a2b9c99574c28200df2a0f8c8bd7ba4d262e6aa8ed1211ba1f" or
            hash.sha256(0, filesize) == "2f49bff45cc091a7bf52dcd061d24f9a7f2cf0ca9b3c12123bd3cf2fac56b481" or
            hash.sha256(0, filesize) == "625abbf876f256662f33a88c122bf787edf74b882c35adbd61562b5bd1b2ac27" or
            hash.sha256(0, filesize) == "654c11935448b3229434ec7d9d165a5f135ae4735d35700cffcb3b84f6a0fbc3" or
            hash.sha256(0, filesize) == "7f33c939f7aaf46945d58ed7fd0d1f5c7e3de1ff6a1a591ecc1992dab2a65078" or
            hash.sha256(0, filesize) == "94244ec2480addeaebb43aebbe48cee94f7f429231aa054f4c26f671653163b0" or
            hash.sha256(0, filesize) == "961346470d15d7795c5e35bc90c17d293fba7a8b811f8f5c26a3dc7c971cdc4e" or
            hash.sha256(0, filesize) == "b3045308a07e46c9f7dd98d352e964f242307ce30df8087dc751488118b5b959" or
            hash.sha256(0, filesize) == "ba1b89023581a0bc7a75f8ede9ec6115d5dda98c0145634f1b98978fbc79c956" or
            hash.sha256(0, filesize) == "f0127e786c9fb7bf2c8c999202d95c977af4c26cc27302a6ee352cfd62869e7b" or
            hash.sha256(0, filesize) == "fa74ac0e05b6209b7691511572386f97464ff5728732de99ddd6b5449ffae386" or
            hash.sha256(0, filesize) == "fd509df74a8d6a9e96762337efd46280ebf8d154c6c5dfbac7b3e8f7bb61f191"
        )
}

rule SAFEPAY_QDoor_Incident_SHA256
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Exact QDoor chain hashes from one SafePay intrusion"
        source = "SP008"
        confidence = "incident-scoped"
    condition:
        filesize > 0 and filesize < 50MB and
        (
            hash.sha256(0, filesize) == "921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae" or
            hash.sha256(0, filesize) == "6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a" or
            hash.sha256(0, filesize) == "e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346"
        )
}

rule SAFEPAY_Revised_Config_Artifact_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "SafePay revised-build mutex and artifact conjunction"
        source = "SP007"
        confidence = "hunting"
    strings:
        $mutex = "Global\\DB1D-19B4-5094-D570-9841-E4BC-8ABD-29AA-03BB-84AD-C61B-1355-4FF2-194B-96BD-7E49" ascii wide
        $note = "readme_safepay.txt" ascii wide nocase
        $ext = ".safepay" ascii wide nocase
        $pass = "-pass=" ascii wide
        $enc = "-enc=" ascii wide
        $path = "-path=" ascii wide
    condition:
        filesize > 128 and filesize < 50MB and
        uint16(0) == 0x5a4d and
        ($mutex or (all of ($pass,$enc,$path) and 1 of ($note,$ext)))
}

rule SAFEPAY_QDoor_Loader_Artifact_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "QDoor loader and custom protocol artifact conjunction"
        source = "SP008"
        confidence = "incident-scoped hunting"
    strings:
        $export = "DllRegisterServer" ascii
        $target = "WerFault.exe" ascii wide
        $dll = "soc.dll" ascii wide nocase
        $header = { C4 C3 C2 C1 }
    condition:
        filesize > 128 and filesize < 30MB and
        uint16(0) == 0x5a4d and
        3 of them
}

rule SAFEPAY_Ransom_Note_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "SafePay ransom-note text and service references"
        source = "SP001, SP002"
        confidence = "text artifact; research documents can match"
    strings:
        $brand = "SafePay team" ascii wide nocase
        $name = "readme_safepay" ascii wide nocase
        $ton = "safepay.ton" ascii wide nocase
        $mail = "VanessaCooke94@protonmail.com" ascii wide nocase
        $extortion = "financial motivation" ascii wide nocase
    condition:
        filesize > 32 and filesize < 256KB and
        2 of them
}

rule SAFEPAY_Command_Artifact_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Script or log containing multiple SafePay locker/recovery command families"
        source = "SP006, SP008"
        confidence = "hunting; operational documentation can match"
    strings:
        $pass = "-pass=" ascii wide
        $enc = "-enc=" ascii wide
        $uac = "-uac" ascii wide
        $network = "-network" ascii wide
        $shadow1 = "vssadmin delete shadows" ascii wide nocase
        $shadow2 = "wmic shadowcopy delete" ascii wide nocase
        $recovery = "recoveryenabled no" ascii wide nocase
    condition:
        filesize > 32 and filesize < 2MB and
        2 of ($pass,$enc,$uac,$network) and 1 of ($shadow*) or
        (all of ($pass,$enc,$uac) and $recovery)
}

rule SAFEPAY_Sygnia_Incident_Artifact_Triage
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Multi-artifact hunt for the SafePay intrusion documented by Sygnia"
        source = "SP049"
        confidence = "high for the case; not family-wide"
    strings:
        $script1 = "RouteCIDR.py" ascii wide nocase
        $script2 = "p.bat_S.bat" ascii wide nocase
        $script3 = "p.bat_W.bat" ascii wide nocase
        $script4 = "SWG.ps1" ascii wide nocase
        $script5 = "sorted.ps1" ascii wide nocase
        $script6 = "check.ps1" ascii wide nocase
        $tool1 = "Snaffler.exe" ascii wide nocase
        $tool2 = "SharpShares.exe" ascii wide nocase
        $output1 = "domains_S.txt" ascii wide nocase
        $output2 = "pingS.txt" ascii wide nocase
        $tenant1 = "jjvq-sharepoint.com" ascii wide nocase
        $tenant2 = "jjvq-my-sharepoint.com" ascii wide nocase
        $sync = "OneDrive - jjvq" ascii wide nocase
    condition:
        filesize > 32 and filesize < 10MB and
        (
            3 of ($script*) or
            (1 of ($tenant*) and ($sync or 1 of ($script*) or 1 of ($output*))) or
            (all of ($tool*) and 1 of ($output*))
        )
}
