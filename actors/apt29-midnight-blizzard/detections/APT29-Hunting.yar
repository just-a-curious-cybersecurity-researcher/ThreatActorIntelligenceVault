/*
    APT29 / Midnight Blizzard defensive hunting rules.
    Two WellMess rules are reproduced from the public NCSC 2020 advisory.
    Repository-authored rules are contextual triage heuristics derived from cited public behavior.
    Presentation reviewed: 2026-09-25.
*/

import "hash"

rule wellmess_certificate_base64_snippets
{
    meta:
        description = "Detects WellMess based on base64 snippets of certificates used"
        author = "NCSC"
        source = "NCSC APT29 vaccine advisory, 2020"
        hash_reference = "8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8"
    strings:
        $a1 = "BgNVHQ4EBwQFAQIDBA"
        $a2 = "YDVR0OBAcEBQECAwQG"
        $a3 = "GA1UdDgQHBAUBAgMEB"
        $b1 = "BgNVBAYTBVR1bmlzMQswCQYDVQQKEwJJVD"
        $b2 = "YDVQQGEwVUdW5pczELMAkGA1UEChMCSVQx"
        $b3 = "GA1UEBhMFVHVuaXMxCzAJBgNVBAoTAklUM"
    condition:
        ((uint16(0) == 0x5a4d and uint16(uint16(0x3c)) == 0x4550) or uint32(0) == 0x464c457f) and
        any of ($a*) and any of ($b*)
}

rule wellmess_regex_used_for_parsing_beacons
{
    meta:
        description = "Detects WellMess Golang and .NET samples based on command and beacon parsing expressions"
        author = "NCSC"
        source = "NCSC APT29 vaccine advisory, 2020"
        hash_reference = "8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8"
    strings:
        $a = "fileName:(?<fn>.*?)\\sargs:(?<arg>.*)\\snotwait:(?<nw>.*)" ascii wide
        $b = "<;(?<key>[^;]*?);>(?<value>[^<]*?)<;[^;]*?;>" ascii wide
    condition:
        ((uint16(0) == 0x5a4d and uint16(uint16(0x3c)) == 0x4550) or uint32(0) == 0x464c457f) and any of them
}

rule APT29_CornFlake_Artifact_Bundle_Triage
{
    meta:
        description = "Local CornFlake string-bundle heuristic"
        author = "ThreatActorIntelligenceVault"
        source = "Microsoft CaptiveCrunch, 2026"
    strings:
        $service = "Cloud Sync Service" ascii wide
        $description = "Synchronizes files with the cloud storage provider" ascii wide
        $config = "sync.dat" ascii wide
        $path = "svchost32\\svchost32.exe" ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and 3 of them
}

rule APT29_GoldMax_Artifact_Bundle_Triage
{
    meta:
        description = "Local GoldMax configuration and network-decoy string-bundle heuristic"
        author = "ThreatActorIntelligenceVault"
        source = "Microsoft GoldMax analysis, 2021"
    strings:
        $config = "features.dat.tmp" ascii wide
        $log_target = "Target:" ascii wide
        $log_status = "StatusCode:" ascii wide
        $decoy1 = "/style.css" ascii wide
        $decoy2 = "/scripts/jquery.js" ascii wide
        $decoy3 = "/css/bootstrap.css" ascii wide
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and filesize < 20MB and
        $config and (2 of ($log_*,$decoy*))
}

rule APT29_WINELOADER_Staging_Script_Triage
{
    meta:
        description = "Local ROOTSAW/WINELOADER staging-script heuristic"
        author = "ThreatActorIntelligenceVault"
        source = "Mandiant WINELOADER campaign, 2024"
    strings:
        $certutil = "certutil -decode" ascii wide nocase
        $tar = "tar -xf" ascii wide nocase
        $invite_txt = "Windows\\Tasks\\invite.txt" ascii wide nocase
        $invite_zip = "Windows\\Tasks\\invite.zip" ascii wide nocase
        $sqldumper = "Windows\\Tasks\\SqlDumper.exe" ascii wide nocase
    condition:
        filesize < 2MB and $certutil and $tar and 2 of ($invite_*) and $sqldumper
}

rule APT29_Retained_SHA256_Exact_Match
{
    meta:
        description = "Exact match for retained source-verified APT29 campaign files"
        author = "ThreatActorIntelligenceVault"
        source = "Microsoft, NCSC and Check Point; see hash-provenance.md"
    condition:
        hash.sha256(0, filesize) == "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593" or
        hash.sha256(0, filesize) == "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c" or
        hash.sha256(0, filesize) == "2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41" or
        hash.sha256(0, filesize) == "8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8" or
        hash.sha256(0, filesize) == "83014ab5b3f63b0253cdab6d715f5988ac9014570fa4ab2b267c7cf9ba237d18" or
        hash.sha256(0, filesize) == "0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494" or
        hash.sha256(0, filesize) == "70d93035b0693b0e4ef65eb7f8529e6385d698759cc5b8666a394b2136cc06eb" or
        hash.sha256(0, filesize) == "0e1f9d4d0884c68ec25dec355140ea1bab434f5ea0f86f2aade34178ff3a7d91" or
        hash.sha256(0, filesize) == "247a733048b6d5361162957f53910ad6653cdef128eb5c87c46f14e7e3e46983" or
        hash.sha256(0, filesize) == "0affab34d950321e3031864ec2b6c00e4edafb54f4b327717cb5b042c38a33c9" or
        hash.sha256(0, filesize) == "7e05ff08e32a64da75ec48b5e738181afb3e24a9f1da7f5514c5a11bb067cbfb" or
        hash.sha256(0, filesize) == "acc74c920d19ea0a5e6007f929ef30b079eb2836b5b28e5ffcc20e68fa707e66" or
        hash.sha256(0, filesize) == "653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358" or
        hash.sha256(0, filesize) == "420d20cddfaada4e96824a9184ac695800764961bad7654a6a6c3fe9b1b74b9a" or
        hash.sha256(0, filesize) == "85484716a369b0bc2391b5f20cf11e4bd65497a34e7a275532b729573d6ef15e" or
        hash.sha256(0, filesize) == "78a810e47e288a6aff7ffbaf1f20144d2b317a1618bba840d42405cddc4cff41" or
        hash.sha256(0, filesize) == "d931078b63d94726d4be5dc1a00324275b53b935b77d3eed1712461f0c180164" or
        hash.sha256(0, filesize) == "24c079b24851a5cc8f61565176bbf1157b9d5559c642e31139ab8d76bbb320f8" or
        hash.sha256(0, filesize) == "adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8"
}

rule APT29_Qualified_Cluster_SHA256_Exact_Match
{
    meta:
        description = "Exact match for Google-published UNC6293 and UNC7005 campaign files"
        author = "ThreatActorIntelligenceVault"
        source = "Google Threat Intelligence 2025-2026; moderate-confidence ICE RELIC initial-access relationship"
    condition:
        hash.sha256(0, filesize) == "329fda9939930e504f47d30834d769b30ebeaced7d73f3c1aadd0e48320d6b39" or
        hash.sha256(0, filesize) == "5b8d50c2e8cc3038b7c6e6dbf1219f6e814930a1e3c0053143a1191ae67f8ffc" or
        hash.sha256(0, filesize) == "a06a8fd1b6fa1924199a4540cf16d089217ce8f78c617739946f145fd1fc88c1" or
        hash.sha256(0, filesize) == "1d9299799a7b8da67c44ebec064d64542c27645f8e84de4a22ca3f6cbc843e3c" or
        hash.sha256(0, filesize) == "c5826032207d623a7f6caec8465af7364eccc355f9a48897da2a54f3e4420265" or
        hash.sha256(0, filesize) == "125752ad7c20d715920a3b2fb0fdde660f07b3f2b053665cf38c2d6d9de86e1e" or
        hash.sha256(0, filesize) == "403b624e35777cbc07dbe66398b21bba70396a20b859c880732338ce1dd1f41f" or
        hash.sha256(0, filesize) == "28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3" or
        hash.sha256(0, filesize) == "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c" or
        hash.sha256(0, filesize) == "1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916" or
        hash.sha256(0, filesize) == "6f7090895c1c3dee30de6b3f098ca3a788dc198646e5293a8b1210430b0add97" or
        hash.sha256(0, filesize) == "20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38" or
        hash.sha256(0, filesize) == "ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25"
}
