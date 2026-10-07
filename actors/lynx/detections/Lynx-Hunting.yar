/*
    Presentation reviewed: 2026-10-07.
  Lynx hunting rules.
  MAL_RANSOM_INC_Aug24 is reproduced from the Nextron analysis with its original
  author metadata. Remaining rules are repository-authored defensive triage.
*/

import "hash"

rule MAL_RANSOM_INC_Aug24
{
    meta:
      author = "X__Junior"
      description = "Detects INC ransomware and it's variants like Lynx"
      reference1 = "https://x.com/rivitna2/status/1817681737251471471"
      reference2 = "https://twitter.com/rivitna2/status/1701739812733014313"
      date = "2024-08-08"
      hash1 = "eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc"
      hash2 = "1754c9973bac8260412e5ec34bf5156f5bb157aa797f95ff4fc905439b74357a"
      score = 80
    strings:
      $s1 = "tarting full encryption in" wide
      $s2 = "oad hidden drives" wide
      $s3 = "ending note to printers" ascii
      $s4 = "uccessfully delete shadow copies from %c:/" wide
      $op1 = { 33 C9 03 C6 83 C0 02 0F 92 C1 F7 D9 0B C8 51 E8 }
      $op2 = { 8B 44 24 [1-4] 6A 00 50 FF 35 ?? ?? ?? ?? 50 FF 15 }
      $op3 = { 57 50 8D 45 ?? C7 45 ?? 00 00 00 00 50 6A 00 6A 00 6A 02 6A 00 6A 02 C7 45 ?? 00 00 00 00 FF D6 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 04 8B F8 8D 45 ?? 50 8D 45 ?? 50 FF 75 ?? 57 6A 02 6A 00 6A 02 FF D6 }
      $op4 = { 6A FF 8D 4? ?? 5? 8D 4? ?? 5? 8D 4? ?? 5? 5? FF 15 ?? ?? ?? ?? 85 C0 }
      $op5 = { 56 6A 00 68 01 00 10 00 FF 15 ?? ?? ?? ?? 8B F0 83 FE FF 74 ?? 6A 00 56 FF 15 ?? ?? ?? ?? 68 88 13 00 00 56 FF 15 ?? ?? ?? ?? 56 FF 15 }
    condition:
      uint16(0) == 0x5A4D and
      (3 of ($s*) or 3 of ($op*) or (2 of ($s*) and 2 of ($op*)))
}

rule LYNX_Published_Locker_SHA256
{
    meta:
    author = "ThreatActorIntelligenceVault"
    description = "Exact published Lynx locker samples"
    date = "2026-10-07"
    condition:
        filesize < 100MB and (
            hash.sha256(0, filesize) == "eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc" or
            hash.sha256(0, filesize) == "571f5de9dd0d509ed7e5242b9b7473c2b2cbb36ba64d38b32122a0a337d6cf8b" or
            hash.sha256(0, filesize) == "82eb1910488657c78bef6879908526a2a2c6c31ab2f0517fcc5f3f6aa588b513" or
            hash.sha256(0, filesize) == "b378b7ef0f906358eec595777a50f9bb5cc7bb6635e0f031d65b818a26bdc4ee" or
            hash.sha256(0, filesize) == "ecbfea3e7869166dd418f15387bc33ce46f2c72168f571071916b5054d7f6e49" or
            hash.sha256(0, filesize) == "85699c7180ad77f2ede0b15862bb7b51ad9df0478ed394866ac7fa9362bf5683" or
            hash.sha256(0, filesize) == "09c5ff735d3d7b8c47b4df7de35e1c72b530b2c2566628bc29aaa54feb4d89f4" or
            hash.sha256(0, filesize) == "07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a" or
            hash.sha256(0, filesize) == "c3b57cd2c04ffd6dd173edfd975d2b05b7f6f502062a56b8585bda8776824a18" or
            hash.sha256(0, filesize) == "6e65483764d7c25523a5bbef5be99eb42349eef39d5517c46b3a4af262a80ceb"
        )
}

rule LYNX_Note_Text_Triage
{
    meta:
    author = "ThreatActorIntelligenceVault"
    description = "Lynx ransom-note text triage"
    date = "2026-10-07"
    strings:
    $a = "Your data is stolen and encrypted" ascii wide nocase
    $b = "unique identificator" ascii wide nocase
    $c = "lynxchat" ascii wide nocase
    $d = "lynxblog" ascii wide nocase
    condition:
    filesize < 256KB and 3 of them
}

rule LYNX_Windows_Artifact_Bundle_Triage
{
    meta:
    author = "ThreatActorIntelligenceVault"
    description = "Lynx Windows PE artifact combination"
    date = "2026-10-07"
    strings:
    $a = "README.txt" ascii wide
    $b = "background-image.jpg" ascii wide
    $c = "--encrypt-network" ascii wide
    $d = "--stop-processes" ascii wide
    $e = "--no-print" ascii wide
    $f = "SeTakeOwnershipPrivilege" ascii wide
    condition:
    uint16(0) == 0x5A4D and filesize < 100MB and 4 of them
}

rule LYNX_Encrypted_Output_Trailer_Triage
{
    meta:
    author = "ThreatActorIntelligenceVault"
    description = "Published Lynx encrypted-file trailer layout at EOF"
    date = "2026-10-07"
    condition:
    filesize >= 116 and
    uint32(filesize - 20) == 0x584E594C and
    uint32(filesize - 16) == 0 and
    uint32(filesize - 12) == 0x000F4240 and
    uint32(filesize - 8) == 5 and
    uint32(filesize - 4) == 1
}
