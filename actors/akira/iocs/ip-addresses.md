# Akira — IP Addresses

Historical investigative pivots, reviewed **2026-09-10**. Reassignment, shared hosting and legitimate services make present-day blocking inappropriate without enrichment. Confidence is for the published incident role, not exclusive Akira control.

| Indicator | Role and context | Observation | Source | Confidence / use |
|---|---|---|---|---|
| `72.23.77[.]35` | Successful SonicWall VPN login source preceding documented intrusion | 2026-08-04 | [Huntress A11](../References.md#a11) | High Confidence in reported event; investigate matching historical login, not IP ownership |
| `137.184.243[.]69` | Wget retrieval of `vmwaretools`; suspected staging/C2 | 2025-08-20 incident | [Darktrace A10](../References.md#a10) | Moderate Confidence in malicious infrastructure role |
| `66.165.243[.]39` | SSH destination during approximately 2 GiB suspected exfiltration; HVC-AS in report | 2025-08-20 incident | [Darktrace A10](../References.md#a10) | Moderate Confidence; corroborate bytes, process and account |
| `193.242.184[.]180` | Listed in Ransomware.live actor IOC section; precise incident role and first-seen not recovered | Unknown; retained 2026-09-10 | [Ransomware.live A09](../References.md#a09); underlying observation unresolved | Low Confidence; quarantine from automatic blocking |
| `20.99.185[.]48` | GLIMPS-listed IP without technical incident context; no proof of attacker control | Undated sheet, URL path 2026/07 | [GLIMPS A08](../References.md#a08) | Low Confidence; retained as unresolved source claim, excluded from detections |

The original two entries are preserved with their limitations. Newly sourced cases add roles rather than turning every contacted address into C2. See [operations](../intelligence/operations.md) for affiliate and campaign scope.

## Mixed Akira / Fog Campaign Infrastructure

Arctic Wolf publishes the following indicators for its **combined August–October 2024 Akira/Fog incident population**. They are not individually labelled as Akira-only. **Moderate Confidence in published campaign association; Low Confidence in exclusive Akira ownership.** All are historical. [A06](../References.md#a06)

| Indicator | Published role | Observation / limitation |
|---|---|---|
| `77.247.126[.]158`, `208.115.232[.]194`, `184.107.5[.]46`, `66.181.33[.]32`, `185.235.137[.]150`, `45.11.59[.]16` | VPN connection sources | August–October 2024 combined campaign; individual ransomware brand uncertain |
| `79.141.173[.]238`, `57.128.101[.]78` | AnyDesk connection / C2 labels in report | Shared relay/service or actor-controlled infrastructure must be distinguished by session evidence |
| `194.33.45[.]167`, `23.227.162[.]18`, `45.86.208[.]146` | Exfiltration destinations; last associated with FileZilla | Campaign-level reporting; do not infer present ownership |
