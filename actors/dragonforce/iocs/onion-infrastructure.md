# DragonForce — Onion and Service Infrastructure

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**Observation source:** RansomLook status snapshot.

- **Main DLS:** `hxxp://z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid[.]onion/blog` — down, 67% 30-day uptime.
- **Main DLS:** `hxxp://xjhmtitnrdrgzw4vmsghirdoo2fk35a3tzj4enlmah4pvehdspydsiyd[.]onion/blog` — up, 58%.
- **Negotiation/chat:** `hxxp://3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd[.]onion/login` — up, 67%.
- **File servers:** `dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd[.]onion` (13%); `zsglo7t7osxyk3vcl7zxzup7hs4ir52sntteymmw63zvoxzcqytlw7qd[.]onion`, `6dgi54prfmpuuolutr4hl3akasxbx4o34g5y2bj4blrvzzkjemhxenad[.]onion`, `eogeko3sdn66gb7vjpwpmlmmmzfx7umtwaugpf5l6tb5jveolfydnuad[.]onion`, `ewrxgpvv7wsrqq7itfwg5jr7lkc6zzknndmru5su2ugrowxo3wwy5yad[.]onion`, `3ro23rujyigqrlrwk3e4keh3a3i6ntgrm3f42tbiqtf7vke47c6a6ayd[.]onion`, `jziu7k7uee467r2wt66ndrwymmw7tsmqgcqi7aemcaxraqmaf2hdm3yd[.]onion`, `2yczff6zyiey3gkgl5anwejktdp73abxbzbnvwobmrwkwgf3hudpyvyd[.]onion`, `bpoowhokr3vi32l3t4mjdtdxfrfpigwachopk5ojwmgxihnojhsawuyd[.]onion`, `dbvczza7nhwdb5kdvkzjtkrcvwnrt5viw7mihutueprvajy7rxhwq6id[.]onion`, `xtcwd3xmxpggtizn7kmwwqeizexflkkyqsytg2kauccau6ddsfa4gfyd[.]onion`, `4wcrfql53ljekid3sn66z6swjot725muveddq77utxltaelw64eikfid[.]onion`, `73h3lxn24kuayyfkn4t6ij7e67jklo24vqzqdhpts3ygmim7hu6u6aid[.]onion`, `nwtetzmrqhxieetg5lvth7szzvg35gfrqt23ly46vku56oo7pkueswyd[.]onion`, `dszmdx3jr7vggdaf2c5k4qunt4mxclelhgbtjlgewlkmlnfpsnsg3sad[.]onion` and `fsguestuctexqqaoxuahuydfa6ovxuhtng66pgyr5gqcrsi7qgchpkad[.]onion` were down at 0%.
- **Admin:** `hxxp://dragongoztkdfmnd7jkchznd3fvkpdmeh4vhbt6p3usrlsoy5dw2bhyd[.]onion` — down, 0%.

RansomLook listed 16 file servers. The table preserves the onion values visible in the cutoff snapshot; another tracker exposed additional historical endpoints with different observation windows.

The public Tox identity is:

```text
1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856D90A65E99D20
```

No reusable affiliate-panel access key, API credential or administrative password was located in public reporting. The unique ID embedded in a ransom note is a victim negotiation token and must not be republished as a service access key.

## Roles and Provenance

The two main DLS addresses and negotiation onion also appear in the archived notes. RansomLook marked its parser degraded and reported only 10% average 30-day uptime, so a “down” state is a point-in-time observation rather than proof of retirement. The file-server list is operational infrastructure; it is not a list of endpoint C2 servers.
