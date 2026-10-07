# Lynx — IP Addresses

**Presentation reviewed:** 2026-10-07.

Historical investigative pivots from one incident. Reassignment and hosting reuse make present-day blocking inappropriate without enrichment.

| Indicator | Role and context | Observation | Confidence / use |
|---|---|---|---|
| `195.211.190[.]189` | Initial external RDP source using valid credentials | March 2025, source hostname `DESKTOP-BUL6K1U` | High in reported event |
| `77.90.153[.]30` | Later external RDP activity from same client hostname | March 2025 | High in reported event |
| `79.141.172[.]131` | External address observed in PacketWatch Lynx incident response | 2026 publication; role varies by incident | High in reported event; historical pivot |
| `185.33.87[.]207` | External address observed in PacketWatch Lynx incident response | 2026 publication; role varies by incident | High in reported event; historical pivot |

## Campaign Infrastructure

| Indicator | Published role | Observation / limitation |
|---|---|---|
| `195.211.190[.]189` | Initial access and repeated RDP sessions | One affiliate case; not demonstrated as core Lynx infrastructure |
| `77.90.153[.]30` | Follow-up RDP source | One affiliate case; validate historical ownership and user-agent/client evidence |
| `79.141.172[.]131` | Incident infrastructure | Direct IR IOC; not demonstrated as core RaaS infrastructure |
| `185.33.87[.]207` | Incident infrastructure | Direct IR IOC; not demonstrated as core RaaS infrastructure |

The two addresses were associated with Railnet/Virtualine infrastructure in the source report. Provider attribution does not imply provider involvement.
