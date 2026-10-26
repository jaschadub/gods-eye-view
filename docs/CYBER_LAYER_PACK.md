# Cyber Layer Pack

Threat-intel layers for God's Eye View that stay inside the project's line:
they model **networks, infrastructure and events**, never individuals.

The pack's thesis is physical/cyber correlation. GEV already ships submarine
cables, landing points, datacenters, GNSS integrity and military traffic; the
cyber layers add the network signal so an analyst (or the voice agent) can ask
"which outage countries have the most cable landings?" or "GNSS anomalies and
routing changes in the same region".

## Status

| #   | Layer                                                                                          | Source                                   | Auth             | Status                 |
| --- | ---------------------------------------------------------------------------------------------- | ---------------------------------------- | ---------------- | ---------------------- |
| 1   | **Internet Health** — country connectivity disruption, 24 h                                    | IODA (Georgia Tech) `v2/outages/summary` | 🟢 none          | **Done (this branch)** |
| 2   | BGP Events — hijack/leak/visibility-drop candidates by origin ASN                              | RIPE RIS Live (WebSocket) + RIPEstat     | 🟢 none          | Planned                |
| 3   | C2 Clusters — active botnet C2 / IOC infrastructure grouped by ASN and hosting city            | abuse.ch ThreatFox + Feodo Tracker       | 🟡 free Auth-Key | Planned                |
| 4   | Outage annotations — Cloudflare Radar outage annotations (cause: cable cut, power, government) | Cloudflare Radar                         | 🟡 free token    | Planned                |
| 5   | Exposure overlay — counts of exposed ICS/OT and camera services per city                       | Shodan / Censys facets                   | 🔴 paid          | Optional               |

## 1. Internet Health (implemented)

- **Proxy** `server/providers/internetHealth.js` → `/api/internet-health`.
  One global 24 h snapshot, cached 5 min, stale fallback up to 1 h, 4 MiB
  body cap, 15 s timeout, `redirect: 'error'`, per-peer rate limit, 60 s
  failure cooldown. Only normalized rows leave the proxy.
- **Records** `src/layers/internetHealth/records.js`: validates the IODA v2
  envelope and both row shapes; refuses malformed payloads rather than
  returning partial data. Folds `bgp` / `ping-slash24` / `merit-nt` score keys
  into `bgp`, `activeProbing` and `telescope` signals. Display bands
  (severe ≥ 100k, major ≥ 1k, minor) are heuristic: IODA scores are
  relative.
- **Geometry** `src/layers/internetHealth/geometry.js` joins ISO-2 codes to
  the bundled Natural Earth countries pack and counts TeleGeography cable
  landing points inside each country (`cableLandings`): the first
  correlation field.
- **Layer** `src/layers/internetHealth/index.js`: country polygons draped on
  terrain/3D tiles and shaded by band, plus a score label per country;
  `getAnalystRecords()` for voice/MCP queries.
- **Wiring:** catalog, source contract, reference sources, a new **Cyber**
  panel group, share token `5`, voice manifest (`internet outages`,
  analyst fields `country`, `score`, `cableLandings`), locale catalogs.

### Notes for review

- The voice prompt ceiling in `src/voice/pointAndAsk.test.mjs` moves from
  52,000 to 52,150. Even a toggle-only manifest entry exceeds the old
  headroom (28 chars), so any new layer needs this change.
- The voice schema pins (`actionSchemas.test.mjs`,
  `firstRunExperience.test.mjs`) and the layer-count and token-ledger fixtures
  were re-derived for one new layer. The ledger simulations shift by one digit
  (5 → 6, etc.).

## 2. BGP Events (next)

- Server-side WebSocket client to `wss://ris-live.ripe.net/v1/ws/` with a
  bounded ring buffer: subscribe to `UPDATE` with `moreSpecific: true` for
  watched prefixes, and to a sampled global stream for origin changes.
- Detectors (pure, testable): MOAS (multiple origins for one prefix),
  more-specific announcements of a watched prefix, and a sudden drop in
  visibility (peer count) via RIPEstat `routing-status`.
- Geography: an ASN maps to a country via RIPEstat `rir-stats-country`. Draw
  at country/ASN-centroid level, never as precise points.
- Correlate with Internet Health (same country, same window) and GNSS
  Integrity (same region).

## 3. C2 Clusters

- ThreatFox `get_iocs` (days=1) and Feodo `ipblocklist.json`, through a
  keyed server proxy (`THREATFOX_AUTH_KEY`, added in POWER UP).
- Group IOCs by ASN → hosting country/city; render clustered rings sized by
  count and colored by malware family. A raw IP is never a map point:
  geolocation is unreliable for VPN, anycast and cloud addresses.
- Analyst fields: `asn`, `asName`, `country`, `iocCount`, `families`,
  `firstSeen`.

## Guardrails

- Same proxy hardening as existing providers: fixed upstream origin, byte
  caps, timeouts, sanitized errors, no keys in the browser.
- Coarse geography only: country, city or ASN level.
- Respect each source's terms. Commercial use of the pack also needs a
  non-community Cesium/Google tier; see DATA_SOURCES.md.
