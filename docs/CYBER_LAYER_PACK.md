# Cyber Layer Pack

Threat-intel layers for God's Eye View that stay inside the project's line:
they model **networks, infrastructure and events**, never individuals. All
geography is **country level**; no indicator IP, host or banner reaches the
browser.

The pack's thesis is physical/cyber correlation. GEV already ships submarine
cables, landing points, datacenters, GNSS integrity and military traffic.
Every cyber record carries `cableLandings` (TeleGeography landing points
inside that country), so the analyst/voice agent can ask questions like
"which outage countries have the most cable landings?" or "C2 clusters in
cable-hub countries".

## Layers

All five sit in the **Cyber** group of the Layers panel.

| Layer                                                                         | Source                                                    | Key (POWER UP)                        | Window      | Share token |
| ----------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------- | ----------- | ----------- |
| **Internet Health**: connectivity disruption score                            | IODA (Georgia Tech) `v2/outages/summary`                  | none                                  | 24 h        | `5`         |
| **Radar Outages**: outage annotations with cause / type / scope               | Cloudflare Radar `annotations/outages`                    | `CLOUDFLARE_RADAR_TOKEN` (free)       | 7 d         | `7`         |
| **BGP Events**: hijacks + route leaks, arcs from source to affected countries | Cloudflare Radar `bgp/hijacks/events`, `bgp/leaks/events` | `CLOUDFLARE_RADAR_TOKEN` (free)       | 7 d         | `8`         |
| **C2 Clusters**: botnet C2 servers per hosting country                        | abuse.ch Feodo Tracker (keyless) + ThreatFox `get_iocs`   | `THREATFOX_AUTH_KEY` (free, optional) | live / 24 h | `6`         |
| **Exposure**: exposed ICS, RDP, database and SMB services per country         | Shodan `host/count` facets (spends no query credits)      | `SHODAN_API_KEY`                      | cached 6 h  | `9`         |

Shading uses three display bands (red high, amber medium, cyan low). Bands
are heuristic and documented beside each normalizer; upstream scores are
relative.

| Layer           | High                         | Medium                      | Low              |
| --------------- | ---------------------------- | --------------------------- | ---------------- |
| Internet Health | IODA score ≥ 100k            | ≥ 1k                        | else             |
| Radar Outages   | ongoing nationwide           | ongoing (other)             | ended in window  |
| BGP Events      | hijacker with confidence ≥ 8 | confidence ≥ 5, or a leaker | affected country |
| C2 Clusters     | ≥ 25 C2                      | ≥ 5                         | else             |
| Exposure        | ≥ 100k services              | ≥ 10k                       | else             |

## Architecture

```
server/providers/cyber/snapshotProxy.js   shared hardened snapshot proxy
server/providers/cyber/ipCountry.js       IPv4→country table (ThreatFox)
server/providers/{internetHealth,cloudflareRadar,c2Clusters,shodanExposure}.js
src/layers/cyber/geometry.js              Natural Earth countries + cable landings
src/layers/cyber/countryLayer.js          one Cesium lifecycle for every layer
src/layers/cyber/source.js                same-origin snapshot source (no_key aware)
src/layers/{internetHealth,radar,c2Clusters,exposure}/  records + projection
```

- **Proxy** (`cyberSnapshotProxy`): one cached snapshot per feed, fresh for
  a per-feed TTL, served stale (with `X-Data-Stale`) up to a limit when the
  upstream fails, failure cooldown, per-peer rate limit, single-flight loads,
  fixed upstream origins, `redirect: 'error'`, byte caps, timeouts, sanitized
  errors. A keyed feed answers `503 {error:'no_key'}` while its env var is
  unset. Keys never reach the browser.
- **Records**: each layer's normalizer validates the upstream shape and
  returns `null` for anything unusable, so a malformed read never replaces
  the last good snapshot. Cloudflare shapes follow the official
  `cloudflare-typescript` Radar types.
- **Projection**: a pure `project(snapshot, geometry)` per layer returns
  `{countries, arcs?, records}`. `createCyberCountryLayer` does all the
  Cesium work: polygons draped on terrain / 3D tiles, collision-managed
  labels, lifted geodesic arcs, analyst records, and `keyRequired` stats that
  drive the panel's "needs a provider key" guidance.
- **ThreatFox geography**: ThreatFox IOCs carry no location. The proxy
  resolves `ip:port` IOCs against `@ip-location-db/asn-country` (CC0;
  NRO statistics CC BY 4.0). The numeric IPv4 table (~3.5 MB, ~140k
  ranges) is downloaded once from jsDelivr into `.gev-cache/`, refreshed
  weekly, and searched with a binary search. IOCs it cannot place are
  counted as `unlocated`, never guessed.
- **Voice / MCP**: every layer is in the voice manifest with two or three
  analyst fields (for example `country`, `c2Count`, `ics`, `asn`,
  `confidence`, `cause`).

## Review notes

- The voice prompt ceiling (`src/voice/pointAndAsk.test.mjs`) moves from
  52,000 to 52,500. The pack adds 519 chars to a 51,972 baseline, and even a
  toggle-only entry overflows the old headroom.
- The voice schema pins (`actionSchemas.test.mjs`,
  `firstRunExperience.test.mjs`) and the layer and registry counts are
  re-derived.
- The token-ledger allocation simulations now derive the next free tokens
  from the real ledger instead of literal digits. The pack used the last free
  digits (5–9), so the next layer gets `00`.
- Cloudflare Radar data is CC BY-NC 4.0, so commercial use needs a license
  from Cloudflare. Shodan use follows Shodan's API terms. See DATA_SOURCES.md.

## Ideas not built

- **Prefix Watch**: a RIPE RIS Live WebSocket subscription for a watched list
  of prefixes and ASNs (MOAS, more-specifics, visibility drops), for
  monitoring a client's own address space.
- **Per-capita normalization** for Exposure and C2 (counts currently favor
  large networks).
- **City-level C2 clustering**: needs a city-resolution IP table and
  careful caveats.
