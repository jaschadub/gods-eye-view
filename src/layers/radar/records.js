/**
 * @file Pure normalization for the Cloudflare Radar layers.
 *
 * Shapes follow Cloudflare's official SDK types
 * (cloudflare-typescript: radar/annotations/outages.ts,
 * radar/bgp/hijacks/events.ts, radar/bgp/leaks/events.ts) inside the v4 API
 * envelope `{ success, errors, result }`. Every normalizer returns null for an
 * unusable payload so a bad read never replaces the last good snapshot.
 * No Cesium, no fetch.
 */

const ISO2 = /^[A-Z]{2}$/;
const code = (v) => {
  const c = String(v ?? '')
    .trim()
    .toUpperCase();
  return ISO2.test(c) ? c : null;
};
const text = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const ms = (v) => {
  const t = Date.parse(v ?? '');
  return Number.isFinite(t) ? t : null;
};
const codes = (list) => [
  ...new Set((Array.isArray(list) ? list : []).map(code).filter(Boolean)),
];

/** Unwrap the Cloudflare v4 envelope; null unless `success` and an object. */
function resultOf(payload) {
  if (!payload || payload.success !== true) return null;
  const result = payload.result;
  return result && typeof result === 'object' ? result : null;
}

// ── Outage annotations ────────────────────────────────────────────────────

/**
 * Normalize `/radar/annotations/outages` into one row per affected country.
 * An annotation naming several locations counts for each of them.
 */
export function normalizeRadarOutages(payload) {
  const result = resultOf(payload);
  if (!result || !Array.isArray(result.annotations)) return null;
  const byCountry = new Map();
  for (const a of result.annotations) {
    if (!a || typeof a !== 'object') return null;
    const startedMs = ms(a.startDate);
    if (startedMs == null) continue;
    const endedMs = ms(a.endDate);
    const ongoing = endedMs == null;
    const type = text(a.outage?.outageType)?.toUpperCase() ?? null;
    const cause = text(a.outage?.outageCause);
    const names = new Map(
      (a.locationsDetails ?? [])
        .filter(Boolean)
        .map((d) => [code(d.code), text(d.name)]),
    );
    for (const cc of codes(a.locations)) {
      let row = byCountry.get(cc);
      if (!row) {
        row = {
          code: cc,
          name: names.get(cc) ?? null,
          outages: 0,
          ongoing: 0,
          nationwide: false,
          causes: new Set(),
          latest: null,
        };
        byCountry.set(cc, row);
      }
      row.outages++;
      if (ongoing) row.ongoing++;
      if (ongoing && type === 'NATIONWIDE') row.nationwide = true;
      if (cause) row.causes.add(cause);
      if (!row.latest || startedMs > row.latest.startedMs)
        row.latest = {
          id: text(String(a.id ?? '')),
          startedMs,
          endedMs,
          type,
          cause,
          scope: text(a.scope),
          description: text(a.description),
          asns: Array.isArray(a.asns) ? a.asns.length : 0,
          linkedUrl: text(a.linkedUrl),
        };
    }
  }
  return [...byCountry.values()]
    .map((row) => ({
      ...row,
      causes: [...row.causes].sort(),
      band: row.nationwide ? 'high' : row.ongoing > 0 ? 'medium' : 'low',
    }))
    .sort(
      (a, b) =>
        b.ongoing - a.ongoing ||
        b.outages - a.outages ||
        a.code.localeCompare(b.code),
    );
}

/** JSON-safe analyst record for one country's Radar outages. */
export function mapRadarOutageRecord(row) {
  const num = (v) => (Number.isFinite(v) ? v : null);
  return {
    id: `CFO-${row?.code ?? 'XX'}`,
    country: row?.name ?? row?.code ?? null,
    countryCode: row?.code ?? null,
    outages: num(row?.outages),
    ongoing: num(row?.ongoing),
    cause: row?.latest?.cause ?? null,
    outageType: row?.latest?.type ?? null,
    startedMs: num(row?.latest?.startedMs),
    description: row?.latest?.description ?? null,
    cableLandings: num(row?.cableLandings),
    lat: num(row?.lat),
    lon: num(row?.lon),
  };
}

// ── BGP hijacks and route leaks ───────────────────────────────────────────

/**
 * Heuristic display bands over Radar's hijack `confidence_score`
 * (higher = more likely malicious; Radar exposes min/max filters, not a
 * published scale).
 */
export function hijackBand(confidence) {
  if (confidence >= 8) return 'high';
  if (confidence >= 5) return 'medium';
  return 'low';
}

function asnNames(result) {
  return new Map(
    (Array.isArray(result.asn_info) ? result.asn_info : [])
      .filter((i) => Number.isInteger(i?.asn))
      .map((i) => [
        i.asn,
        { name: text(i.org_name), country: code(i.country_code) },
      ]),
  );
}

/** Normalize `/radar/bgp/hijacks/events`. */
export function normalizeBgpHijacks(payload) {
  const result = resultOf(payload);
  if (!result || !Array.isArray(result.events)) return null;
  const info = asnNames(result);
  const out = [];
  for (const e of result.events) {
    if (!e || typeof e !== 'object' || !Number.isInteger(e.hijacker_asn))
      return null;
    const confidence = Number.isFinite(e.confidence_score)
      ? e.confidence_score
      : 0;
    out.push({
      id: `HIJ-${e.id}`,
      kind: 'hijack',
      asn: e.hijacker_asn,
      asnName: info.get(e.hijacker_asn)?.name ?? null,
      country: code(e.hijacker_country) ?? info.get(e.hijacker_asn)?.country,
      victimAsns: (e.victim_asns ?? []).filter(Number.isInteger),
      victimCountries: codes(e.victim_countries),
      prefixes: Array.isArray(e.prefixes) ? e.prefixes.length : 0,
      confidence,
      band: hijackBand(confidence),
      startedMs: ms(e.min_hijack_ts),
      endedMs: ms(e.max_hijack_ts),
      ongoing: (e.on_going_count ?? 0) > 0,
      stale: e.is_stale === true,
    });
  }
  return out;
}

/** Normalize `/radar/bgp/leaks/events`. */
export function normalizeBgpLeaks(payload) {
  const result = resultOf(payload);
  if (!result || !Array.isArray(result.events)) return null;
  const info = asnNames(result);
  const out = [];
  for (const e of result.events) {
    if (!e || typeof e !== 'object' || !Number.isInteger(e.leak_asn))
      return null;
    out.push({
      id: `LEAK-${e.id}`,
      kind: 'leak',
      asn: e.leak_asn,
      asnName: info.get(e.leak_asn)?.name ?? null,
      country: info.get(e.leak_asn)?.country ?? null,
      victimAsns: [],
      victimCountries: codes(e.countries),
      prefixes: Number.isInteger(e.prefix_count) ? e.prefix_count : 0,
      confidence: null,
      band: 'medium',
      startedMs: ms(e.min_ts),
      endedMs: ms(e.max_ts),
      ongoing: e.finished === false,
      stale: false,
    });
  }
  return out;
}

/**
 * Country involvement across events: a source country (hijacker / leaker)
 * takes the event's band; an affected country is at least 'low'.
 */
export function bgpCountryBands(events) {
  const rank = { low: 1, medium: 2, high: 3 };
  const bands = new Map();
  const raise = (cc, band) => {
    if (!cc) return;
    const prior = bands.get(cc);
    if (!prior || rank[band] > rank[prior.band])
      bands.set(cc, { band, events: (prior?.events ?? 0) + 1 });
    else prior.events++;
  };
  for (const e of events) {
    raise(e.country, e.band);
    for (const cc of e.victimCountries) if (cc !== e.country) raise(cc, 'low');
  }
  return bands;
}

/** JSON-safe analyst record for one BGP event. */
export function mapBgpEventRecord(event) {
  const num = (v) => (Number.isFinite(v) ? v : null);
  return {
    id: event?.id ?? null,
    kind: event?.kind ?? null,
    asn: Number.isInteger(event?.asn) ? `AS${event.asn}` : null,
    asnName: event?.asnName ?? null,
    countryCode: event?.country ?? null,
    victimCountries: (event?.victimCountries ?? []).join(', ') || null,
    prefixes: num(event?.prefixes),
    confidence: num(event?.confidence),
    startedMs: num(event?.startedMs),
    ongoing: event?.ongoing ? 1 : 0,
    lat: num(event?.lat),
    lon: num(event?.lon),
  };
}
