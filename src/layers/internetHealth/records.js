/**
 * @file Pure normalization for the Internet Health layer (IODA outage summary).
 *
 * IODA (Internet Outage Detection and Analysis, Georgia Tech) scores each
 * country's connectivity disruption over a window from three independent
 * signals: BGP reachability, active probing (ping-slash24) and the network
 * telescope (merit-nt). A score is a relative severity, not a count of users.
 *
 * No Cesium and no fetch here, so the proxy, the browser layer and the tests
 * share one validator.
 */

export const INTERNET_HEALTH_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Heuristic severity bands over IODA's overall score. IODA publishes no fixed
 * scale, so these are display bands only.
 */
export const INTERNET_HEALTH_BANDS = Object.freeze([
  Object.freeze({ id: 'severe', min: 100_000 }),
  Object.freeze({ id: 'major', min: 1_000 }),
  Object.freeze({ id: 'minor', min: 0 }),
]);

/** Map an overall score to a display band id. */
export function severityBand(score) {
  const value = Number.isFinite(score) ? score : 0;
  return INTERNET_HEALTH_BANDS.find((band) => value >= band.min).id;
}

/** Fold `<source>` or `<source>.<method>` score keys into the three signals. */
function signalScores(scores) {
  const out = { bgp: null, activeProbing: null, telescope: null };
  for (const [key, raw] of Object.entries(scores)) {
    if (key === 'overall' || !Number.isFinite(raw)) continue;
    const source = key.split('.')[0];
    const slot =
      source === 'bgp'
        ? 'bgp'
        : source === 'ping-slash24'
          ? 'activeProbing'
          : source === 'merit-nt' || source === 'ucsd-nt'
            ? 'telescope'
            : null;
    if (slot) out[slot] = (out[slot] ?? 0) + raw;
  }
  return out;
}

/**
 * Validate an IODA `/v2/outages/summary?entityType=country` payload.
 * Accepts the v2 envelope (`{ data: [...] }`) or a bare array, and both the
 * current (`entity: {type, code, name}`) and older (`entityType`,
 * `entityCode`) row shapes. Returns null when the payload is unusable so a
 * malformed read can never replace the last good snapshot.
 * @returns {Array<{code: string, name: string|null, score: number,
 *   severity: string, events: number|null, bgp: number|null,
 *   activeProbing: number|null, telescope: number|null}>|null}
 */
export function normalizeInternetHealthSummary(payload) {
  const list = Array.isArray(payload)
    ? payload
    : Array.isArray(payload?.data)
      ? payload.data
      : null;
  if (!list) return null;
  const rows = [];
  const seen = new Set();
  for (const item of list) {
    if (!item || typeof item !== 'object') return null;
    const type = item.entity?.type ?? item.entityType;
    const rawCode = item.entity?.code ?? item.entityCode;
    if (type !== 'country') continue;
    const code = String(rawCode ?? '')
      .trim()
      .toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) continue;
    const scores = item.scores;
    if (!scores || typeof scores !== 'object' || Array.isArray(scores))
      return null;
    const score = scores.overall;
    if (!Number.isFinite(score) || score < 0) return null;
    if (seen.has(code)) continue;
    seen.add(code);
    const name = item.entity?.name ?? item.entityName ?? null;
    const events = item.event_cnt ?? item.eventCount ?? null;
    rows.push({
      code,
      name: typeof name === 'string' && name.trim() ? name.trim() : null,
      score,
      severity: severityBand(score),
      events: Number.isFinite(events) ? events : null,
      ...signalScores(scores),
    });
  }
  rows.sort((a, b) => b.score - a.score || a.code.localeCompare(b.code));
  return rows;
}

/**
 * JSON-safe analyst record for one outage country (voice / MCP query seam).
 * @param {object} row normalized row plus optional `lat`, `lon`,
 *   `cableLandings`.
 */
export function mapInternetHealthAnalystRecord(row) {
  const num = (v) => (Number.isFinite(v) ? v : null);
  return {
    id: `IODA-${row?.code ?? 'XX'}`,
    country: row?.name ?? row?.code ?? null,
    countryCode: row?.code ?? null,
    score: num(row?.score),
    severity: row?.severity ?? null,
    events: num(row?.events),
    bgpScore: num(row?.bgp),
    activeProbingScore: num(row?.activeProbing),
    telescopeScore: num(row?.telescope),
    cableLandings: num(row?.cableLandings),
    lat: num(row?.lat),
    lon: num(row?.lon),
  };
}
