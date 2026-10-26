/**
 * @file Pure normalization for the Exposure overlay (Shodan country facets).
 *
 * Each preset is one `GET /shodan/host/count?query=…&facets=country:N` call —
 * the count endpoint returns totals and facets only (no host results) and
 * does not consume query credits. Output is per-country counts of
 * internet-exposed services; no host, IP or banner ever leaves the proxy.
 */

/** Preset queries: id → Shodan query. Order is display order. */
export const EXPOSURE_PRESETS = Object.freeze([
  Object.freeze({ id: 'ics', query: 'tag:ics' }),
  Object.freeze({ id: 'rdp', query: 'port:3389' }),
  Object.freeze({ id: 'databases', query: 'port:27017,9200,6379' }),
  Object.freeze({ id: 'smb', query: 'port:445' }),
]);

const ISO2 = /^[A-Z]{2}$/;

/** Display bands over the per-country total across presets. */
export function exposureBand(total) {
  if (total >= 100_000) return 'high';
  if (total >= 10_000) return 'medium';
  return 'low';
}

/**
 * Validate one `host/count` answer's country facet.
 * @returns {{total: number, countries: Map<string, number>}|null}
 */
export function normalizeShodanCountryFacet(payload) {
  if (!payload || typeof payload !== 'object') return null;
  if (!Number.isFinite(payload.total)) return null;
  const facet = payload.facets?.country;
  if (!Array.isArray(facet)) return null;
  const countries = new Map();
  for (const item of facet) {
    if (!item || typeof item !== 'object') return null;
    const code = String(item.value ?? '').toUpperCase();
    if (!ISO2.test(code) || !Number.isFinite(item.count) || item.count < 0)
      continue;
    countries.set(code, item.count);
  }
  return { total: payload.total, countries };
}

/**
 * Merge per-preset facets into one row per country.
 * @param {Array<{id: string, facet: {total: number, countries: Map}}>} results
 */
export function mergeExposureFacets(results) {
  const rows = new Map();
  const totals = {};
  for (const { id, facet } of results) {
    totals[id] = facet.total;
    for (const [code, count] of facet.countries) {
      let row = rows.get(code);
      if (!row) {
        row = { code, total: 0, byPreset: {} };
        rows.set(code, row);
      }
      row.byPreset[id] = count;
      row.total += count;
    }
  }
  return {
    totals,
    rows: [...rows.values()]
      .map((row) => ({ ...row, band: exposureBand(row.total) }))
      .sort((a, b) => b.total - a.total || a.code.localeCompare(b.code)),
  };
}

/** JSON-safe analyst record for one country's exposure. */
export function mapExposureRecord(row) {
  const num = (v) => (Number.isFinite(v) ? v : null);
  return {
    id: `EXP-${row?.code ?? 'XX'}`,
    country: row?.name ?? row?.code ?? null,
    countryCode: row?.code ?? null,
    exposedTotal: num(row?.total),
    ics: num(row?.byPreset?.ics),
    rdp: num(row?.byPreset?.rdp),
    databases: num(row?.byPreset?.databases),
    smb: num(row?.byPreset?.smb),
    cableLandings: num(row?.cableLandings),
    lat: num(row?.lat),
    lon: num(row?.lon),
  };
}
