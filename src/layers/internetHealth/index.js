import { mapInternetHealthAnalystRecord } from './records.js';
import {
  createCyberCountryLayer,
  compactNumber,
} from '../cyber/countryLayer.js';
export * from './records.js';
export { createIodaInternetHealthSource } from './source.js';

const BAND_FOR_SEVERITY = Object.freeze({
  severe: 'high',
  major: 'medium',
  minor: 'low',
});

/** Pure projection: IODA rows → shaded countries + analyst records. */
export function projectInternetHealth(snapshot, geometry) {
  const countries = [];
  const records = [];
  for (const row of snapshot.rows ?? []) {
    const country = geometry.countries.get(row.code);
    records.push(
      mapInternetHealthAnalystRecord({
        ...row,
        name: row.name ?? country?.name ?? null,
        cableLandings: geometry.cableLandings(row.code),
        lat: country?.label.lat,
        lon: country?.label.lon,
      }),
    );
    countries.push({
      code: row.code,
      band: BAND_FOR_SEVERITY[row.severity] ?? 'low',
      label: `${row.code} ${compactNumber(row.score)}`,
      weight: Math.log10((row.score ?? 0) + 1) * 1000,
    });
  }
  return { countries, records };
}

/**
 * Internet Health: countries with IODA-detected connectivity disruption in the
 * last 24 h, shaded by severity band and labeled with the overall score.
 * Records carry the count of submarine-cable landings in that country.
 */
export function createInternetHealthLayer({ source, overlayHost } = {}) {
  return createCyberCountryLayer({
    id: 'internet-health',
    name: 'Internet Health (24h)',
    icon: '🛜',
    sourceLabel: 'IODA · Georgia Tech',
    updateInterval: 5 * 60_000,
    source,
    overlayHost,
    project: projectInternetHealth,
  });
}
