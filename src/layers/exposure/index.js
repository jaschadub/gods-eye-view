import { mapExposureRecord } from './records.js';
import { createCyberSnapshotSource } from '../cyber/source.js';
import {
  createCyberCountryLayer,
  compactNumber,
} from '../cyber/countryLayer.js';
export * from './records.js';

export function createShodanExposureSource({ fetchImpl } = {}) {
  return createCyberSnapshotSource({
    route: '/api/exposure',
    label: 'Exposure', // i18n-ignore: feed name inside English error data
    ...(fetchImpl ? { fetchImpl } : {}),
  });
}

/** Pure projection: per-country exposure counts → shading + records. */
export function projectExposure(snapshot, geometry) {
  const countries = [];
  const records = [];
  for (const row of snapshot.rows ?? []) {
    const country = geometry.countries.get(row.code);
    records.push(
      mapExposureRecord({
        ...row,
        name: country?.name ?? null,
        cableLandings: geometry.cableLandings(row.code),
        lat: country?.label.lat,
        lon: country?.label.lon,
      }),
    );
    const ics = row.byPreset?.ics;
    countries.push({
      code: row.code,
      band: row.band,
      label: `${row.code} ${compactNumber(row.total)}${ics ? ` · ICS ${compactNumber(ics)}` : ''}`,
      weight: Math.log10(row.total + 1) * 1000,
    });
  }
  return { countries, records };
}

/**
 * Exposure: internet-facing ICS, RDP, database and SMB services per country
 * (Shodan facet counts — no hosts, no IPs). Needs SHODAN_API_KEY.
 */
export function createExposureLayer({ source, overlayHost } = {}) {
  return createCyberCountryLayer({
    id: 'exposure',
    name: 'Exposure',
    icon: '🧲',
    sourceLabel: 'Shodan',
    updateInterval: 60 * 60_000,
    requiresKeyId: 'shodan',
    source,
    overlayHost,
    project: projectExposure,
  });
}
