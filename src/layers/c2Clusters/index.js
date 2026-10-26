import { mapC2AnalystRecord } from './records.js';
import { createCyberSnapshotSource } from '../cyber/source.js';
import { createCyberCountryLayer } from '../cyber/countryLayer.js';
export * from './records.js';

/** Read the same-origin abuse.ch proxy (`/api/c2-clusters`). */
export function createAbuseChC2Source({ fetchImpl } = {}) {
  return createCyberSnapshotSource({
    route: '/api/c2-clusters',
    label: 'C2 clusters', // i18n-ignore: feed name inside English error data
    ...(fetchImpl ? { fetchImpl } : {}),
  });
}

/** Pure projection: per-country C2 aggregates → shaded countries + records. */
export function projectC2Clusters(snapshot, geometry) {
  const countries = [];
  const records = [];
  for (const row of snapshot.rows ?? []) {
    const country = geometry.countries.get(row.code);
    records.push(
      mapC2AnalystRecord({
        ...row,
        name: country?.name ?? null,
        cableLandings: geometry.cableLandings(row.code),
        lat: country?.label.lat,
        lon: country?.label.lon,
      }),
    );
    countries.push({
      code: row.code,
      band: row.band,
      label: `${row.code} ${row.total} C2`,
      weight: row.total,
    });
  }
  return { countries, records };
}

/**
 * C2 Clusters: botnet command-and-control servers from abuse.ch, counted per
 * hosting country (never drawn per IP). Feodo Tracker is keyless; a free
 * ThreatFox Auth-Key adds its last-24 h `ip:port` IOCs.
 */
export function createC2ClustersLayer({ source, overlayHost } = {}) {
  return createCyberCountryLayer({
    id: 'c2-clusters',
    name: 'C2 Clusters',
    icon: '☣️',
    sourceLabel: 'abuse.ch Feodo · ThreatFox',
    updateInterval: 15 * 60_000,
    source,
    overlayHost,
    project: projectC2Clusters,
  });
}
