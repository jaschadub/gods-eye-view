import {
  mapRadarOutageRecord,
  mapBgpEventRecord,
  bgpCountryBands,
} from './records.js';
import { createCyberSnapshotSource } from '../cyber/source.js';
import { createCyberCountryLayer } from '../cyber/countryLayer.js';
export * from './records.js';

/** KEY_SETUP_KEYS id shared by both Radar layers. */
export const RADAR_KEY_ID = 'cloudflare-radar';
const MAX_ARCS = 150;

export function createRadarOutagesSource({ fetchImpl } = {}) {
  return createCyberSnapshotSource({
    route: '/api/radar-outages',
    label: 'Cloudflare Radar outages', // i18n-ignore: feed name inside English error data
    ...(fetchImpl ? { fetchImpl } : {}),
  });
}

export function createBgpEventsSource({ fetchImpl } = {}) {
  return createCyberSnapshotSource({
    route: '/api/bgp-events',
    label: 'BGP events', // i18n-ignore: feed name inside English error data
    ...(fetchImpl ? { fetchImpl } : {}),
  });
}

/** Pure projection: per-country outage rows → shading + records. */
export function projectRadarOutages(snapshot, geometry) {
  const countries = [];
  const records = [];
  for (const row of snapshot.rows ?? []) {
    const country = geometry.countries.get(row.code);
    records.push(
      mapRadarOutageRecord({
        ...row,
        name: row.name ?? country?.name ?? null,
        cableLandings: geometry.cableLandings(row.code),
        lat: country?.label.lat,
        lon: country?.label.lon,
      }),
    );
    const cause = row.latest?.cause
      ? ` ${String(row.latest.cause).toLowerCase().replace(/_/g, ' ')}`
      : '';
    countries.push({
      code: row.code,
      band: row.band,
      label: `${row.code}${row.ongoing ? ' ONGOING' : ''}${cause}`,
      weight: row.ongoing * 100 + row.outages,
    });
  }
  return { countries, records };
}

/**
 * Pure projection: BGP events → involved-country shading, source→affected
 * arcs (hijacker → victim countries, leaker → affected countries) and one
 * analyst record per event.
 */
export function projectBgpEvents(snapshot, geometry) {
  const events = snapshot.rows ?? [];
  const bands = bgpCountryBands(events);
  const countries = [...bands.entries()].map(([code, { band, events: n }]) => ({
    code,
    band,
    label: `${code} ${n} BGP`, // i18n-ignore: protocol acronym on a map label
    weight: n,
  }));
  const arcs = [];
  for (const e of events) {
    if (arcs.length >= MAX_ARCS) break;
    for (const to of e.victimCountries) {
      if (!e.country || to === e.country) continue;
      arcs.push({ id: `${e.id}:${to}`, from: e.country, to, band: e.band });
    }
  }
  const records = events.map((e) => {
    const country = geometry.countries.get(e.country);
    return mapBgpEventRecord({
      ...e,
      lat: country?.label.lat,
      lon: country?.label.lon,
    });
  });
  return { countries, arcs: arcs.slice(0, MAX_ARCS), records };
}

/** Cloudflare Radar outage annotations (cause, type, scope), last 7 days. */
export function createRadarOutagesLayer({ source, overlayHost } = {}) {
  return createCyberCountryLayer({
    id: 'radar-outages',
    name: 'Radar Outages (7d)',
    icon: '📉',
    sourceLabel: 'Cloudflare Radar',
    updateInterval: 10 * 60_000,
    requiresKeyId: RADAR_KEY_ID,
    source,
    overlayHost,
    project: projectRadarOutages,
  });
}

/** Cloudflare Radar BGP hijack and route-leak events, last 7 days. */
export function createBgpEventsLayer({ source, overlayHost } = {}) {
  return createCyberCountryLayer({
    id: 'bgp-events',
    name: 'BGP Events (7d)',
    icon: '🔀',
    sourceLabel: 'Cloudflare Radar BGP',
    updateInterval: 10 * 60_000,
    requiresKeyId: RADAR_KEY_ID,
    source,
    overlayHost,
    project: projectBgpEvents,
  });
}
