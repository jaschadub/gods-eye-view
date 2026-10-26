import {
  normalizeRadarOutages,
  normalizeBgpHijacks,
  normalizeBgpLeaks,
} from '../../src/layers/radar/records.js';
import {
  cyberSnapshotProxy,
  fetchUpstreamJson,
} from './cyber/snapshotProxy.js';

// Cloudflare Radar (free API token with Radar read permission,
// CLOUDFLARE_RADAR_TOKEN). The token stays server-side; the browser gets
// only normalized rows.
const RADAR_BASE = 'https://api.cloudflare.com/client/v4/radar';
export const RADAR_TOKEN_ENV = 'CLOUDFLARE_RADAR_TOKEN';
const WINDOW = '7d';

const radarGet = (fetchImpl, path, params, { key, signal }) =>
  fetchUpstreamJson(
    fetchImpl,
    `${RADAR_BASE}${path}?${new URLSearchParams({ ...params, format: 'json' })}`,
    { signal, headers: { Authorization: `Bearer ${key}` } },
  );

/** `/api/radar-outages`: outage annotations over the last 7 days. */
export function radarOutagesProxy({
  fetchImpl = (...args) => globalThis.fetch(...args),
  env = process.env,
  now = () => Date.now(),
  warn,
} = {}) {
  return cyberSnapshotProxy({
    name: 'radar-outages',
    route: '/api/radar-outages',
    keyEnv: RADAR_TOKEN_ENV,
    cacheMs: 10 * 60_000,
    env,
    now,
    warn,
    async load({ key, signal }) {
      const rows = normalizeRadarOutages(
        await radarGet(
          fetchImpl,
          '/annotations/outages',
          { dateRange: WINDOW, limit: '200' },
          { key, signal },
        ),
      );
      if (!rows) throw new Error('invalid_outages');
      return { window: WINDOW, rows };
    },
  });
}

/** `/api/bgp-events`: hijack and route-leak events over the last 7 days. */
export function bgpEventsProxy({
  fetchImpl = (...args) => globalThis.fetch(...args),
  env = process.env,
  now = () => Date.now(),
  warn,
} = {}) {
  return cyberSnapshotProxy({
    name: 'bgp-events',
    route: '/api/bgp-events',
    keyEnv: RADAR_TOKEN_ENV,
    cacheMs: 10 * 60_000,
    env,
    now,
    warn,
    async load({ key, signal }) {
      const page = {
        dateRange: WINDOW,
        per_page: '100',
        sortBy: 'TIME',
        sortOrder: 'DESC',
      };
      const [hijackPayload, leakPayload] = await Promise.all([
        radarGet(fetchImpl, '/bgp/hijacks/events', page, { key, signal }),
        radarGet(fetchImpl, '/bgp/leaks/events', page, { key, signal }),
      ]);
      const hijacks = normalizeBgpHijacks(hijackPayload);
      const leaks = normalizeBgpLeaks(leakPayload);
      if (!hijacks || !leaks) throw new Error('invalid_bgp_events');
      const rows = [...hijacks, ...leaks].sort(
        (a, b) => (b.startedMs ?? 0) - (a.startedMs ?? 0),
      );
      return { window: WINDOW, rows };
    },
  });
}
