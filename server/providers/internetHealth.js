import {
  INTERNET_HEALTH_WINDOW_MS,
  normalizeInternetHealthSummary,
} from '../../src/layers/internetHealth/records.js';
import {
  cyberSnapshotProxy,
  fetchUpstreamJson,
} from './cyber/snapshotProxy.js';

// IODA (Georgia Tech) public v2 API — keyless. One global snapshot covers
// every viewer. Only normalized rows leave this proxy.
const IODA_BASE = 'https://api.ioda.inetintel.cc.gatech.edu/v2';

/** Build the upstream summary URL for a window ending at `untilMs`. */
export function iodaSummaryUrl(untilMs) {
  const until = Math.floor(untilMs / 1000);
  const from = until - Math.floor(INTERNET_HEALTH_WINDOW_MS / 1000);
  const params = new URLSearchParams({
    from: String(from),
    until: String(until),
    entityType: 'country',
    limit: '300',
  });
  return { url: `${IODA_BASE}/outages/summary?${params}`, from, until };
}

/** Bounded, cached IODA outage-summary route for dev and preview. */
export function internetHealthProxy({
  fetchImpl = (...args) => globalThis.fetch(...args),
  now = () => Date.now(),
  warn,
} = {}) {
  return cyberSnapshotProxy({
    name: 'internet-health',
    route: '/api/internet-health',
    now,
    warn,
    async load({ signal, now: t }) {
      const { url, from, until } = iodaSummaryUrl(t);
      const payload = await fetchUpstreamJson(fetchImpl, url, {
        signal,
        maxBytes: 4 * 1024 * 1024,
      });
      const rows = normalizeInternetHealthSummary(payload);
      if (!rows) throw new Error('invalid_summary');
      return { from: from * 1000, until: until * 1000, rows };
    },
  });
}
