import {
  INTERNET_HEALTH_WINDOW_MS,
  normalizeInternetHealthSummary,
} from '../../src/layers/internetHealth/records.js';
import { readResponseJsonCapped } from './common/http.js';
import { makeRateLimiter, clientKey } from './common/rate-limit.js';

// IODA (Georgia Tech) public v2 API — keyless. One global snapshot covers
// every viewer, so the proxy keeps a single cached summary rather than a
// per-anchor cache. Only normalized rows leave this proxy.
const IODA_BASE = 'https://api.ioda.inetintel.cc.gatech.edu/v2';
const CACHE_MS = 5 * 60_000;
const STALE_LIMIT_MS = 60 * 60_000;
const FAILURE_COOLDOWN_MS = 60_000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const TIMEOUT_MS = 15_000;

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
  warn = (...args) => console.warn(...args),
} = {}) {
  const allow = makeRateLimiter({ windowMs: 60_000, max: 20, globalMax: 300 });
  let cached = null; // { value, savedAt }
  let inFlight = null;
  let cooldownUntil = 0;

  async function load() {
    const { url, from, until } = iodaSummaryUrl(now());
    const signal = AbortSignal.timeout(TIMEOUT_MS);
    const response = await fetchImpl(url, {
      signal,
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'gods-eye-view-internet-health/1.0',
      },
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw Object.assign(new Error('upstream_unavailable'), {
        status: response.status === 429 ? 429 : 502,
      });
    }
    const payload = await readResponseJsonCapped(
      response,
      MAX_RESPONSE_BYTES,
      signal,
    );
    const rows = normalizeInternetHealthSummary(payload);
    if (!rows) throw new Error('invalid_summary');
    return { from: from * 1000, until: until * 1000, rows };
  }

  async function acquire(peer) {
    const t = now();
    if (cached && t - cached.savedAt < CACHE_MS)
      return { ...cached.value, ageMs: t - cached.savedAt };
    if (t < cooldownUntil || !allow(peer)) {
      if (cached && t - cached.savedAt < STALE_LIMIT_MS)
        return { ...cached.value, ageMs: t - cached.savedAt, stale: true };
      throw Object.assign(new Error('cooling_down'), { status: 429 });
    }
    try {
      inFlight ??= load().finally(() => {
        inFlight = null;
      });
      const value = await inFlight;
      cached = { value, savedAt: now() };
      return { ...value, ageMs: 0 };
    } catch (error) {
      cooldownUntil = now() + FAILURE_COOLDOWN_MS;
      warn('[internet-health] upstream failed:', error?.message);
      if (cached && now() - cached.savedAt < STALE_LIMIT_MS)
        return { ...cached.value, ageMs: now() - cached.savedAt, stale: true };
      throw error;
    }
  }

  async function handler(req, res) {
    const json = (status, value) => {
      if (res.destroyed) return;
      res.writeHead(status, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...(status === 405 ? { Allow: 'GET' } : {}),
        ...([429, 502].includes(status) ? { 'Retry-After': '60' } : {}),
        ...(value?.stale ? { 'X-Data-Stale': 'true' } : {}),
      });
      res.end(JSON.stringify(value));
    };
    if (req.method !== 'GET') return json(405, { error: 'method_not_allowed' });
    const path = (req.url || '/').split('?')[0];
    if (path !== '/' && path !== '')
      return json(404, { error: 'unknown_route' });
    try {
      json(200, await acquire(clientKey(req)));
    } catch (error) {
      json(error.status === 429 ? 429 : 502, {
        error:
          error.status === 429
            ? 'internet_health_rate_limited'
            : 'internet_health_unavailable',
      });
    }
  }

  return {
    name: 'internet-health',
    configureServer({ middlewares }) {
      middlewares.use('/api/internet-health', handler);
    },
    configurePreviewServer({ middlewares }) {
      middlewares.use('/api/internet-health', handler);
    },
  };
}
