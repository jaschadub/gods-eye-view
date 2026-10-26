import { readResponseJsonCapped } from '../common/http.js';
import { makeRateLimiter, clientKey } from '../common/rate-limit.js';

/**
 * Shared single-snapshot proxy for the cyber layer pack.
 *
 * Every cyber feed is one global (or per-variant) snapshot that every viewer
 * shares, so this keeps a small keyed cache instead of per-anchor caches:
 * fresh for `cacheMs`, served stale up to `staleMs` when upstream fails, a
 * failure cooldown, a per-peer rate limit, single-flight loads, and sanitized
 * errors. Keyed feeds answer 503 `{error:'no_key'}` while their env var is
 * unset, which the browser layer turns into the panel's key guidance.
 *
 * @param {object} options
 * @param {string} options.name Plugin and log name.
 * @param {string} options.route Mount path, e.g. '/api/internet-health'.
 * @param {(ctx: {variant: string|null, key: string|null, signal: AbortSignal,
 *   now: number}) => Promise<object>} options.load Fetch + normalize; must
 *   throw on malformed data so a bad read never replaces a good snapshot.
 * @param {string} [options.keyEnv] Env var that must hold a key.
 * @param {string[]} [options.variants] Allowed `?variant=` values (first is
 *   the default).
 */
export function cyberSnapshotProxy({
  name,
  route,
  load,
  keyEnv = null,
  variants = null,
  cacheMs = 5 * 60_000,
  staleMs = 60 * 60_000,
  failureCooldownMs = 60_000,
  timeoutMs = 20_000,
  env = process.env,
  now = () => Date.now(),
  warn = (...args) => console.warn(...args),
}) {
  const allow = makeRateLimiter({ windowMs: 60_000, max: 20, globalMax: 300 });
  const cache = new Map(); // variant -> { value, savedAt }
  const inFlight = new Map();
  const cooldownUntil = new Map();
  const readKey = () => (keyEnv ? String(env[keyEnv] || '').trim() : null);

  async function acquire(variant, peer) {
    const t = now();
    const cached = cache.get(variant);
    const fresh = (entry) => ({ ...entry.value, ageMs: now() - entry.savedAt });
    const stale = (entry) => ({ ...fresh(entry), stale: true });
    if (cached && t - cached.savedAt < cacheMs) return fresh(cached);
    if (t < (cooldownUntil.get(variant) ?? 0) || !allow(peer)) {
      if (cached && t - cached.savedAt < staleMs) return stale(cached);
      throw Object.assign(new Error('cooling_down'), { status: 429 });
    }
    try {
      if (!inFlight.has(variant)) {
        const signal = AbortSignal.timeout(timeoutMs);
        inFlight.set(
          variant,
          load({ variant, key: readKey(), signal, now: now() }).finally(() =>
            inFlight.delete(variant),
          ),
        );
      }
      const value = await inFlight.get(variant);
      const entry = { value, savedAt: now() };
      cache.set(variant, entry);
      return fresh(entry);
    } catch (error) {
      cooldownUntil.set(variant, now() + failureCooldownMs);
      warn(`[${name}] upstream failed:`, error?.message);
      if (cached && now() - cached.savedAt < staleMs) return stale(cached);
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
    const [path, query = ''] = (req.url || '/').split('?');
    if (path !== '/' && path !== '')
      return json(404, { error: 'unknown_route' });
    let variant = null;
    if (variants) {
      variant = new URLSearchParams(query).get('variant') || variants[0];
      if (!variants.includes(variant))
        return json(400, { error: 'unknown_variant' });
    }
    if (keyEnv && !readKey()) return json(503, { error: 'no_key' });
    try {
      json(200, await acquire(variant, clientKey(req)));
    } catch (error) {
      const limited = error.status === 429;
      json(limited ? 429 : 502, {
        error: limited ? `${name}_rate_limited` : `${name}_unavailable`,
      });
    }
  }

  return {
    name,
    configureServer({ middlewares }) {
      middlewares.use(route, handler);
    },
    configurePreviewServer({ middlewares }) {
      middlewares.use(route, handler);
    },
  };
}

/**
 * Fetch JSON from a fixed upstream with the pack's hardening: no redirects,
 * a byte cap, and an error that never echoes upstream bodies or keys.
 */
export async function fetchUpstreamJson(
  fetchImpl,
  url,
  { signal, headers = {}, method = 'GET', body, maxBytes = 8 * 1024 * 1024 },
) {
  const response = await fetchImpl(url, {
    method,
    signal,
    redirect: 'error',
    headers: {
      Accept: 'application/json',
      'User-Agent': 'gods-eye-view-cyber/1.0',
      ...headers,
    },
    ...(body === undefined ? {} : { body }),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw Object.assign(new Error(`upstream_http_${response.status}`), {
      status: response.status === 429 ? 429 : 502,
    });
  }
  return readResponseJsonCapped(response, maxBytes, signal);
}
