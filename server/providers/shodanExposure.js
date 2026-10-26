import {
  EXPOSURE_PRESETS,
  normalizeShodanCountryFacet,
  mergeExposureFacets,
} from '../../src/layers/exposure/records.js';
import {
  cyberSnapshotProxy,
  fetchUpstreamJson,
} from './cyber/snapshotProxy.js';

// Shodan (SHODAN_API_KEY). host/count returns totals + facets only and does
// not spend query credits; calls are spaced to Shodan's 1 request/second API
// rate. The key stays server-side; only per-country counts leave.
const SHODAN_COUNT_URL = 'https://api.shodan.io/shodan/host/count';
const COUNTRY_FACET = 'country:100';
const SPACING_MS = 1_100;

/** `/api/exposure`: per-country exposed-service counts for each preset. */
export function shodanExposureProxy({
  fetchImpl = (...args) => globalThis.fetch(...args),
  env = process.env,
  now = () => Date.now(),
  warn,
  sleep = (ms, signal) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, ms);
      signal?.addEventListener('abort', () => {
        clearTimeout(timer);
        reject(signal.reason);
      });
    }),
} = {}) {
  return cyberSnapshotProxy({
    name: 'exposure',
    route: '/api/exposure',
    keyEnv: 'SHODAN_API_KEY',
    // Exposure moves slowly; a long cache keeps the key's API budget intact.
    cacheMs: 6 * 60 * 60_000,
    staleMs: 24 * 60 * 60_000,
    timeoutMs: 30_000,
    env,
    now,
    warn,
    async load({ key, signal }) {
      const results = [];
      for (const [index, preset] of EXPOSURE_PRESETS.entries()) {
        if (index > 0) await sleep(SPACING_MS, signal);
        const params = new URLSearchParams({
          key,
          query: preset.query,
          facets: COUNTRY_FACET,
        });
        const facet = normalizeShodanCountryFacet(
          await fetchUpstreamJson(fetchImpl, `${SHODAN_COUNT_URL}?${params}`, {
            signal,
          }),
        );
        if (!facet) throw new Error('invalid_shodan_facet');
        results.push({ id: preset.id, facet });
      }
      const { rows, totals } = mergeExposureFacets(results);
      return {
        presets: EXPOSURE_PRESETS.map(({ id, query }) => ({ id, query })),
        totals,
        rows,
      };
    },
  });
}
