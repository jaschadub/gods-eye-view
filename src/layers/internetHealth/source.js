import { readResponseJsonCapped } from '../../sources/httpBody.js';

// Portable package: failures stay English data; the Layers panel translates.
const msg = (text) => text;

/** Read the same-origin IODA proxy (`/api/internet-health`). */
export function createIodaInternetHealthSource({
  fetchImpl = (...args) => globalThis.fetch(...args),
} = {}) {
  return {
    async getSnapshot({ signal } = {}) {
      signal?.throwIfAborted();
      const response = await fetchImpl('/api/internet-health', { signal });
      if (!response.ok) {
        // HTTP errors are matched by FEED_ERROR_PATTERNS in ui/statusText.js.
        throw Object.assign(
          new Error(
            response.status === 429
              ? msg('Internet health feed rate limited (HTTP 429)')
              : `Internet health feed unavailable (HTTP ${response.status})`,
          ),
          {
            status: response.status,
            retryable: response.status === 429 || response.status >= 500,
          },
        );
      }
      const payload = await readResponseJsonCapped(
        response,
        2 * 1024 * 1024,
        signal,
      );
      signal?.throwIfAborted();
      if (!Array.isArray(payload?.rows))
        throw new Error(msg('Malformed internet health snapshot'));
      return {
        rows: payload.rows,
        windowFrom: Number.isFinite(payload.from) ? payload.from : null,
        windowUntil: Number.isFinite(payload.until) ? payload.until : null,
        ageMs: Number.isFinite(payload.ageMs) ? payload.ageMs : null,
        stale: payload.stale === true,
      };
    },
  };
}
