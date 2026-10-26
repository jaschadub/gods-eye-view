import { readResponseJsonCapped } from '../../sources/httpBody.js';

// Portable package: failures stay English data; the Layers panel translates.

/**
 * Read one same-origin cyber snapshot route (see
 * server/providers/cyber/snapshotProxy.js).
 *
 * A keyed route answers 503 `{error:'no_key'}` while its provider key is
 * unset; that surfaces as an error with `keyRequired: true` so the layer can
 * report `stats.keyRequired` and the panel can name the missing key.
 *
 * @param {object} options
 * @param {string} options.route e.g. '/api/c2-clusters'
 * @param {string} options.label Feed name used in error text.
 * @param {(payload: object) => boolean} [options.validate] Shape check.
 */
export function createCyberSnapshotSource({
  route,
  label,
  validate = (payload) => Array.isArray(payload?.rows),
  fetchImpl = (...args) => globalThis.fetch(...args),
}) {
  return {
    async getSnapshot({ signal, variant } = {}) {
      signal?.throwIfAborted();
      const url = variant
        ? `${route}?${new URLSearchParams({ variant })}`
        : route;
      const response = await fetchImpl(url, { signal });
      if (!response.ok) {
        let code = null;
        if (response.status === 503) {
          try {
            code = (await response.json())?.error ?? null;
          } catch {
            code = null;
          }
        } else {
          await response.body?.cancel?.();
        }
        const keyRequired = code === 'no_key';
        // HTTP errors are matched by FEED_ERROR_PATTERNS in ui/statusText.js.
        throw Object.assign(
          new Error(
            keyRequired
              ? `${label} needs a provider key (POWER UP)`
              : response.status === 429
                ? `${label} feed rate limited (HTTP 429)`
                : `${label} feed unavailable (HTTP ${response.status})`,
          ),
          {
            status: response.status,
            keyRequired,
            retryable:
              !keyRequired &&
              (response.status === 429 || response.status >= 500),
          },
        );
      }
      const payload = await readResponseJsonCapped(
        response,
        4 * 1024 * 1024,
        signal,
      );
      signal?.throwIfAborted();
      if (!validate(payload)) throw new Error(`Malformed ${label} snapshot`);
      return payload;
    },
  };
}
