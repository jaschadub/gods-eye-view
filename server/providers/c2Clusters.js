import {
  normalizeFeodoBlocklist,
  normalizeThreatFoxIocs,
  aggregateC2ByCountry,
} from '../../src/layers/c2Clusters/records.js';
import {
  cyberSnapshotProxy,
  fetchUpstreamJson,
} from './cyber/snapshotProxy.js';
import { createIpCountryTable } from './cyber/ipCountry.js';

// abuse.ch: Feodo Tracker's blocklist is keyless and carries ASN + country;
// ThreatFox needs a free Auth-Key (THREATFOX_AUTH_KEY) and its IOCs are
// located by the IP→country table. Only per-country aggregates leave the
// proxy — never individual indicator IPs.
const FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
const THREATFOX_URL = 'https://threatfox-api.abuse.ch/api/v1/';

/** Bounded, cached `/api/c2-clusters` route. */
export function c2ClustersProxy({
  fetchImpl = (...args) => globalThis.fetch(...args),
  env = process.env,
  now = () => Date.now(),
  warn,
  ipCountry = createIpCountryTable({ fetchImpl }),
} = {}) {
  return cyberSnapshotProxy({
    name: 'c2-clusters',
    route: '/api/c2-clusters',
    cacheMs: 15 * 60_000,
    staleMs: 6 * 60 * 60_000,
    env,
    now,
    warn,
    async load({ signal }) {
      const threatFoxKey = String(env.THREATFOX_AUTH_KEY || '').trim();
      const feeds = {};
      const entries = [];

      const feodo = normalizeFeodoBlocklist(
        await fetchUpstreamJson(fetchImpl, FEODO_URL, {
          signal,
          maxBytes: 4 * 1024 * 1024,
        }),
      );
      if (!feodo) throw new Error('invalid_feodo_blocklist');
      entries.push(...feodo);
      feeds.feodo = { status: 'ok', indicators: feodo.length };

      if (!threatFoxKey) {
        feeds.threatfox = { status: 'no_key' };
      } else {
        try {
          const [payload, table] = await Promise.all([
            fetchUpstreamJson(fetchImpl, THREATFOX_URL, {
              signal,
              method: 'POST',
              headers: {
                'Auth-Key': threatFoxKey,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ query: 'get_iocs', days: 1 }),
              maxBytes: 16 * 1024 * 1024,
            }),
            ipCountry.get(signal),
          ]);
          const iocs = normalizeThreatFoxIocs(payload, (ip) =>
            table.lookup(ip),
          );
          if (!iocs) throw new Error('invalid_threatfox_answer');
          entries.push(...iocs);
          feeds.threatfox = { status: 'ok', indicators: iocs.length };
        } catch (error) {
          // ThreatFox is additive: Feodo alone is still a valid snapshot.
          feeds.threatfox = { status: 'unavailable' };
          warn?.('[c2-clusters] ThreatFox failed:', error?.message);
        }
      }

      const { rows, unlocated, indicators } = aggregateC2ByCountry(entries);
      return { rows, unlocated, indicators, feeds };
    },
  });
}
