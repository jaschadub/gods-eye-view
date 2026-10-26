import test from 'node:test';
import assert from 'node:assert/strict';
import { shodanExposureProxy } from './shodanExposure.js';
import { EXPOSURE_PRESETS } from '../../src/layers/exposure/records.js';

function call(plugin) {
  let handler;
  plugin.configureServer({ middlewares: { use: (_p, fn) => (handler = fn) } });
  return new Promise((resolve) => {
    const res = {
      destroyed: false,
      writeHead(status) {
        this.status = status;
      },
      end(body) {
        resolve({ status: this.status, body: JSON.parse(body) });
      },
    };
    handler({ method: 'GET', url: '/', headers: {}, socket: {} }, res);
  });
}

test('no key: 503 no_key without contacting Shodan', async () => {
  let fetched = false;
  const res = await call(
    shodanExposureProxy({
      env: {},
      warn: () => {},
      fetchImpl: async () => {
        fetched = true;
      },
    }),
  );
  assert.equal(res.status, 503);
  assert.equal(res.body.error, 'no_key');
  assert.equal(fetched, false);
});

test('queries each preset with country facets, spaced, key never echoed', async () => {
  const queries = [];
  const sleeps = [];
  const res = await call(
    shodanExposureProxy({
      env: { SHODAN_API_KEY: 'shodan-secret' },
      warn: () => {},
      sleep: async (ms) => sleeps.push(ms),
      fetchImpl: async (url) => {
        const u = new URL(url);
        assert.equal(u.pathname, '/shodan/host/count');
        assert.equal(u.searchParams.get('facets'), 'country:100');
        queries.push(u.searchParams.get('query'));
        return new Response(
          JSON.stringify({
            matches: [],
            total: 5,
            facets: { country: [{ value: 'US', count: 5 }] },
          }),
        );
      },
    }),
  );
  assert.equal(res.status, 200);
  assert.deepEqual(
    queries,
    EXPOSURE_PRESETS.map((p) => p.query),
  );
  assert.equal(sleeps.length, EXPOSURE_PRESETS.length - 1);
  assert.ok(sleeps.every((ms) => ms >= 1000));
  assert.equal(res.body.rows[0].total, 5 * EXPOSURE_PRESETS.length);
  assert.ok(!JSON.stringify(res.body).includes('shodan-secret'));
});

test('a malformed facet is a 502', async () => {
  const res = await call(
    shodanExposureProxy({
      env: { SHODAN_API_KEY: 'k' },
      warn: () => {},
      sleep: async () => {},
      fetchImpl: async () => new Response(JSON.stringify({ error: 'x' })),
    }),
  );
  assert.equal(res.status, 502);
});
