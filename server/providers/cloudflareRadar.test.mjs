import test from 'node:test';
import assert from 'node:assert/strict';
import { radarOutagesProxy, bgpEventsProxy } from './cloudflareRadar.js';

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
const ok = (result) =>
  new Response(JSON.stringify({ success: true, errors: [], result }), {
    status: 200,
  });

test('without a token both routes answer 503 no_key and never fetch', async () => {
  let fetched = false;
  const fetchImpl = async () => {
    fetched = true;
  };
  for (const make of [radarOutagesProxy, bgpEventsProxy]) {
    const res = await call(make({ fetchImpl, env: {}, warn: () => {} }));
    assert.equal(res.status, 503);
    assert.equal(res.body.error, 'no_key');
  }
  assert.equal(fetched, false);
});

test('outages: Bearer token, 7d window, JSON format', async () => {
  let seen;
  const res = await call(
    radarOutagesProxy({
      env: { CLOUDFLARE_RADAR_TOKEN: 'cf-token' },
      warn: () => {},
      fetchImpl: async (url, init) => {
        seen = { url: new URL(url), init };
        return ok({ annotations: [] });
      },
    }),
  );
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.rows, []);
  assert.equal(seen.url.pathname, '/client/v4/radar/annotations/outages');
  assert.equal(seen.url.searchParams.get('dateRange'), '7d');
  assert.equal(seen.init.headers.Authorization, 'Bearer cf-token');
  assert.equal(seen.init.redirect, 'error');
});

test('bgp: merges hijacks and leaks newest first; bad envelope is 502', async () => {
  const paths = [];
  const res = await call(
    bgpEventsProxy({
      env: { CLOUDFLARE_RADAR_TOKEN: 't' },
      warn: () => {},
      fetchImpl: async (url) => {
        const u = new URL(url);
        paths.push(u.pathname);
        return u.pathname.endsWith('/hijacks/events')
          ? ok({
              asn_info: [],
              events: [
                {
                  id: 1,
                  hijacker_asn: 1,
                  hijacker_country: 'US',
                  victim_countries: [],
                  min_hijack_ts: '2026-10-01T00:00:00Z',
                },
              ],
            })
          : ok({
              asn_info: [],
              events: [
                {
                  id: 2,
                  leak_asn: 2,
                  countries: [],
                  min_ts: '2026-10-02T00:00:00Z',
                },
              ],
            });
      },
    }),
  );
  assert.equal(res.status, 200);
  assert.deepEqual(
    res.body.rows.map((r) => r.id),
    ['LEAK-2', 'HIJ-1'],
  );
  assert.equal(paths.length, 2);
  const broken = await call(
    bgpEventsProxy({
      env: { CLOUDFLARE_RADAR_TOKEN: 't' },
      warn: () => {},
      fetchImpl: async () =>
        new Response(JSON.stringify({ success: false }), { status: 200 }),
    }),
  );
  assert.equal(broken.status, 502);
});
