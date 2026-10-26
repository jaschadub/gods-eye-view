import test from 'node:test';
import assert from 'node:assert/strict';
import { internetHealthProxy, iodaSummaryUrl } from './internetHealth.js';

function harness(fetchImpl, clock = { t: 1_800_000_000_000 }) {
  const plugin = internetHealthProxy({
    fetchImpl,
    now: () => clock.t,
    warn: () => {},
  });
  let handler;
  plugin.configureServer({
    middlewares: { use: (_path, fn) => (handler = fn) },
  });
  const call = (method = 'GET', url = '/') =>
    new Promise((resolve) => {
      const res = {
        destroyed: false,
        writeHead(status, headers) {
          this.status = status;
          this.headers = headers;
        },
        end(body) {
          resolve({ ...this, body: JSON.parse(body) });
        },
      };
      handler({ method, url, headers: {}, socket: {} }, res);
    });
  return { call, clock };
}

const okBody = {
  data: [
    {
      entity: { type: 'country', code: 'MV', name: 'Maldives' },
      scores: { overall: 6119, bgp: 19 },
      event_cnt: 1,
    },
  ],
};
const okResponse = () =>
  new Response(JSON.stringify(okBody), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });

test('builds a 24 h country summary URL on the IODA v2 host', () => {
  const { url, from, until } = iodaSummaryUrl(1_800_000_000_000);
  assert.equal(until - from, 86400);
  assert.match(
    url,
    /^https:\/\/api\.ioda\.inetintel\.cc\.gatech\.edu\/v2\/outages\/summary\?/,
  );
  assert.match(url, /entityType=country/);
});

test('serves normalized rows and caches for five minutes', async () => {
  let calls = 0;
  const { call, clock } = harness(async () => {
    calls++;
    return okResponse();
  });
  const first = await call();
  assert.equal(first.status, 200);
  assert.equal(first.body.rows[0].code, 'MV');
  assert.equal(first.body.rows[0].severity, 'major');
  clock.t += 60_000;
  await call();
  assert.equal(calls, 1);
  clock.t += 5 * 60_000;
  await call();
  assert.equal(calls, 2);
});

test('falls back to the last good snapshot as stale on upstream failure', async () => {
  let fail = false;
  const { call, clock } = harness(async () =>
    fail ? new Response('nope', { status: 503 }) : okResponse(),
  );
  await call();
  fail = true;
  clock.t += 6 * 60_000;
  const stale = await call();
  assert.equal(stale.status, 200);
  assert.equal(stale.body.stale, true);
  assert.equal(stale.headers['X-Data-Stale'], 'true');
});

test('502 with no cache; rejects non-GET and unknown paths', async () => {
  const { call } = harness(async () => new Response('x', { status: 500 }));
  assert.equal((await call()).status, 502);
  assert.equal((await call('POST')).status, 405);
  assert.equal((await call('GET', '/other')).status, 404);
});

test('refuses a malformed upstream body', async () => {
  const { call } = harness(
    async () => new Response('{"data":"bad"}', { status: 200 }),
  );
  assert.equal((await call()).status, 502);
});
