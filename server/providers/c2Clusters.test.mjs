import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { c2ClustersProxy } from './c2Clusters.js';
import {
  parseIpCountryCsv,
  ipv4ToNumber,
  createIpCountryTable,
  IP_COUNTRY_URL,
} from './cyber/ipCountry.js';

const TABLE = [
  `${ipv4ToNumber('5.0.0.0')},${ipv4ToNumber('5.255.255.255')},RU`,
  `${ipv4ToNumber('50.0.0.0')},${ipv4ToNumber('50.255.255.255')},US`,
].join('\n');

function harness(fetchImpl, env = {}, extra = {}) {
  const plugin = c2ClustersProxy({
    fetchImpl,
    env,
    warn: () => {},
    ipCountry: { get: async () => parseIpCountryCsv(TABLE, { minRows: 1 }) },
    ...extra,
  });
  let handler;
  plugin.configureServer({ middlewares: { use: (_p, fn) => (handler = fn) } });
  return () =>
    new Promise((resolve) => {
      const res = {
        destroyed: false,
        writeHead(status, headers) {
          this.status = status;
          this.headers = headers;
        },
        end(body) {
          resolve({ status: this.status, body: JSON.parse(body) });
        },
      };
      handler({ method: 'GET', url: '/', headers: {}, socket: {} }, res);
    });
}

const json = (value) =>
  new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
const FEODO = [
  {
    ip_address: '50.16.16.211',
    port: 443,
    status: 'online',
    as_number: 14618,
    as_name: 'AMAZON-AES',
    country: 'US',
    malware: 'QakBot',
  },
];

test('ip table: binary search, strict parsing', () => {
  const table = parseIpCountryCsv(TABLE, { minRows: 1 });
  assert.equal(table.lookup('5.6.7.8'), 'RU');
  assert.equal(table.lookup('50.16.16.211'), 'US');
  assert.equal(table.lookup('8.8.8.8'), null);
  assert.equal(table.lookup('not-an-ip'), null);
  assert.throws(() => parseIpCountryCsv('1,0,US', { minRows: 1 }));
  assert.throws(() => parseIpCountryCsv(TABLE), /truncated/);
});

test('ip table loader downloads once and serves from the disk cache', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'gev-ipdb-'));
  try {
    let calls = 0;
    const fetchImpl = async (url) => {
      calls++;
      assert.equal(url, IP_COUNTRY_URL);
      return new Response(TABLE);
    };
    const first = createIpCountryTable({
      fetchImpl,
      cacheDir: dir,
      minRows: 1,
    });
    assert.equal((await first.get()).lookup('5.1.1.1'), 'RU');
    assert.ok(existsSync(path.join(dir, 'asn-country-ipv4-num.csv')));
    const second = createIpCountryTable({
      fetchImpl,
      cacheDir: dir,
      minRows: 1,
    });
    assert.equal((await second.get()).lookup('50.1.1.1'), 'US');
    assert.equal(calls, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ip table loader keeps a stale disk copy when the network fails', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'gev-ipdb-'));
  try {
    writeFileSync(path.join(dir, 'asn-country-ipv4-num.csv'), TABLE);
    const table = createIpCountryTable({
      fetchImpl: async () => new Response('x', { status: 500 }),
      cacheDir: dir,
      minRows: 1,
      now: () => Date.now() + 30 * 24 * 60 * 60_000,
    });
    assert.equal((await table.get()).lookup('5.1.1.1'), 'RU');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('keyless: Feodo only, ThreatFox reported as no_key, no IPs leave', async () => {
  const urls = [];
  const call = harness(async (url) => {
    urls.push(url);
    return json(FEODO);
  });
  const { status, body } = await call();
  assert.equal(status, 200);
  assert.equal(urls.length, 1);
  assert.equal(body.feeds.threatfox.status, 'no_key');
  assert.equal(body.rows[0].code, 'US');
  assert.ok(!JSON.stringify(body).includes('50.16.16.211'));
});

test('with a ThreatFox key: POSTs get_iocs with Auth-Key and merges', async () => {
  let threatFoxInit;
  const call = harness(
    async (url, init) => {
      if (url.includes('threatfox')) {
        threatFoxInit = init;
        return json({
          query_status: 'ok',
          data: [
            {
              ioc: '5.6.7.8:4444',
              ioc_type: 'ip:port',
              malware_printable: 'Cobalt Strike',
            },
          ],
        });
      }
      return json(FEODO);
    },
    { THREATFOX_AUTH_KEY: 'tf-key' },
  );
  const { body } = await call();
  assert.equal(threatFoxInit.method, 'POST');
  assert.equal(threatFoxInit.headers['Auth-Key'], 'tf-key');
  assert.deepEqual(JSON.parse(threatFoxInit.body), {
    query: 'get_iocs',
    days: 1,
  });
  assert.equal(body.feeds.threatfox.status, 'ok');
  assert.deepEqual(
    body.rows.map((r) => r.code),
    ['RU', 'US'].sort(),
  );
});

test('a ThreatFox failure degrades to Feodo; a Feodo failure is a 502', async () => {
  const degraded = harness(
    async (url) =>
      url.includes('threatfox')
        ? new Response('no', { status: 401 })
        : json(FEODO),
    { THREATFOX_AUTH_KEY: 'bad' },
  );
  const ok = await degraded();
  assert.equal(ok.status, 200);
  assert.equal(ok.body.feeds.threatfox.status, 'unavailable');
  const broken = harness(async () => new Response('x', { status: 500 }));
  assert.equal((await broken()).status, 502);
});
