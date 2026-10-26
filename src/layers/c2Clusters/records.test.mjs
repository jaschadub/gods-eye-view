import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeFeodoBlocklist,
  normalizeThreatFoxIocs,
  aggregateC2ByCountry,
  mapC2AnalystRecord,
  c2Band,
} from './records.js';
import { projectC2Clusters } from './index.js';

// Shape copied from the live feodotracker ipblocklist.json.
const feodo = [
  {
    ip_address: '50.16.16.211',
    port: 443,
    status: 'online',
    hostname: 'ec2-50-16-16-211.compute-1.amazonaws.com',
    as_number: 14618,
    as_name: 'AMAZON-AES',
    country: 'US',
    first_seen: '2025-12-30 13:56:31',
    last_online: '2026-03-12',
    malware: 'QakBot',
  },
  {
    ip_address: '162.243.103.246',
    port: 8080,
    status: 'offline',
    hostname: null,
    as_number: 14061,
    as_name: 'DIGITALOCEAN-ASN',
    country: 'US',
    first_seen: '2022-06-04 21:24:53',
    last_online: '2026-03-07',
    malware: 'Emotet',
  },
];

const threatfox = {
  query_status: 'ok',
  data: [
    {
      ioc: '50.16.16.211:443',
      ioc_type: 'ip:port',
      malware: 'win.qakbot',
      malware_printable: 'QakBot',
      confidence_level: 100,
      first_seen: '2026-10-25 10:00:00 UTC',
    },
    {
      ioc: '5.6.7.8:4444',
      ioc_type: 'ip:port',
      malware_printable: 'Cobalt Strike',
      confidence_level: 75,
    },
    {
      ioc: '9.9.9.9:80',
      ioc_type: 'ip:port',
      malware_printable: 'Sliver',
    },
    { ioc: 'evil.example', ioc_type: 'domain', malware_printable: 'X' },
  ],
};

test('Feodo normalization keeps ASN and country, refuses non-arrays', () => {
  const rows = normalizeFeodoBlocklist(feodo);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].asn, 14618);
  assert.equal(rows[0].online, true);
  assert.equal(rows[1].online, false);
  assert.equal(normalizeFeodoBlocklist({}), null);
  assert.equal(normalizeFeodoBlocklist([null]), null);
});

test('ThreatFox keeps ip:port IOCs and locates them by lookup', () => {
  const lookup = (ip) => ({ '5.6.7.8': 'RU', '50.16.16.211': 'US' })[ip];
  const rows = normalizeThreatFoxIocs(threatfox, lookup);
  assert.equal(rows.length, 3);
  assert.equal(rows[1].country, 'RU');
  assert.equal(rows[2].country, null);
  assert.deepEqual(normalizeThreatFoxIocs({ query_status: 'no_result' }), []);
  assert.equal(normalizeThreatFoxIocs({ query_status: 'illegal' }), null);
});

test('aggregation dedupes ip:port (Feodo wins) and never guesses a country', () => {
  const lookup = (ip) => ({ '5.6.7.8': 'RU', '50.16.16.211': 'US' })[ip];
  const { rows, unlocated, indicators } = aggregateC2ByCountry([
    ...normalizeThreatFoxIocs(threatfox, lookup),
    ...normalizeFeodoBlocklist(feodo),
  ]);
  assert.equal(indicators, 4);
  assert.equal(unlocated, 1);
  assert.deepEqual(
    rows.map((r) => [r.code, r.total, r.online]),
    [
      ['US', 2, 1],
      ['RU', 1, 1],
    ],
  );
  const us = rows[0];
  assert.deepEqual(us.sources, ['feodo']);
  // One indicator each: ties break on ascending ASN.
  assert.deepEqual(
    us.asns.map((a) => a.asn),
    [14061, 14618],
  );
  assert.deepEqual(
    us.families.map((f) => f.name),
    ['Emotet', 'QakBot'],
  );
});

test('bands and analyst records', () => {
  assert.equal(c2Band(0), 'low');
  assert.equal(c2Band(5), 'medium');
  assert.equal(c2Band(25), 'high');
  const record = mapC2AnalystRecord({
    code: 'US',
    total: 2,
    online: 1,
    families: [{ name: 'QakBot', count: 1 }],
    asns: [{ asn: 14618, name: 'AMAZON-AES', count: 1 }],
  });
  assert.equal(record.topAsn, 'AS14618');
  assert.equal(record.topFamily, 'QakBot');
  assert.doesNotThrow(() => JSON.stringify(record));
});

test('projection joins country geometry and cable landings', () => {
  const geometry = {
    countries: new Map([
      ['US', { name: 'United States', label: { lat: 39, lon: -98 } }],
    ]),
    cableLandings: (code) => (code === 'US' ? 90 : null),
  };
  const { countries, records } = projectC2Clusters(
    {
      rows: [
        { code: 'US', total: 30, online: 3, band: 'high', families: [] },
        { code: 'ZZ', total: 1, online: 0, band: 'low', families: [] },
      ],
    },
    geometry,
  );
  assert.equal(countries[0].band, 'high');
  assert.equal(countries[0].label, 'US 30 C2');
  assert.equal(records[0].country, 'United States');
  assert.equal(records[0].cableLandings, 90);
  assert.equal(records[1].country, 'ZZ');
});
