import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeRadarOutages,
  normalizeBgpHijacks,
  normalizeBgpLeaks,
  hijackBand,
  bgpCountryBands,
  mapRadarOutageRecord,
  mapBgpEventRecord,
} from './records.js';
import { projectBgpEvents, projectRadarOutages } from './index.js';

// Field names follow cloudflare-typescript's Radar types.
const outages = {
  success: true,
  errors: [],
  result: {
    annotations: [
      {
        id: '101',
        asns: [12880],
        asnsDetails: [],
        dataSource: 'ALL',
        description: 'Government-directed shutdown',
        endDate: null,
        eventType: 'OUTAGE',
        locations: ['IR'],
        locationsDetails: [{ code: 'IR', name: 'Iran' }],
        outage: {
          outageCause: 'GOVERNMENT_DIRECTED',
          outageType: 'NATIONWIDE',
        },
        scope: null,
        startDate: '2026-10-24T08:00:00Z',
        linkedUrl: 'https://radar.cloudflare.com/',
      },
      {
        id: '102',
        asns: [],
        locations: ['IR', 'IQ'],
        locationsDetails: [null],
        outage: { outageCause: 'CABLE_CUT', outageType: 'REGIONAL' },
        startDate: '2026-10-20T00:00:00Z',
        endDate: '2026-10-20T06:00:00Z',
      },
      { id: '103', locations: ['US'], startDate: 'not a date' },
    ],
  },
};

const hijacks = {
  success: true,
  result: {
    asn_info: [{ asn: 64500, country_code: 'RU', org_name: 'Example Transit' }],
    events: [
      {
        id: 7,
        confidence_score: 9,
        hijacker_asn: 64500,
        hijacker_country: 'RU',
        victim_asns: [13335],
        victim_countries: ['US', 'DE'],
        prefixes: ['1.1.1.0/24'],
        min_hijack_ts: '2026-10-25T01:00:00Z',
        max_hijack_ts: '2026-10-25T02:00:00Z',
        on_going_count: 1,
        is_stale: false,
      },
    ],
    total_monitors: 400,
  },
};

const leaks = {
  success: true,
  result: {
    asn_info: [{ asn: 64501, country_code: 'BR', org_name: 'Leaky ISP' }],
    events: [
      {
        id: 9,
        countries: ['BR', 'AR'],
        leak_asn: 64501,
        prefix_count: 40,
        finished: false,
        min_ts: '2026-10-24T00:00:00Z',
        max_ts: '2026-10-24T01:00:00Z',
      },
    ],
  },
};

test('outages fold per country, ongoing nationwide is high', () => {
  const rows = normalizeRadarOutages(outages);
  assert.deepEqual(
    rows.map((r) => [r.code, r.band, r.outages, r.ongoing]),
    [
      ['IR', 'high', 2, 1],
      ['IQ', 'low', 1, 0],
    ],
  );
  assert.equal(rows[0].name, 'Iran');
  assert.equal(rows[0].latest.cause, 'GOVERNMENT_DIRECTED');
  assert.deepEqual(rows[0].causes, ['CABLE_CUT', 'GOVERNMENT_DIRECTED']);
  const record = mapRadarOutageRecord(rows[0]);
  assert.equal(record.outageType, 'NATIONWIDE');
  assert.equal(record.ongoing, 1);
});

test('envelopes that did not succeed are refused', () => {
  assert.equal(normalizeRadarOutages({ success: false, result: {} }), null);
  assert.equal(normalizeRadarOutages({ success: true, result: {} }), null);
  assert.equal(normalizeBgpHijacks({ success: true, result: {} }), null);
  assert.equal(
    normalizeBgpLeaks({ success: true, result: { events: [{}] } }),
    null,
  );
});

test('hijacks and leaks normalize with ASN names and bands', () => {
  const [h] = normalizeBgpHijacks(hijacks);
  assert.equal(h.asnName, 'Example Transit');
  assert.equal(h.band, 'high');
  assert.equal(h.ongoing, true);
  assert.deepEqual(h.victimCountries, ['US', 'DE']);
  const [l] = normalizeBgpLeaks(leaks);
  assert.equal(l.country, 'BR');
  assert.equal(l.prefixes, 40);
  assert.equal(l.ongoing, true);
  assert.equal(hijackBand(4), 'low');
  assert.equal(hijackBand(5), 'medium');
  assert.equal(mapBgpEventRecord(h).asn, 'AS64500');
});

test('country bands: source takes event band, victims at least low', () => {
  const events = [...normalizeBgpHijacks(hijacks), ...normalizeBgpLeaks(leaks)];
  const bands = bgpCountryBands(events);
  assert.equal(bands.get('RU').band, 'high');
  assert.equal(bands.get('US').band, 'low');
  assert.equal(bands.get('BR').band, 'medium');
  assert.equal(bands.get('AR').band, 'low');
});

test('BGP projection draws source→victim arcs, skipping self-arcs', () => {
  const events = [...normalizeBgpHijacks(hijacks), ...normalizeBgpLeaks(leaks)];
  const geometry = {
    countries: new Map([['RU', { label: { lat: 60, lon: 90 } }]]),
    cableLandings: () => null,
  };
  const { arcs, records, countries } = projectBgpEvents(
    { rows: events },
    geometry,
  );
  assert.deepEqual(
    arcs.map((a) => `${a.from}>${a.to}`),
    ['RU>US', 'RU>DE', 'BR>AR'],
  );
  assert.equal(records[0].lat, 60);
  assert.ok(countries.find((c) => c.code === 'RU'));
});

test('outage projection labels ongoing outages with their cause', () => {
  const geometry = {
    countries: new Map(),
    cableLandings: () => 3,
  };
  const { countries, records } = projectRadarOutages(
    { rows: normalizeRadarOutages(outages) },
    geometry,
  );
  assert.equal(countries[0].label, 'IR ONGOING government directed');
  assert.equal(records[0].cableLandings, 3);
});
