import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeInternetHealthSummary,
  severityBand,
  mapInternetHealthAnalystRecord,
} from './records.js';
import {
  indexCountries,
  landingPoints,
  countLandingsIn,
  loadInternetHealthGeometry,
} from './geometry.js';

test('normalizes the v2 envelope, sorts by score, folds signal keys', () => {
  const rows = normalizeInternetHealthSummary({
    data: [
      {
        entity: { type: 'country', code: 'mv', name: 'Maldives' },
        scores: { overall: 6119.2, 'ping-slash24': 6000, bgp: 119.2 },
        event_cnt: 2,
      },
      {
        entity: { type: 'country', code: 'IR', name: 'Iran' },
        scores: {
          overall: 250000,
          'bgp.median': 100000,
          'merit-nt.median': 150000,
        },
        event_cnt: 5,
      },
      { entity: { type: 'region', code: '1234' }, scores: { overall: 9 } },
    ],
  });
  assert.equal(rows.length, 2);
  assert.deepEqual(
    rows.map((r) => [r.code, r.severity]),
    [
      ['IR', 'severe'],
      ['MV', 'major'],
    ],
  );
  assert.equal(rows[0].bgp, 100000);
  assert.equal(rows[0].telescope, 150000);
  assert.equal(rows[1].activeProbing, 6000);
  assert.equal(rows[1].events, 2);
});

test('accepts the older entityType/entityCode row shape', () => {
  const rows = normalizeInternetHealthSummary([
    { entityType: 'country', entityCode: 'MV', scores: { overall: 10 } },
  ]);
  assert.equal(rows[0].code, 'MV');
  assert.equal(rows[0].severity, 'minor');
});

test('refuses malformed payloads instead of returning partial data', () => {
  assert.equal(normalizeInternetHealthSummary(null), null);
  assert.equal(normalizeInternetHealthSummary({ data: 'x' }), null);
  assert.equal(
    normalizeInternetHealthSummary({
      data: [{ entity: { type: 'country', code: 'US' }, scores: {} }],
    }),
    null,
  );
  assert.equal(
    normalizeInternetHealthSummary({
      data: [
        { entity: { type: 'country', code: 'US' }, scores: { overall: -1 } },
      ],
    }),
    null,
  );
});

test('severity bands', () => {
  assert.equal(severityBand(0), 'minor');
  assert.equal(severityBand(999), 'minor');
  assert.equal(severityBand(1000), 'major');
  assert.equal(severityBand(100000), 'severe');
  assert.equal(severityBand(NaN), 'minor');
});

test('analyst records are JSON-safe', () => {
  const record = mapInternetHealthAnalystRecord({
    code: 'MV',
    score: 5,
    severity: 'minor',
    lat: NaN,
  });
  assert.equal(record.id, 'IODA-MV');
  assert.equal(record.lat, null);
  assert.equal(record.country, 'MV');
  assert.doesNotThrow(() => JSON.stringify(record));
});

test('counts landing points inside a country polygon', () => {
  // A 10°×10° square encoded at 0 decimals: absolute start then deltas.
  const index = indexCountries({
    meta: { decimals: 0 },
    features: [
      {
        iso2: 'XA',
        name: 'Squareland',
        polygons: [[[0, 0, 10, 0, 0, 10, -10, 0]]],
      },
    ],
  });
  const country = index.get('XA');
  assert.ok(country);
  const points = landingPoints({
    features: [
      { geometry: { coordinates: [5, 5] } },
      { geometry: { coordinates: [15, 5] } },
      { geometry: { coordinates: [1, 9] } },
    ],
  });
  assert.equal(countLandingsIn(country.polygons, points), 2);
});

test('bundled packs join real countries and landings', async () => {
  const geometry = await loadInternetHealthGeometry();
  assert.ok(geometry.countries.size > 200);
  assert.ok(geometry.countries.get('EG'));
  // Egypt is a major cable hub; a landlocked country has none.
  assert.ok(geometry.cableLandings('EG') > 3);
  assert.equal(geometry.cableLandings('CH'), 0);
  assert.equal(geometry.cableLandings('ZZ'), null);
});
