import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeShodanCountryFacet,
  mergeExposureFacets,
  exposureBand,
  mapExposureRecord,
} from './records.js';
import { projectExposure } from './index.js';

const facet = (total, pairs) => ({
  matches: [],
  total,
  facets: { country: pairs.map(([value, count]) => ({ value, count })) },
});

test('facet normalization validates totals and codes', () => {
  const f = normalizeShodanCountryFacet(
    facet(10, [
      ['US', 7],
      ['xx', 1],
      ['', 2],
    ]),
  );
  assert.equal(f.total, 10);
  assert.deepEqual(
    [...f.countries],
    [
      ['US', 7],
      ['XX', 1],
    ],
  );
  assert.equal(normalizeShodanCountryFacet({ total: 1 }), null);
  assert.equal(normalizeShodanCountryFacet({ facets: { country: [] } }), null);
});

test('merging sums presets per country and bands the total', () => {
  const { rows, totals } = mergeExposureFacets([
    {
      id: 'ics',
      facet: normalizeShodanCountryFacet(
        facet(900, [
          ['US', 600],
          ['DE', 300],
        ]),
      ),
    },
    {
      id: 'smb',
      facet: normalizeShodanCountryFacet(facet(200000, [['US', 150000]])),
    },
  ]);
  assert.deepEqual(totals, { ics: 900, smb: 200000 });
  assert.deepEqual(
    rows.map((r) => [r.code, r.total, r.band]),
    [
      ['US', 150600, 'high'],
      ['DE', 300, 'low'],
    ],
  );
  assert.equal(exposureBand(10_000), 'medium');
  const record = mapExposureRecord(rows[0]);
  assert.equal(record.ics, 600);
  assert.equal(record.rdp, null);
});

test('projection labels carry the ICS count', () => {
  const { countries } = projectExposure(
    {
      rows: [{ code: 'US', total: 1500, band: 'low', byPreset: { ics: 600 } }],
    },
    { countries: new Map(), cableLandings: () => null },
  );
  assert.equal(countries[0].label, 'US 1.5k · ICS 600');
});
