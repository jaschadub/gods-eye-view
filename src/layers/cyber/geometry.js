/**
 * @file Country geometry and cable-landing correlation for the cyber pack.
 *
 * Joins ISO-3166 alpha-2 codes to the bundled Natural Earth countries pack and
 * counts TeleGeography submarine-cable landing points inside each country —
 * the pack's physical/cyber correlation: an outage, C2 cluster or BGP event in
 * a cable hub is a different story from one in a landlocked country.
 *
 * Pure apart from lazy, memoized pack loads; no Cesium.
 */
import { loadBundledJson } from '../../data/bundledJson.js';
import { decodeRing, polygonsContain } from '../../data/adminBoundaries.js';

const COUNTRIES_URL = new URL(
  '../../data/local_data/natural_earth/countries.json',
  import.meta.url,
);
const LANDINGS_URL = new URL(
  '../../data/local_data/telegeography_submarine_cables/landing-point-geo.json',
  import.meta.url,
);

/** Area-weighted centroid of an open [lon, lat] ring. */
function ringCentroid(ring) {
  let a = 0;
  let cx = 0;
  let cy = 0;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [x0, y0] = ring[j];
    const [x1, y1] = ring[i];
    const f = x0 * y1 - x1 * y0;
    a += f;
    cx += (x0 + x1) * f;
    cy += (y0 + y1) * f;
  }
  if (!a) return { lon: ring[0][0], lat: ring[0][1] };
  return { lon: cx / (3 * a), lat: cy / (3 * a) };
}

/**
 * Build `iso2 -> { name, polygons, label }` from a countries pack.
 * Exported for tests; pass a parsed pack.
 */
export function indexCountries(pack) {
  const decimals = pack?.meta?.decimals ?? 3;
  const index = new Map();
  for (const feature of pack?.features ?? []) {
    const iso2 = String(feature?.iso2 ?? '').toUpperCase();
    if (!/^[A-Z]{2}$/.test(iso2) || index.has(iso2)) continue;
    const polygons = (feature.polygons ?? []).map((poly) =>
      poly.map((ring) => decodeRing(ring, feature.d ?? decimals)),
    );
    if (!polygons.length || !polygons[0]?.[0]?.length) continue;
    // Label on the largest outer ring (by vertex count, a cheap proxy).
    const largest = polygons.reduce((best, poly) =>
      poly[0].length > best[0].length ? poly : best,
    );
    const label = Array.isArray(feature.label)
      ? { lon: feature.label[0], lat: feature.label[1] }
      : ringCentroid(largest[0]);
    index.set(iso2, { name: feature.name ?? iso2, polygons, label });
  }
  return index;
}

/** Extract [lon, lat] landing points from the TeleGeography GeoJSON. */
export function landingPoints(geojson) {
  const points = [];
  for (const feature of geojson?.features ?? []) {
    const [lon, lat] = feature?.geometry?.coordinates ?? [];
    if (Number.isFinite(lon) && Number.isFinite(lat))
      points.push({ lon, lat, name: feature.properties?.name ?? null });
  }
  return points;
}

/** Count landing points inside one country's polygons (bbox prefilter). */
export function countLandingsIn(polygons, points) {
  let west = Infinity;
  let east = -Infinity;
  let south = Infinity;
  let north = -Infinity;
  for (const [outer] of polygons)
    for (const [lon, lat] of outer) {
      if (lon < west) west = lon;
      if (lon > east) east = lon;
      if (lat < south) south = lat;
      if (lat > north) north = lat;
    }
  let count = 0;
  for (const p of points) {
    if (p.lat < south || p.lat > north || p.lon < west || p.lon > east)
      continue;
    if (polygonsContain(polygons, p.lat, p.lon)) count++;
  }
  return count;
}

let countriesPromise = null;
let landingsPromise = null;
const landingCounts = new Map();

/** Lazily load and memoize the geometry packs (one load per page). */
export async function loadCountryGeometry({ signal } = {}) {
  countriesPromise ??= loadBundledJson(COUNTRIES_URL).then(indexCountries);
  landingsPromise ??= loadBundledJson(LANDINGS_URL).then(landingPoints);
  try {
    const [countries, landings] = await Promise.all([
      countriesPromise,
      landingsPromise,
    ]);
    signal?.throwIfAborted();
    return {
      countries,
      cableLandings(code) {
        if (!landingCounts.has(code)) {
          const country = countries.get(code);
          landingCounts.set(
            code,
            country ? countLandingsIn(country.polygons, landings) : null,
          );
        }
        return landingCounts.get(code);
      },
    };
  } catch (error) {
    // A failed pack load must not poison later attempts.
    if (!signal?.aborted) {
      countriesPromise = null;
      landingsPromise = null;
    }
    throw error;
  }
}
