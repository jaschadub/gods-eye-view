import * as Cesium from 'cesium';
import { loadCountryGeometry } from './geometry.js';

/**
 * @file One lifecycle for every country-level layer in the cyber pack.
 *
 * A cyber layer supplies a snapshot source and a pure `project()` that turns
 * the snapshot plus country geometry into:
 *   - `countries`: `{code, band, label}` — shaded polygons + one score label,
 *   - `arcs` (optional): `{from, to, band, id}` — country-to-country arcs
 *     (BGP hijacker → victim),
 *   - `records`: JSON-safe analyst records for voice / MCP queries.
 * Everything Cesium-specific lives here, so each layer's own logic stays pure
 * and unit-testable.
 */

const OVERLAY_COHORT_LIMIT = 48;
const OVERLAY_COLLISION_CAPACITY = 32;

/** Shared band palette: red high, amber medium, cyan low. */
export const CYBER_BAND_COLORS = Object.freeze({
  high: '#ff3b3b',
  medium: '#ffb020',
  low: '#3cc8ff',
});
const BAND_ALPHA = Object.freeze({ high: 0.45, medium: 0.35, low: 0.22 });
const BAND_PRIORITY = Object.freeze({ high: 3, medium: 2, low: 1 });

const cesiumColor = (band) =>
  Cesium.Color.fromCssColorString(
    CYBER_BAND_COLORS[band] ?? CYBER_BAND_COLORS.low,
  );

/** Great-circle-ish arc between two label points, lifted mid-span. */
function arcPositions(a, b, steps = 32) {
  const start = Cesium.Cartographic.fromDegrees(a.lon, a.lat);
  const end = Cesium.Cartographic.fromDegrees(b.lon, b.lat);
  const geodesic = new Cesium.EllipsoidGeodesic(start, end);
  const lift = Math.min(1_500_000, geodesic.surfaceDistance * 0.25);
  const positions = [];
  for (let i = 0; i <= steps; i++) {
    const f = i / steps;
    const p = geodesic.interpolateUsingFraction(f);
    positions.push(
      Cesium.Cartesian3.fromRadians(
        p.longitude,
        p.latitude,
        Math.sin(Math.PI * f) * lift,
      ),
    );
  }
  return positions;
}

/**
 * @param {object} options
 * @param {string} options.id Layer id (also the overlay source id).
 * @param {string} options.name Panel fallback name.
 * @param {string} options.icon
 * @param {string} options.sourceLabel Provider credit shown in the row.
 * @param {number} options.updateInterval ms
 * @param {string|null} [options.requiresKeyId] KEY_SETUP_KEYS id.
 * @param {{getSnapshot: Function}} options.source
 * @param {object} options.overlayHost
 * @param {(snapshot: object, geometry: object) => {countries: Array,
 *   arcs?: Array, records: Array}} options.project
 */
export function createCyberCountryLayer({
  id,
  name,
  icon,
  sourceLabel,
  updateInterval,
  requiresKeyId = null,
  source,
  overlayHost,
  project,
}) {
  if (typeof source?.getSnapshot !== 'function')
    throw new TypeError(`${id} requires a snapshot source`);
  if (!overlayHost) throw new TypeError(`${id} requires an overlay host`);
  if (typeof project !== 'function')
    throw new TypeError(`${id} requires a projection`);
  let _viewer = null;
  let _dataSource = null;
  let _request = null;
  let _enabled = false;
  let _records = [];
  let _lastUpdate = null;
  let _lastError = null;
  let _keyRequired = false;

  const layer = {
    id,
    name,
    icon,
    source: sourceLabel,
    updateInterval,
    ...(requiresKeyId ? { requiresKeyId } : {}),

    init(viewer) {
      if (_viewer) throw new Error(`${id} is already initialized`);
      _viewer = viewer;
      _dataSource = new Cesium.CustomDataSource(id);
      _dataSource.show = false;
      viewer.dataSources.add(_dataSource);
      overlayHost.setVisible(id, false);
    },

    enable() {
      _enabled = true;
      if (_dataSource) _dataSource.show = true;
      overlayHost.setVisible(id, true);
    },

    disable() {
      _request?.abort();
      _request = null;
      _enabled = false;
      if (_dataSource) _dataSource.show = false;
      overlayHost.clearSource(id);
      overlayHost.setVisible(id, false);
    },

    async update() {
      if (!_enabled || !_dataSource) return false;
      _request?.abort();
      const request = new AbortController();
      _request = request;
      const { signal } = request;
      try {
        const [snapshot, geometry] = await Promise.all([
          source.getSnapshot({ signal }),
          loadCountryGeometry({ signal }),
        ]);
        if (signal.aborted || _request !== request || !_enabled) return false;
        const {
          countries = [],
          arcs = [],
          records = [],
        } = project(snapshot, geometry);

        const entities = [];
        const overlay = [];
        for (const row of countries) {
          const country = geometry.countries.get(row.code);
          if (!country) continue; // Queryable, not drawable.
          const color = cesiumColor(row.band);
          country.polygons.forEach(([outer, ...holes], part) => {
            entities.push(
              new Cesium.Entity({
                id: `${id}:${row.code}:${part}`,
                polygon: {
                  hierarchy: new Cesium.PolygonHierarchy(
                    Cesium.Cartesian3.fromDegreesArray(outer.flat()),
                    holes.map(
                      (hole) =>
                        new Cesium.PolygonHierarchy(
                          Cesium.Cartesian3.fromDegreesArray(hole.flat()),
                        ),
                    ),
                  ),
                  // No height: Cesium drapes it on terrain and 3D tiles.
                  material: color.withAlpha(BAND_ALPHA[row.band] ?? 0.22),
                  classificationType: Cesium.ClassificationType.BOTH,
                },
                properties: { countryCode: row.code },
              }),
            );
          });
          if (row.label)
            overlay.push({
              id: row.code,
              position: Cesium.Cartesian3.fromDegrees(
                country.label.lon,
                country.label.lat,
              ),
              variant: 'label',
              title: row.label,
              accent: color.toCssColorString(),
              priority:
                (BAND_PRIORITY[row.band] ?? 1) * 100_000 +
                Math.round(row.weight ?? 0),
              collisionGroup: 'ambient-label',
              paintLane: 'ambient-label',
              interactive: false,
              edgeFade: 'keyhole',
              horizonCull: true,
              terrainOcclusion: false,
              gapPx: 12,
              verticalOnly: true,
              placement: 'above',
            });
        }
        for (const arc of arcs) {
          const from = geometry.countries.get(arc.from);
          const to = geometry.countries.get(arc.to);
          if (!from || !to || arc.from === arc.to) continue;
          entities.push(
            new Cesium.Entity({
              id: `${id}:arc:${arc.id}`,
              polyline: {
                positions: arcPositions(from.label, to.label),
                width: 2,
                arcType: Cesium.ArcType.NONE,
                material: new Cesium.PolylineGlowMaterialProperty({
                  glowPower: 0.2,
                  color: cesiumColor(arc.band).withAlpha(0.9),
                }),
              },
            }),
          );
        }

        _dataSource.entities.removeAll();
        for (const entity of entities) _dataSource.entities.add(entity);
        overlay.sort((a, b) => b.priority - a.priority);
        overlayHost.setEntries(id, overlay.slice(0, OVERLAY_COHORT_LIMIT), {
          cohortLimit: OVERLAY_COHORT_LIMIT,
          collisionCapacity: OVERLAY_COLLISION_CAPACITY,
          moving: false,
        });
        _records = records;
        _lastUpdate = Date.now();
        _keyRequired = false;
        // i18n-ignore: English status data, like other layers' feed errors
        const staleText = `${name}: feed is stale (showing last good snapshot)`;
        _lastError = snapshot.stale === true ? staleText : null;
        return true;
      } catch (error) {
        if (signal.aborted || _request !== request || !_enabled) return false;
        _keyRequired = error?.keyRequired === true;
        if (!_keyRequired) console.warn(`[Data:${id}] Fetch error:`, error);
        _lastError = error?.message || `${name} unavailable`;
        return false;
      } finally {
        if (_request === request) _request = null;
      }
    },

    destroy(viewer = _viewer) {
      _request?.abort();
      _request = null;
      _enabled = false;
      overlayHost.clearSource(id);
      overlayHost.setVisible(id, false);
      if (_dataSource) {
        viewer?.dataSources.remove(_dataSource, true);
        _dataSource = null;
      }
      _viewer = null;
      _records = [];
    },

    /** Analyst seam: JSON-safe records, most significant first. */
    getAnalystRecords(maxCount = 500) {
      if (!_dataSource?.show) return [];
      return _records.slice(0, Math.max(1, Math.floor(maxCount) || 500));
    },

    getStats() {
      return {
        count: _records.length,
        lastUpdate: _lastUpdate,
        error: _lastError,
        ...(requiresKeyId ? { keyRequired: _keyRequired } : {}),
      };
    },
  };
  return layer;
}

/** Compact number for map labels: 1234 → 1.2k. */
export function compactNumber(value) {
  const n = Number(value) || 0;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(Math.round(n));
}
