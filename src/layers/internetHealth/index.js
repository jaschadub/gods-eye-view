import * as Cesium from 'cesium';
import { mapInternetHealthAnalystRecord } from './records.js';
import { loadInternetHealthGeometry } from './geometry.js';
export * from './records.js';
export { createIodaInternetHealthSource } from './source.js';

export const INTERNET_HEALTH_OVERLAY_SOURCE_ID = 'internet-health';
const OVERLAY_COHORT_LIMIT = 48;
const OVERLAY_COLLISION_CAPACITY = 32;

const msg = (text) => text;

/** Band colors — red for severe, amber for major, cyan for minor. */
const BAND_COLORS = Object.freeze({
  severe: Cesium.Color.fromCssColorString('#ff3b3b'),
  major: Cesium.Color.fromCssColorString('#ffb020'),
  minor: Cesium.Color.fromCssColorString('#3cc8ff'),
});
const BAND_ALPHA = Object.freeze({ severe: 0.45, major: 0.35, minor: 0.22 });

function compactScore(score) {
  if (score >= 1e6) return `${(score / 1e6).toFixed(1)}M`;
  if (score >= 1e3) return `${(score / 1e3).toFixed(1)}k`;
  return String(Math.round(score));
}

/**
 * Internet Health: countries with IODA-detected connectivity disruption in the
 * last 24 h, shaded by severity band and labeled with the overall score.
 * Records carry the count of submarine-cable landings in that country.
 */
export function createInternetHealthLayer({ source, overlayHost } = {}) {
  if (typeof source?.getSnapshot !== 'function')
    throw new TypeError('Internet health requires a snapshot source');
  if (!overlayHost)
    throw new TypeError('Internet health requires an overlay host');
  let _viewer = null;
  let _dataSource = null;
  let _request = null;
  let _enabled = false;
  let _records = [];
  let _lastUpdate = null;
  let _lastError = null;

  return {
    id: 'internet-health',
    name: 'Internet Health (24h)',
    icon: '🛜',
    source: 'IODA · Georgia Tech',
    updateInterval: 5 * 60_000,
    init(viewer) {
      if (_viewer) throw new Error('Internet health is already initialized');
      _viewer = viewer;
      _dataSource = new Cesium.CustomDataSource('internet-health');
      _dataSource.show = false;
      viewer.dataSources.add(_dataSource);
      overlayHost.setVisible(INTERNET_HEALTH_OVERLAY_SOURCE_ID, false);
    },

    enable() {
      _enabled = true;
      if (_dataSource) _dataSource.show = true;
      overlayHost.setVisible(INTERNET_HEALTH_OVERLAY_SOURCE_ID, true);
    },

    disable() {
      _request?.abort();
      _request = null;
      _enabled = false;
      if (_dataSource) _dataSource.show = false;
      overlayHost.clearSource(INTERNET_HEALTH_OVERLAY_SOURCE_ID);
      overlayHost.setVisible(INTERNET_HEALTH_OVERLAY_SOURCE_ID, false);
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
          loadInternetHealthGeometry({ signal }),
        ]);
        if (signal.aborted || _request !== request || !_enabled) return false;

        const entities = [];
        const overlay = [];
        const records = [];
        for (const row of snapshot.rows) {
          const country = geometry.countries.get(row.code);
          const cableLandings = geometry.cableLandings(row.code);
          records.push(
            mapInternetHealthAnalystRecord({
              ...row,
              name: row.name ?? country?.name ?? null,
              cableLandings,
              lat: country?.label.lat,
              lon: country?.label.lon,
            }),
          );
          if (!country) continue; // Unknown code: queryable, not drawable.
          const color = BAND_COLORS[row.severity] ?? BAND_COLORS.minor;
          country.polygons.forEach(([outer, ...holes], part) => {
            entities.push(
              new Cesium.Entity({
                id: `internet-health:${row.code}:${part}`,
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
                  material: color.withAlpha(BAND_ALPHA[row.severity] ?? 0.22),
                  classificationType: Cesium.ClassificationType.BOTH,
                },
                properties: { countryCode: row.code },
              }),
            );
          });
          overlay.push({
            id: row.code,
            position: Cesium.Cartesian3.fromDegrees(
              country.label.lon,
              country.label.lat,
            ),
            variant: 'label',
            title: `${row.code} ${compactScore(row.score)}`,
            accent: color.toCssColorString(),
            priority: Math.round(Math.log10(row.score + 1) * 1000),
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

        _dataSource.entities.removeAll();
        for (const entity of entities) _dataSource.entities.add(entity);
        overlayHost.setEntries(
          INTERNET_HEALTH_OVERLAY_SOURCE_ID,
          overlay.slice(0, OVERLAY_COHORT_LIMIT),
          {
            cohortLimit: OVERLAY_COHORT_LIMIT,
            collisionCapacity: OVERLAY_COLLISION_CAPACITY,
            moving: false,
          },
        );
        _records = records;
        _lastUpdate = Date.now();
        _lastError = snapshot.stale
          ? msg('Internet health feed is stale (showing last good snapshot)')
          : null;
        return true;
      } catch (error) {
        if (signal.aborted || _request !== request || !_enabled) return false;
        console.warn('[Data:InternetHealth] Fetch error:', error);
        _lastError = error?.message || msg('Internet health unavailable');
        return false;
      } finally {
        if (_request === request) _request = null;
      }
    },

    destroy(viewer = _viewer) {
      _request?.abort();
      _request = null;
      _enabled = false;
      overlayHost.clearSource(INTERNET_HEALTH_OVERLAY_SOURCE_ID);
      overlayHost.setVisible(INTERNET_HEALTH_OVERLAY_SOURCE_ID, false);
      if (_dataSource) {
        viewer?.dataSources.remove(_dataSource, true);
        _dataSource = null;
      }
      _viewer = null;
      _records = [];
    },

    /** Analyst seam: JSON-safe outage records, highest score first. */
    getAnalystRecords(maxCount = 500) {
      if (!_dataSource?.show) return [];
      return _records.slice(0, Math.max(1, Math.floor(maxCount) || 500));
    },

    getStats() {
      return {
        count: _records.length,
        lastUpdate: _lastUpdate,
        error: _lastError,
      };
    },
  };
}
