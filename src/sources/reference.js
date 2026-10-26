import { createUsgsEarthquakeSource } from '../layers/earthquakes/source.js';
import { createEcccAirQualitySource } from '../layers/airQuality/source.js';
import { createWfigsPerimeterSource } from '../layers/perimeters/source.js';
import { createBundledCableSource } from '../layers/submarineCables/bundledSource.js';
import { createAdsbGnssSource } from '../layers/gnss/source.js';
import { createIodaInternetHealthSource } from '../layers/internetHealth/source.js';
import { createAbuseChC2Source } from '../layers/c2Clusters/index.js';
import {
  createRadarOutagesSource,
  createBgpEventsSource,
} from '../layers/radar/index.js';
import { createShodanExposureSource } from '../layers/exposure/index.js';

/** Construct the existing reference feeds independently of application setup. */
export function createReferenceSources() {
  return {
    earthquakes: createUsgsEarthquakeSource(),
    'air-quality': createEcccAirQualitySource(),
    'fire-perimeters': createWfigsPerimeterSource(),
    cables: createBundledCableSource(),
    'gnss-integrity': createAdsbGnssSource(),
    'internet-health': createIodaInternetHealthSource(),
    'radar-outages': createRadarOutagesSource(),
    'bgp-events': createBgpEventsSource(),
    'c2-clusters': createAbuseChC2Source(),
    exposure: createShodanExposureSource(),
  };
}
