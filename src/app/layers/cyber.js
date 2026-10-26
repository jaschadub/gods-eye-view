import { createC2ClustersLayer } from '../../layers/c2Clusters/index.js';
import {
  createRadarOutagesLayer,
  createBgpEventsLayer,
} from '../../layers/radar/index.js';
import { createExposureLayer } from '../../layers/exposure/index.js';
import { overlayHost } from './overlayHost.js';

/** Wire the cyber layer pack to the application overlay host. */
export const createApplicationC2Clusters = (options) =>
  createC2ClustersLayer({ overlayHost, ...options });
export const createApplicationRadarOutages = (options) =>
  createRadarOutagesLayer({ overlayHost, ...options });
export const createApplicationBgpEvents = (options) =>
  createBgpEventsLayer({ overlayHost, ...options });
export const createApplicationExposure = (options) =>
  createExposureLayer({ overlayHost, ...options });
