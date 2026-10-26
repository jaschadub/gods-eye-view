import { createInternetHealthLayer } from '../../layers/internetHealth/index.js';
import { overlayHost } from './overlayHost.js';
/** Wire IODA internet-health observations to the application overlay host. */
export function createApplicationInternetHealth(options) {
  return createInternetHealthLayer({ overlayHost, ...options });
}
