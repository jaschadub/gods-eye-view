import { createCyberSnapshotSource } from '../cyber/source.js';

/** Read the same-origin IODA proxy (`/api/internet-health`). */
export function createIodaInternetHealthSource({ fetchImpl } = {}) {
  return createCyberSnapshotSource({
    route: '/api/internet-health',
    label: 'Internet health', // i18n-ignore: feed name inside English error data
    ...(fetchImpl ? { fetchImpl } : {}),
  });
}
