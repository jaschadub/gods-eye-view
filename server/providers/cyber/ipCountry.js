import fsp from 'node:fs/promises';
import path from 'node:path';
import { readResponseTextCapped } from '../common/http.js';

/**
 * IPv4 → country for indicators that arrive without geography (ThreatFox).
 *
 * Data: `@ip-location-db/asn-country` (CC0 packaging of RIR delegation
 * statistics; NRO data CC BY 4.0, attribution nro.net). The numeric IPv4 CSV
 * (`start,end,CC`, ~3.5 MB, ~140k ranges) is downloaded once from jsDelivr,
 * kept in `.gev-cache/`, and refreshed weekly. Lookups are a binary search
 * over typed arrays. Country only — the table does not pretend to locate a
 * host more precisely than its registry allocation.
 */
export const IP_COUNTRY_URL =
  'https://cdn.jsdelivr.net/npm/@ip-location-db/asn-country@2/asn-country-ipv4-num.csv';
const MAX_BYTES = 8 * 1024 * 1024;
const REFRESH_MS = 7 * 24 * 60 * 60_000;
const FAILED_RETRY_MS = 60 * 60_000;

/** Dotted quad → unsigned 32-bit integer, or null. */
export function ipv4ToNumber(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const v = Number(part);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

/**
 * Parse `start,end,CC` lines (ascending, non-overlapping) into a lookup.
 * Throws on malformed or truncated data so a bad download never replaces a
 * good cached table.
 */
export function parseIpCountryCsv(csv, { minRows = 100_000 } = {}) {
  const lines = String(csv).split('\n');
  const starts = new Float64Array(lines.length);
  const ends = new Float64Array(lines.length);
  const codes = new Array(lines.length);
  let count = 0;
  let previousEnd = -1;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const [a, b, cc] = line.split(',');
    const start = Number(a);
    const end = Number(b);
    const code = String(cc ?? '').toUpperCase();
    if (
      !Number.isInteger(start) ||
      !Number.isInteger(end) ||
      end < start ||
      start <= previousEnd ||
      !/^[A-Z]{2}$/.test(code)
    )
      throw new Error('invalid_ip_country_table');
    starts[count] = start;
    ends[count] = end;
    codes[count] = code;
    previousEnd = end;
    count++;
  }
  if (count < minRows) throw new Error('truncated_ip_country_table');
  return {
    size: count,
    lookup(ip) {
      const n = ipv4ToNumber(ip);
      if (n == null) return null;
      let lo = 0;
      let hi = count - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (n < starts[mid]) hi = mid - 1;
        else if (n > ends[mid]) lo = mid + 1;
        else return codes[mid];
      }
      return null;
    },
  };
}

/**
 * Memoized loader: disk cache first, network when missing or a week old,
 * the stale table when the network fails.
 */
export function createIpCountryTable({
  fetchImpl = (...args) => globalThis.fetch(...args),
  cacheDir = path.join(process.cwd(), '.gev-cache'),
  now = () => Date.now(),
  minRows,
} = {}) {
  const file = path.join(cacheDir, 'asn-country-ipv4-num.csv');
  const parse = (csv) =>
    parseIpCountryCsv(csv, minRows == null ? undefined : { minRows });
  let table = null;
  let freshUntil = 0;
  let diskChecked = false;
  let pending = null;

  async function readDisk() {
    try {
      const [csv, stat] = await Promise.all([
        fsp.readFile(file, 'utf8'),
        fsp.stat(file),
      ]);
      table = parse(csv);
      freshUntil = stat.mtimeMs + REFRESH_MS;
    } catch {
      /* no usable disk copy yet */
    }
  }

  async function download(signal) {
    const response = await fetchImpl(IP_COUNTRY_URL, {
      signal,
      headers: { 'User-Agent': 'gods-eye-view-cyber/1.0' },
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`ip_country_http_${response.status}`);
    }
    const csv = await readResponseTextCapped(response, MAX_BYTES, signal);
    const parsed = parse(csv);
    await fsp.mkdir(cacheDir, { recursive: true });
    await fsp.writeFile(file, csv);
    return parsed;
  }

  async function load(signal) {
    if (!diskChecked) {
      diskChecked = true;
      await readDisk();
    }
    if (table && now() < freshUntil) return table;
    try {
      table = await download(signal);
      freshUntil = now() + REFRESH_MS;
    } catch (error) {
      if (!table) throw error;
      freshUntil = now() + FAILED_RETRY_MS;
    }
    return table;
  }

  return {
    /** Resolve the table (shared in-flight load). */
    get(signal) {
      pending ??= load(signal).finally(() => {
        pending = null;
      });
      return pending;
    },
  };
}
