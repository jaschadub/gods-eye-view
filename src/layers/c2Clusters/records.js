/**
 * @file Pure normalization and aggregation for the C2 Clusters layer.
 *
 * Inputs are botnet command-and-control indicators from abuse.ch:
 *   - Feodo Tracker's recommended blocklist (keyless; carries ASN + country),
 *   - ThreatFox `get_iocs` (free Auth-Key; `ip:port` IOCs, no geography —
 *     the proxy resolves country from an IP→country table).
 * Output is aggregated to COUNTRY level on purpose: IP geolocation is
 * unreliable for VPN, anycast and cloud ranges, so a raw C2 IP is never drawn
 * as a map point. No Cesium, no fetch.
 */

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const ISO2 = /^[A-Z]{2}$/;

/** Display bands over the per-country C2 count. */
export function c2Band(count) {
  if (count >= 25) return 'high';
  if (count >= 5) return 'medium';
  return 'low';
}

const text = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const code = (v) => {
  const c = String(v ?? '')
    .trim()
    .toUpperCase();
  return ISO2.test(c) ? c : null;
};

/**
 * Validate Feodo Tracker `ipblocklist.json` (an array of C2 entries).
 * @returns {Array<object>|null} null when the payload is unusable.
 */
export function normalizeFeodoBlocklist(payload) {
  if (!Array.isArray(payload)) return null;
  const out = [];
  for (const item of payload) {
    if (!item || typeof item !== 'object') return null;
    const ip = text(item.ip_address);
    if (!ip || !IPV4.test(ip)) continue;
    out.push({
      ip,
      port: Number.isInteger(item.port) ? item.port : null,
      online: item.status === 'online',
      asn: Number.isInteger(item.as_number) ? item.as_number : null,
      asName: text(item.as_name),
      country: code(item.country),
      family: text(item.malware) ?? 'Unknown',
      firstSeen: text(item.first_seen),
      source: 'feodo',
    });
  }
  return out;
}

/**
 * Validate a ThreatFox `get_iocs` answer and keep `ip:port` IOCs.
 * `lookupCountry(ip)` resolves the hosting country (or null).
 * `query_status: 'no_result'` is a valid empty answer.
 * @returns {Array<object>|null}
 */
export function normalizeThreatFoxIocs(payload, lookupCountry = () => null) {
  if (!payload || typeof payload !== 'object') return null;
  if (payload.query_status === 'no_result') return [];
  if (payload.query_status !== 'ok' || !Array.isArray(payload.data))
    return null;
  const out = [];
  for (const item of payload.data) {
    if (!item || typeof item !== 'object') return null;
    if (item.ioc_type !== 'ip:port') continue;
    const [ip, port] = String(item.ioc ?? '').split(':');
    if (!IPV4.test(ip)) continue;
    out.push({
      ip,
      port: Number.isInteger(Number(port)) ? Number(port) : null,
      // ThreatFox lists active reports; last_seen is often null.
      online: true,
      asn: null,
      asName: null,
      country: code(lookupCountry(ip)),
      family: text(item.malware_printable) ?? text(item.malware) ?? 'Unknown',
      firstSeen: text(item.first_seen),
      confidence: Number.isFinite(item.confidence_level)
        ? item.confidence_level
        : null,
      source: 'threatfox',
    });
  }
  return out;
}

function top(map, limit) {
  return [...map.entries()]
    .sort((a, b) => b[1].count - a[1].count || String(a[0]).localeCompare(b[0]))
    .slice(0, limit)
    .map(([, value]) => value);
}

/**
 * Deduplicate by ip:port (Feodo wins over ThreatFox for its ASN detail) and
 * aggregate per country, highest count first. Entries without a resolvable
 * country are counted in `unlocated`, never guessed.
 */
export function aggregateC2ByCountry(entries) {
  const seen = new Map();
  for (const entry of entries) {
    const key = `${entry.ip}:${entry.port ?? ''}`;
    const prior = seen.get(key);
    if (!prior || (prior.source !== 'feodo' && entry.source === 'feodo'))
      seen.set(key, entry);
  }
  const countries = new Map();
  let unlocated = 0;
  for (const entry of seen.values()) {
    if (!entry.country) {
      unlocated++;
      continue;
    }
    let row = countries.get(entry.country);
    if (!row) {
      row = {
        code: entry.country,
        total: 0,
        online: 0,
        families: new Map(),
        asns: new Map(),
        sources: new Set(),
      };
      countries.set(entry.country, row);
    }
    row.total++;
    if (entry.online) row.online++;
    row.sources.add(entry.source);
    const fam = row.families.get(entry.family) ?? {
      name: entry.family,
      count: 0,
    };
    fam.count++;
    row.families.set(entry.family, fam);
    if (entry.asn != null) {
      const asn = row.asns.get(entry.asn) ?? {
        asn: entry.asn,
        name: entry.asName,
        count: 0,
      };
      asn.count++;
      row.asns.set(entry.asn, asn);
    }
  }
  const rows = [...countries.values()]
    .map((row) => ({
      code: row.code,
      total: row.total,
      online: row.online,
      band: c2Band(row.total),
      families: top(row.families, 5),
      asns: top(row.asns, 3),
      sources: [...row.sources].sort(),
    }))
    .sort((a, b) => b.total - a.total || a.code.localeCompare(b.code));
  return { rows, unlocated, indicators: seen.size };
}

/** JSON-safe analyst record for one country's C2 cluster. */
export function mapC2AnalystRecord(row) {
  const num = (v) => (Number.isFinite(v) ? v : null);
  return {
    id: `C2-${row?.code ?? 'XX'}`,
    country: row?.name ?? row?.code ?? null,
    countryCode: row?.code ?? null,
    c2Count: num(row?.total),
    online: num(row?.online),
    topFamily: row?.families?.[0]?.name ?? null,
    families: (row?.families ?? []).map((f) => f.name).join(', ') || null,
    topAsn: row?.asns?.[0] ? `AS${row.asns[0].asn}` : null,
    topAsnName: row?.asns?.[0]?.name ?? null,
    cableLandings: num(row?.cableLandings),
    lat: num(row?.lat),
    lon: num(row?.lon),
  };
}
