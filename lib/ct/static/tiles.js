import { X509Certificate } from "node:crypto";
import { normalizeHost, toIsoTime } from "../common.js";

/**
 * Encodes a numeric tile index into the Static CT API path convention:
 * 3-digit decimal chunks, all but the last prefixed with 'x'.
 * Examples:
 *   0       -> "000"
 *   5       -> "005"
 *   1234    -> "x001/234"
 *   1234067 -> "x001/x234/067"
 *   2282206 -> "x002/x282/206"
 */
export function tileIndexToPath(tileIndex) {
  const s = String(tileIndex);
  const padLen = Math.ceil(s.length / 3) * 3 || 3;
  const padded = s.padStart(padLen, "0");

  const chunks = [];
  for (let i = 0; i < padded.length; i += 3) {
    chunks.push(padded.slice(i, i + 3));
  }

  return chunks
    .map((chunk, idx) => (idx === chunks.length - 1 ? chunk : `x${chunk}`))
    .join("/");
}

function readUint24(buffer, offset) {
  return (buffer[offset] << 16) + (buffer[offset + 1] << 8) + buffer[offset + 2];
}

function extractDnsNames(subjectAltName) {
  return [...String(subjectAltName || "").matchAll(/DNS:([^,\n]+)/g)]
    .map((match) => normalizeHost(match[1]))
    .filter((domain) => domain.includes("."));
}

function extractCommonName(subject) {
  const match = String(subject || "").match(/(?:^|\n|,\s*)CN\s*=\s*([^,\n]+)/);
  return match ? normalizeHost(match[1]) : "";
}

/**
 * Parses a binary data tile containing concatenated entry bundles.
 * Returns array of parsed entry objects.
 */
export function parseTileEntries(buffer, log, baseEntryIndex = 0) {
  const entries = [];
  let offset = 0;
  let entryIndexInTile = 0;

  while (offset + 10 <= buffer.length) {
    const entryStart = offset;
    const timestampMs = Number(buffer.readBigUInt64BE(offset));
    const entryType = buffer.readUInt16BE(offset + 8);
    offset += 10;

    let certDer = null;
    let isPrecert = false;

    if (entryType === 0) {
      // x509_entry: 3-byte cert_length, followed by certificate bytes
      if (offset + 3 > buffer.length) break;
      const certLen = readUint24(buffer, offset);
      offset += 3;
      if (offset + certLen > buffer.length) break;
      certDer = buffer.subarray(offset, offset + certLen);
      offset += certLen;

      // Extensions
      if (offset + 2 <= buffer.length) {
        const extLen = buffer.readUInt16BE(offset);
        offset += 2 + extLen;
      }
    } else if (entryType === 1) {
      // precert_entry: 32-byte issuer_key_hash, 3-byte tbs_length, TBS bytes
      isPrecert = true;
      if (offset + 35 > buffer.length) break;
      const issuerKeyHash = buffer.subarray(offset, offset + 32);
      offset += 32;
      const tbsLen = readUint24(buffer, offset);
      offset += 3;
      if (offset + tbsLen > buffer.length) break;
      certDer = buffer.subarray(offset, offset + tbsLen);
      offset += tbsLen;

      // Extensions
      if (offset + 2 <= buffer.length) {
        const extLen = buffer.readUInt16BE(offset);
        offset += 2 + extLen;
      }
    } else {
      // Unknown entry type
      break;
    }

    const currentIndex = baseEntryIndex + entryIndexInTile;
    entryIndexInTile += 1;

    try {
      if (certDer && certDer.length > 0) {
        if (!isPrecert) {
          const cert = new X509Certificate(certDer);
          const commonName = extractCommonName(cert.subject);
          const dnsNames = [...new Set([...extractDnsNames(cert.subjectAltName), commonName].filter(Boolean))];

          if (dnsNames.length) {
            entries.push({
              dns_names: dnsNames,
              common_name: commonName || dnsNames[0],
              not_before: toIsoTime(cert.validFrom),
              issuer: { aggregated: cert.issuer },
              cert_index: currentIndex,
              cert_fingerprint: cert.fingerprint256?.replaceAll(":", "").toLowerCase(),
              cert_serial: cert.serialNumber || null,
              entry_type: "x509",
              seen: timestampMs / 1000,
              source: "static_ct",
              source_label: "Static CT (Tile)",
              source_ref: `${log.monitoring_url || log.submission_url}:${currentIndex}`,
              log_name: log.description,
              log_operator: log.operator,
              protocol: "static-ct-api"
            });
          }
        } else {
          // Precertificate TBS handling
          entries.push({
            dns_names: [],
            is_precert: true,
            tbs_der: certDer,
            cert_index: currentIndex,
            entry_type: "precert",
            seen: timestampMs / 1000,
            source: "static_ct",
            source_label: "Static CT (Precert)",
            source_ref: `${log.monitoring_url || log.submission_url}:${currentIndex}`,
            log_name: log.description,
            log_operator: log.operator,
            protocol: "static-ct-api"
          });
        }
      }
    } catch (_err) {
      // Continue parsing next entry in tile
    }
  }

  return entries;
}

/**
 * Fetches a data tile from a static CT log's monitoring URL.
 */
export async function fetchTile(monitoringUrl, tileIndex, partialWidth = null, timeoutMs = 12000) {
  const normUrl = String(monitoringUrl || "").replace(/\/?$/, "/");
  const tilePath = tileIndexToPath(tileIndex);
  const fullPath = partialWidth ? `${tilePath}.p/${partialWidth}` : tilePath;
  const targetUrl = `${normUrl}tile/data/${fullPath}`;

  const res = await fetch(targetUrl, {
    headers: { "User-Agent": "sgCertWatch/1.0" },
    signal: AbortSignal.timeout(timeoutMs)
  });

  if (!res.ok) {
    throw new Error(`Tile fetch failed: ${res.status} ${res.statusText} at ${targetUrl}`);
  }

  const arrayBuf = await res.arrayBuffer();
  return Buffer.from(arrayBuf);
}
