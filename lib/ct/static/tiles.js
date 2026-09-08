import crypto, { X509Certificate } from "node:crypto";
import { normalizeHost, toIsoTime } from "../common.js";

/**
 * Encodes a numeric tile index into the Static CT API path convention:
 * 3-digit decimal chunks, all but the last prefixed with 'x'.
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

export function wrapTbsDer(tbsDer) {
  const alg = Buffer.from("300d06092a864886f70d01010b0500", "hex");
  const sig = Buffer.from("0303000000", "hex");
  const innerLen = tbsDer.length + alg.length + sig.length;
  let header;
  if (innerLen < 128) {
    header = Buffer.from([0x30, innerLen]);
  } else if (innerLen < 256) {
    header = Buffer.from([0x30, 0x81, innerLen]);
  } else if (innerLen < 65536) {
    header = Buffer.from([0x30, 0x82, (innerLen >> 8) & 0xff, innerLen & 0xff]);
  } else {
    header = Buffer.from([0x30, 0x83, (innerLen >> 16) & 0xff, (innerLen >> 8) & 0xff, innerLen & 0xff]);
  }
  return Buffer.concat([header, tbsDer, alg, sig]);
}

// Validate C2SP TileLeaf framing independently of certificate parsing and DNS extraction.
function validateTileFraming(buffer, expectedBundleCount) {
  if (!Number.isInteger(expectedBundleCount) || expectedBundleCount < 1 || expectedBundleCount > 256) {
    throw new Error("tile_framing_invalid: expected bundle count must be between 1 and 256");
  }
  let offset = 0;
  let bundleCount = 0;
  function take(length, field) {
    if (offset + length > buffer.length) throw new Error(`tile_framing_invalid: truncated ${field}`);
    offset += length;
  }
  function vector(prefixBytes, field, minimum = 0) {
    take(prefixBytes, `${field} length`);
    const length = buffer.readUIntBE(offset - prefixBytes, prefixBytes);
    if (length < minimum) throw new Error(`tile_framing_invalid: empty ${field}`);
    take(length, field);
    return length;
  }
  while (offset < buffer.length) {
    take(10, "timestamp and entry type");
    const entryType = buffer.readUInt16BE(offset - 2);
    if (entryType === 0) {
      vector(3, "certificate", 1);
    } else if (entryType === 1) {
      take(32, "issuer key hash");
      vector(3, "TBSCertificate", 1);
    } else {
      throw new Error(`tile_framing_invalid: unknown entry type ${entryType}`);
    }
    vector(2, "extensions");
    if (entryType === 1) vector(3, "precertificate", 1);
    if (vector(2, "chain fingerprints") % 32 !== 0) {
      throw new Error("tile_framing_invalid: chain fingerprints must be 32 bytes each");
    }
    bundleCount += 1;
  }
  if (bundleCount !== expectedBundleCount) {
    throw new Error(`tile_framing_invalid: expected ${expectedBundleCount} bundles, read ${bundleCount}`);
  }
}

/**
 * Parses a binary data tile containing concatenated entry bundles.
 */
export function parseTileEntries(buffer, log, baseEntryIndex = 0, { expectedBundleCount } = {}) {
  if (expectedBundleCount !== undefined) validateTileFraming(buffer, expectedBundleCount);
  const entries = [];
  let offset = 0;
  let entryIndexInTile = 0;

  while (offset + 10 <= buffer.length) {
    const timestampMs = Number(buffer.readBigUInt64BE(offset));
    const entryType = buffer.readUInt16BE(offset + 8);
    offset += 10;

    let certDer = null;
    let isPrecert = false;

    if (entryType === 0) {
      // x509_entry
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
      // Certificate chain
      if (offset + 2 <= buffer.length) {
        const chainLen = buffer.readUInt16BE(offset);
        offset += 2 + chainLen;
      }
    } else if (entryType === 1) {
      // precert_entry
      isPrecert = true;
      if (offset + 35 > buffer.length) break;
      const _issuerKeyHash = buffer.subarray(offset, offset + 32);
      offset += 32;
      const tbsLen = readUint24(buffer, offset);
      offset += 3;
      if (offset + tbsLen > buffer.length) break;
      const tbsDer = buffer.subarray(offset, offset + tbsLen);
      offset += tbsLen;

      // Extensions
      if (offset + 2 <= buffer.length) {
        const extLen = buffer.readUInt16BE(offset);
        offset += 2 + extLen;
      }
      // Full precertificate
      if (offset + 3 <= buffer.length) {
        const precertLen = readUint24(buffer, offset);
        offset += 3;
        if (offset + precertLen <= buffer.length) {
          certDer = buffer.subarray(offset, offset + precertLen);
          offset += precertLen;
        }
      }
      if (!certDer) {
        certDer = wrapTbsDer(tbsDer);
      }
      // Precert chain
      if (offset + 2 <= buffer.length) {
        const chainLen = buffer.readUInt16BE(offset);
        offset += 2 + chainLen;
      }
    } else {
      break;
    }

    const currentIndex = baseEntryIndex + entryIndexInTile;
    entryIndexInTile += 1;

    try {
      if (certDer && certDer.length > 0) {
        const cert = new X509Certificate(certDer);
        const commonName = extractCommonName(cert.subject);
        const rawDnsNames = [...new Set([...extractDnsNames(cert.subjectAltName), commonName].filter(Boolean))];
        const isWildcard = rawDnsNames.some((d) => d.startsWith("*.") || d.includes("*"));
        const dnsNames = rawDnsNames.map((d) => (d.startsWith("*.") ? d.slice(2) : d));

        if (dnsNames.length) {
          const issuerDnSha256 = crypto.createHash("sha256").update(cert.issuer).digest("hex");
          entries.push({
            dns_names: dnsNames,
            common_name: commonName || dnsNames[0],
            not_before: toIsoTime(cert.validFrom),
            issuer: { aggregated: cert.issuer },
            cert_index: currentIndex,
            cert_fingerprint: cert.fingerprint256?.replaceAll(":", "").toLowerCase(),
            cert_serial: cert.serialNumber || null,
            cert_issuer_dn_sha256: issuerDnSha256,
            entry_types: [isPrecert ? "precert" : "x509"],
            san_count: dnsNames.length,
            is_wildcard: isWildcard,
            seen: timestampMs / 1000,
            source: "static_ct",
            source_label: isPrecert ? "Static CT (Precert)" : "Static CT",
            source_ref: `${log.monitoring_url || log.submission_url}:${currentIndex}`,
            log_name: log.description,
            log_operator: log.operator,
            protocol: "static-ct-api"
          });
        }
      }
    } catch (_err) {
      // Continue parsing next entry
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
