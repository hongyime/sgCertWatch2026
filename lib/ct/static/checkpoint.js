import crypto from "node:crypto";

/**
 * Parses a signed note / checkpoint formatted string.
 * Format:
 * <origin line>
 * <tree size, decimal>
 * <root hash, base64>
 * <optional extensions / blank line>
 * \n
 * — <identity> <signature>
 */
export function parseCheckpoint(checkpointText) {
  if (typeof checkpointText !== "string" || !checkpointText.trim()) {
    throw new Error("Empty or invalid checkpoint");
  }

  const normalized = checkpointText.replace(/\r\n/g, "\n");
  const sepIdx = normalized.indexOf("\n\n");
  if (sepIdx === -1) {
    throw new Error("Malformed checkpoint: missing separator line");
  }

  const bodyText = normalized.slice(0, sepIdx + 2);
  const headerLines = normalized.slice(0, sepIdx).split("\n");
  if (headerLines.length < 3) {
    throw new Error("Malformed checkpoint: expected origin, size, and root hash");
  }

  const origin = headerLines[0].trim();
  const treeSize = Number.parseInt(headerLines[1].trim(), 10);
  if (!Number.isFinite(treeSize) || treeSize < 0) {
    throw new Error(`Invalid checkpoint tree size: ${headerLines[1]}`);
  }

  const rootHash = headerLines[2].trim();

  const signatureLines = normalized.slice(sepIdx + 2).split("\n");
  const signatures = [];
  for (const line of signatureLines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("— ") || trimmed.startsWith("\u2014 ")) {
      const parts = trimmed.slice(2).trim().split(/\s+/);
      if (parts.length >= 2) {
        signatures.push({
          identity: parts[0],
          signature: parts[1]
        });
      }
    }
  }

  return {
    origin,
    treeSize,
    rootHash,
    bodyText,
    signatures
  };
}

/**
 * Verifies a checkpoint signature using the log's DER public key.
 */
export function verifyCheckpoint(checkpointText, publicKeyDerBase64) {
  const parsed = parseCheckpoint(checkpointText);
  if (!publicKeyDerBase64) {
    return { ok: false, reason: "missing_public_key", parsed };
  }

  if (!parsed.signatures.length) {
    return { ok: false, reason: "missing_signatures", parsed };
  }

  try {
    const pubKeyDer = Buffer.from(publicKeyDerBase64, "base64");
    const pubKey = crypto.createPublicKey({
      key: pubKeyDer,
      format: "der",
      type: "spki"
    });

    const dataToVerify = Buffer.from(parsed.bodyText, "utf8");

    for (const sig of parsed.signatures) {
      try {
        const sigBytes = Buffer.from(sig.signature, "base64");
        // In signed-note format, first 4 bytes are key name hash, rest is signature
        const rawSig = sigBytes.length > 4 ? sigBytes.subarray(4) : sigBytes;

        // Try standard verify (handles DER)
        const isVerified = crypto.verify("sha256", dataToVerify, pubKey, rawSig);
        if (isVerified) {
          return { ok: true, parsed };
        }

        // Try IEEE-P1363 / raw r||s encoding if 64 bytes
        if (rawSig.length === 64) {
          const isVerifiedP1363 = crypto.verify(
            "sha256",
            dataToVerify,
            { key: pubKey, dsaEncoding: "ieee-p1363" },
            rawSig
          );
          if (isVerifiedP1363) {
            return { ok: true, parsed };
          }
        }
      } catch (_sigErr) {
        // Continue to test other signatures
      }
    }

    return { ok: false, reason: "signature_mismatch", parsed };
  } catch (err) {
    return { ok: false, reason: `verification_error: ${err.message}`, parsed };
  }
}
