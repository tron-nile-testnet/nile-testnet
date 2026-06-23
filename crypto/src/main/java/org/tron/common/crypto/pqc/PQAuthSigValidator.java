package org.tron.common.crypto.pqc;

import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

/**
 * Shared, cheap size gate for an inbound {@link PQAuthSig}, applied at every
 * entry point that ingests a post-quantum signature (p2p handshake, p2p
 * transaction ingress, RPC broadcast). It bounds {@code public_key} /
 * {@code signature} to the declared scheme's legal maximum and rejects nested
 * unknown fields so an oversized PQ field is rejected early, mirroring the
 * legacy ECDSA {@code isValidLength} check. Exact per-scheme length matching
 * and the actual signature verification still happen later in the dedicated
 * verify paths ({@code RelayService}, {@code TransactionCapsule},
 * {@code BlockCapsule}).
 */
public final class PQAuthSigValidator {

  private PQAuthSigValidator() {
  }

  /**
   * Returns {@code true} iff the {@link PQAuthSig} is within legal size: no
   * nested unknown fields, and public key / signature within the declared
   * scheme's maximum. A registered scheme uses its exact per-scheme maximum; an
   * unknown/future scheme falls back to the global maximum across all
   * registered schemes, so memory stays bounded without rejecting
   * forward-compatible peers.
   *
   * <p>The unknown-field check matters because generated {@code PQAuthSig}
   * retains and re-serializes unknown fields: bounding only public_key/signature
   * would let a caller smuggle a large unknown length-delimited field while both
   * known fields stay within bounds. PQAuthSig's field set is fixed
   * (scheme/public_key/signature), so rejecting unknown fields is safe.
   */
  public static boolean isLengthWithinBounds(PQAuthSig pqAuthSig) {
    if (pqAuthSig.getUnknownFields().getSerializedSize() != 0) {
      return false;
    }
    PQScheme scheme = pqAuthSig.getScheme();
    int maxPk;
    int maxSig;
    if (PQSchemeRegistry.contains(scheme)) {
      maxPk = PQSchemeRegistry.getPublicKeyLength(scheme);
      maxSig = PQSchemeRegistry.getSignatureLength(scheme);
    } else {
      maxPk = PQSchemeRegistry.getMaxPublicKeyLength();
      maxSig = PQSchemeRegistry.getMaxSignatureLength();
    }
    return pqAuthSig.getPublicKey().size() <= maxPk
        && pqAuthSig.getSignature().size() <= maxSig;
  }
}
