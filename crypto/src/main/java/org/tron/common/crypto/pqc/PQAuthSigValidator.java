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
 *
 * <p><b>Unknown fields are rejected uniformly</b> across the ingress gates and
 * the consensus verify paths ({@code TransactionCapsule#validatePQSignatureGetWeight},
 * {@code BlockCapsule#validatePQSignature}) via {@link #hasNoUnknownFields}.
 * Keeping the rule identical at every layer removes the asymmetry where a
 * relay/RPC gate would reject a {@code PQAuthSig} that consensus would still
 * accept. {@code PQAuthSig}'s field set is fixed (scheme/public_key/signature);
 * a future field addition is a wire-format change that must be coordinated by a
 * protocol upgrade / hard fork anyway, so rejecting unknown fields outright is
 * the intended, forward-safe behavior rather than a compatibility hazard.
 */
public final class PQAuthSigValidator {

  private PQAuthSigValidator() {
  }

  /**
   * Returns {@code true} iff the {@link PQAuthSig} carries no nested unknown
   * fields. Generated {@code PQAuthSig} retains and re-serializes unknown
   * fields, so bounding only public_key/signature would let a caller smuggle a
   * large (or simply unexpected) unknown length-delimited field while both
   * known fields stay within bounds. This is the single primitive every entry
   * point and consensus verify path uses to enforce the fixed field set.
   */
  public static boolean hasNoUnknownFields(PQAuthSig pqAuthSig) {
    return pqAuthSig.getUnknownFields().getSerializedSize() == 0;
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
    if (!hasNoUnknownFields(pqAuthSig)) {
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
