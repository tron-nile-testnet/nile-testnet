package org.tron.common.crypto.pqc;

import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

/**
 * Shared admission checks for {@link PQAuthSig}. Ingress paths use the bounded
 * size check; consensus paths also reject unknown fields to keep wire semantics
 * uniform.
 */
public final class PQAuthSigValidator {

  private PQAuthSigValidator() {
  }

  /** Returns {@code true} when nested unknown fields are present. */
  public static boolean hasUnknownFields(PQAuthSig pqAuthSig) {
    return pqAuthSig.getUnknownFields().getSerializedSize() != 0;
  }

  /**
   * Bounds known fields by scheme and rejects nested unknown fields. Unknown
   * schemes fall back to the global registered maximum.
   */
  public static boolean isLengthWithinBounds(PQAuthSig pqAuthSig) {
    if (hasUnknownFields(pqAuthSig)) {
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
