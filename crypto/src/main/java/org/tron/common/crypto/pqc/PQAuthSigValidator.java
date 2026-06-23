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
   * Bounds known fields for registered schemes and rejects nested unknown
   * fields. Unregistered schemes are invalid at admission.
   */
  public static boolean isLengthWithinBounds(PQAuthSig pqAuthSig) {
    if (hasUnknownFields(pqAuthSig)) {
      return false;
    }
    PQScheme scheme = pqAuthSig.getScheme();
    if (!PQSchemeRegistry.contains(scheme)) {
      return false;
    }
    return pqAuthSig.getPublicKey().size() <= PQSchemeRegistry.getPublicKeyLength(scheme)
        && pqAuthSig.getSignature().size() <= PQSchemeRegistry.getSignatureLength(scheme);
  }
}
