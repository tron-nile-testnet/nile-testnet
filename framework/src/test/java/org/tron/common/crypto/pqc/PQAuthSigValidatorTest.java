package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import org.junit.Test;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

/**
 * Covers the shared size gate applied at every pq_auth_sig entry point
 * (handshake, p2p tx ingress, rpc broadcast).
 */
public class PQAuthSigValidatorTest {

  private static PQAuthSig sig(PQScheme scheme, int pkLen, int sigLen) {
    return PQAuthSig.newBuilder()
        .setScheme(scheme)
        .setPublicKey(ByteString.copyFrom(new byte[pkLen]))
        .setSignature(ByteString.copyFrom(new byte[sigLen]))
        .build();
  }

  @Test
  public void acceptsRegisteredSchemeAtMaxLengths() {
    int pk = PQSchemeRegistry.getPublicKeyLength(PQScheme.FN_DSA_512);
    int s = PQSchemeRegistry.getSignatureLength(PQScheme.FN_DSA_512);
    assertTrue(PQAuthSigValidator.isLengthWithinBounds(sig(PQScheme.FN_DSA_512, pk, s)));
  }

  @Test
  public void rejectsOversizedPublicKeyForRegisteredScheme() {
    int pk = PQSchemeRegistry.getPublicKeyLength(PQScheme.FN_DSA_512) + 1;
    int s = PQSchemeRegistry.getSignatureLength(PQScheme.FN_DSA_512);
    assertFalse(PQAuthSigValidator.isLengthWithinBounds(sig(PQScheme.FN_DSA_512, pk, s)));
  }

  @Test
  public void rejectsUndersizedPublicKeyForRegisteredScheme() {
    // Public key length must match the scheme exactly; a shorter key is rejected.
    int pk = PQSchemeRegistry.getPublicKeyLength(PQScheme.FN_DSA_512) - 1;
    int s = PQSchemeRegistry.getSignatureLength(PQScheme.FN_DSA_512);
    assertFalse(PQAuthSigValidator.isLengthWithinBounds(sig(PQScheme.FN_DSA_512, pk, s)));
  }

  @Test
  public void rejectsOversizedSignatureForRegisteredScheme() {
    int pk = PQSchemeRegistry.getPublicKeyLength(PQScheme.ML_DSA_44);
    int s = PQSchemeRegistry.getSignatureLength(PQScheme.ML_DSA_44) + 1;
    assertFalse(PQAuthSigValidator.isLengthWithinBounds(sig(PQScheme.ML_DSA_44, pk, s)));
  }

  @Test
  public void rejectsNestedUnknownFieldEvenWhenKnownFieldsAreLegal() {
    int pk = PQSchemeRegistry.getPublicKeyLength(PQScheme.FN_DSA_512);
    int s = PQSchemeRegistry.getSignatureLength(PQScheme.FN_DSA_512);
    UnknownFieldSet unknown = UnknownFieldSet.newBuilder()
        .addField(99, UnknownFieldSet.Field.newBuilder()
            .addLengthDelimited(ByteString.copyFrom(new byte[4096])).build())
        .build();
    PQAuthSig smuggled = PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(new byte[pk]))
        .setSignature(ByteString.copyFrom(new byte[s]))
        .setUnknownFields(unknown)
        .build();
    assertFalse(PQAuthSigValidator.isLengthWithinBounds(smuggled));
  }

  @Test
  public void hasUnknownFieldsReflectsPresenceOfUnknownFields() {
    int pk = PQSchemeRegistry.getPublicKeyLength(PQScheme.FN_DSA_512);
    int s = PQSchemeRegistry.getSignatureLength(PQScheme.FN_DSA_512);
    assertFalse(PQAuthSigValidator.hasUnknownFields(sig(PQScheme.FN_DSA_512, pk, s)));

    PQAuthSig withUnknown = sig(PQScheme.FN_DSA_512, pk, s).toBuilder()
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(99, UnknownFieldSet.Field.newBuilder()
                .addLengthDelimited(ByteString.copyFrom(new byte[16])).build())
            .build())
        .build();
    assertTrue(PQAuthSigValidator.hasUnknownFields(withUnknown));
  }

  @Test
  public void rejectsUnknownScheme() {
    assertFalse(PQAuthSigValidator.isLengthWithinBounds(
        sig(PQScheme.UNKNOWN_PQ_SCHEME, 0, 0)));
  }
}
