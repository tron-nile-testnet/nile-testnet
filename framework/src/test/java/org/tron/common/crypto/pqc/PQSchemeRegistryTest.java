package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

/**
 * Covers the static dispatch helpers of {@link PQSchemeRegistry} and the
 * defensive paths exercised by callers passing {@code null}, {@code UNRECOGNIZED}
 * or wrong-shaped public keys.
 */
public class PQSchemeRegistryTest {

  @Test
  public void containsRejectsNullScheme() {
    assertFalse(PQSchemeRegistry.contains(null));
  }

  @Test
  public void containsRejectsUnrecognized() {
    assertFalse(PQSchemeRegistry.contains(PQScheme.UNRECOGNIZED));
  }

  @Test
  public void containsRejectsUnknownPqScheme() {
    assertFalse(PQSchemeRegistry.contains(PQScheme.UNKNOWN_PQ_SCHEME));
  }

  @Test
  public void containsAcceptsRegisteredScheme() {
    assertTrue(PQSchemeRegistry.contains(PQScheme.FN_DSA_512));
    assertTrue(PQSchemeRegistry.contains(PQScheme.ML_DSA_44));
  }

  @Test
  public void registeredSchemesContainsBothLaunchSchemes() {
    assertTrue(PQSchemeRegistry.registeredSchemes().contains(PQScheme.FN_DSA_512));
    assertTrue(PQSchemeRegistry.registeredSchemes().contains(PQScheme.ML_DSA_44));
  }

  @Test
  public void isSeedDeterministicMatchesSchemeProperties() {
    // Falcon's FFT-based keygen drifts across platforms — operators must
    // persist the expanded priv‖pub, not just the seed.
    assertFalse(PQSchemeRegistry.isSeedDeterministic(PQScheme.FN_DSA_512));
    // FIPS-204 keygen is pure integer arithmetic and reproducible.
    assertTrue(PQSchemeRegistry.isSeedDeterministic(PQScheme.ML_DSA_44));
  }

  @Test
  public void getSeedLengthReturnsRegisteredValue() {
    assertEquals(FNDSA512.SEED_LENGTH, PQSchemeRegistry.getSeedLength(PQScheme.FN_DSA_512));
    assertEquals(MLDSA44.SEED_LENGTH, PQSchemeRegistry.getSeedLength(PQScheme.ML_DSA_44));
  }

  @Test
  public void getPrivateKeyLengthReturnsRegisteredValue() {
    assertEquals(FNDSA512.PRIVATE_KEY_LENGTH,
        PQSchemeRegistry.getPrivateKeyLength(PQScheme.FN_DSA_512));
    assertEquals(MLDSA44.PRIVATE_KEY_LENGTH,
        PQSchemeRegistry.getPrivateKeyLength(PQScheme.ML_DSA_44));
  }

  @Test
  public void fromSeedDispatchesToFalcon() {
    byte[] seed = new byte[FNDSA512.SEED_LENGTH];
    Arrays.fill(seed, (byte) 0x07);
    PQSignature sig = PQSchemeRegistry.fromSeed(PQScheme.FN_DSA_512, seed);
    assertNotNull(sig);
    assertEquals(PQScheme.FN_DSA_512, sig.getScheme());
    // Same seed must yield deterministic keypair across direct and dispatched paths.
    FNDSA512 direct = new FNDSA512(seed);
    assertArrayEquals(direct.getPublicKey(), sig.getPublicKey());
    assertArrayEquals(direct.getPrivateKey(), sig.getPrivateKey());
  }

  @Test
  public void fromSeedDispatchesToMlDsa() {
    byte[] seed = new byte[MLDSA44.SEED_LENGTH];
    Arrays.fill(seed, (byte) 0x07);
    PQSignature sig = PQSchemeRegistry.fromSeed(PQScheme.ML_DSA_44, seed);
    assertNotNull(sig);
    assertEquals(PQScheme.ML_DSA_44, sig.getScheme());
    MLDSA44 direct = new MLDSA44(seed);
    assertArrayEquals(direct.getPublicKey(), sig.getPublicKey());
    assertArrayEquals(direct.getPrivateKey(), sig.getPrivateKey());
  }

  @Test
  public void fromKeypairDispatchesAndPreservesAddress() {
    byte[] seed = new byte[FNDSA512.SEED_LENGTH];
    Arrays.fill(seed, (byte) 0x09);
    FNDSA512 src = new FNDSA512(seed);
    PQSignature sig = PQSchemeRegistry.fromKeypair(
        PQScheme.FN_DSA_512, src.getPrivateKey(), src.getPublicKey());
    assertArrayEquals(src.getAddress(), sig.getAddress());
    byte[] msg = "from-keypair".getBytes();
    byte[] s = sig.sign(msg);
    assertTrue(sig.verify(msg, s));
  }

  @Test
  public void deriveHashRejectsNullPublicKey() {
    try {
      PQSchemeRegistry.deriveHash(PQScheme.FN_DSA_512, null);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void deriveHashRejectsWrongLengthPublicKey() {
    try {
      PQSchemeRegistry.deriveHash(PQScheme.FN_DSA_512, new byte[FNDSA512.PUBLIC_KEY_LENGTH - 1]);
      fail("short public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void requireRejectsNullScheme() {
    try {
      PQSchemeRegistry.getPublicKeyLength(null);
      fail("null scheme must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("scheme"));
    }
  }

  @Test
  public void requireRejectsUnrecognizedScheme() {
    try {
      PQSchemeRegistry.getPublicKeyLength(PQScheme.UNRECOGNIZED);
      fail("UNRECOGNIZED scheme must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("PQSignature registered"));
    }
  }

  @Test
  public void requireRejectsUnknownPqScheme() {
    try {
      PQSchemeRegistry.getPublicKeyLength(PQScheme.UNKNOWN_PQ_SCHEME);
      fail("UNKNOWN_PQ_SCHEME must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("PQSignature registered"));
    }
  }

  @Test
  public void isValidSignatureLengthRejectsZero() {
    assertFalse(PQSchemeRegistry.isValidSignatureLength(PQScheme.FN_DSA_512, 0));
  }
}
