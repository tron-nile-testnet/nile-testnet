package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.junit.Before;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

public class FNDSA512Test {

  private static final FalconParameters PARAMS = FalconParameters.falcon_512;

  private FNDSA512 keypair;
  private FalconPublicKeyParameters pk;
  private FalconPrivateKeyParameters sk;

  @Before
  public void setUp() {
    AsymmetricCipherKeyPair kp = freshKeyPair();
    pk = (FalconPublicKeyParameters) kp.getPublic();
    sk = (FalconPrivateKeyParameters) kp.getPrivate();
    keypair = new FNDSA512(sk.getEncoded(), pk.getH());
  }

  private static AsymmetricCipherKeyPair freshKeyPair() {
    FalconKeyPairGenerator gen = new FalconKeyPairGenerator();
    gen.init(new FalconKeyGenerationParameters(new SecureRandom(), PARAMS));
    return gen.generateKeyPair();
  }

  private byte[] rawSign(byte[] message) {
    FalconSigner signer = new FalconSigner();
    signer.init(true, new ParametersWithRandom(sk, new SecureRandom()));
    try {
      return signer.generateSignature(message);
    } catch (Exception e) {
      throw new AssertionError("failed to sign in test setup", e);
    }
  }

  @Test
  public void schemeAndLengthsMatchFips206Draft() {
    assertEquals(PQScheme.FN_DSA_512, keypair.getScheme());
    assertEquals(FNDSA512.PUBLIC_KEY_LENGTH, keypair.getPublicKeyLength());
    assertEquals(FNDSA512.SIGNATURE_MAX_LENGTH, keypair.getSignatureLength());
    assertEquals(617, keypair.getSignatureMinLength());
    assertEquals(FNDSA512.PRIVATE_KEY_LENGTH, keypair.getPrivateKeyLength());
    assertEquals(FNDSA512.PUBLIC_KEY_LENGTH, pk.getH().length);
  }

  @Test
  public void publicKeyHasFixedLength() {
    for (int i = 0; i < 4; i++) {
      AsymmetricCipherKeyPair kp = freshKeyPair();
      byte[] pkBytes = ((FalconPublicKeyParameters) kp.getPublic()).getH();
      assertEquals(FNDSA512.PUBLIC_KEY_LENGTH, pkBytes.length);
    }
  }

  @Test
  public void privateKeyEncodingHasFixedLength() {
    for (int i = 0; i < 4; i++) {
      AsymmetricCipherKeyPair kp = freshKeyPair();
      byte[] skBytes = ((FalconPrivateKeyParameters) kp.getPrivate()).getEncoded();
      assertEquals(FNDSA512.PRIVATE_KEY_LENGTH, skBytes.length);
    }
  }

  @Test
  public void signProducesVerifiableSignatureWithinBound() {
    byte[] msg = "hello, fn-dsa".getBytes();
    byte[] sig = FNDSA512.sign(sk.getEncoded(), msg);
    assertTrue("signature must be non-empty", sig.length > 0);
    assertTrue(
        "signature must respect protocol-level upper bound",
        sig.length <= FNDSA512.SIGNATURE_MAX_LENGTH);
    assertTrue(
        "signature must respect protocol-level lower bound",
        sig.length >= FNDSA512.SIGNATURE_MIN_LENGTH);
    assertTrue(FNDSA512.verify(pk.getH(), msg, sig));
  }

  @Test
  public void signatureBoundaryAtMaxAcceptedByLengthCheck() {
    byte[] sig = new byte[FNDSA512.SIGNATURE_MAX_LENGTH];
    keypair.validateSignature(sig);
  }

  @Test
  public void signatureBoundaryAboveMaxRejected() {
    byte[] sig = new byte[FNDSA512.SIGNATURE_MAX_LENGTH + 1];
    try {
      keypair.validateSignature(sig);
      fail("signature longer than upper bound should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void minimalValidLengthAcceptedByLengthCheck() {
    byte[] sig = new byte[FNDSA512.SIGNATURE_MIN_LENGTH];
    keypair.validateSignature(sig);
  }

  @Test
  public void belowMinLengthRejectedByLengthCheck() {
    byte[] sig = new byte[FNDSA512.SIGNATURE_MIN_LENGTH - 1];
    try {
      keypair.validateSignature(sig);
      fail("signature shorter than min should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void emptySignatureRejectedByLengthCheck() {
    byte[] sig = new byte[0];
    try {
      keypair.validateSignature(sig);
      fail("empty signature should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void verifyRejectsSignatureLongerThanUpperBound() {
    byte[] msg = new byte[] {1, 2, 3};
    byte[] tooLong = new byte[FNDSA512.SIGNATURE_MAX_LENGTH + 1];
    try {
      FNDSA512.verify(pk.getH(), msg, tooLong);
      fail("signature exceeding upper bound should be rejected at static verify");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void verifyRejectsEmptySignature() {
    byte[] msg = new byte[] {1, 2, 3};
    byte[] empty = new byte[0];
    try {
      FNDSA512.verify(pk.getH(), msg, empty);
      fail("empty signature should be rejected at static verify");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[FNDSA512.PUBLIC_KEY_LENGTH - 1];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[FNDSA512.SIGNATURE_MIN_LENGTH];
    try {
      FNDSA512.verify(badPk, msg, sig);
      fail("short public key should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[FNDSA512.SIGNATURE_MIN_LENGTH];
    try {
      FNDSA512.verify(pk.getH(), null, sig);
      fail("null message should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("message"));
    }
  }

  @Test
  public void signatureBoundToMessage() {
    byte[] msg = "hello".getBytes();
    byte[] sig = rawSign(msg);
    byte[] tamperedMsg = "hellp".getBytes();
    assertFalse(keypair.verify(tamperedMsg, sig));
  }

  @Test
  public void tamperedSignatureFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = rawSign(msg);
    sig[0] ^= 0x01;
    assertFalse(keypair.verify(msg, sig));
  }

  @Test
  public void validSignatureCarriesCanonicalHeader() {
    byte[] msg = "header check".getBytes();
    byte[] sig = rawSign(msg);
    assertEquals(
        "BC must produce the canonical compressed header",
        FNDSA512.SIGNATURE_HEADER, sig[0]);
  }

  @Test
  public void nonCanonicalHeaderRejected() {
    byte[] msg = "header check".getBytes();
    byte[] sig = rawSign(msg);
    assertTrue(FNDSA512.verify(pk.getH(), msg, sig));
    // Padded (0x49) and constant-time (0x59) encodings must be rejected even though
    // their length is in range — only the compressed 0x39 header is accepted.
    for (byte header : new byte[] {0x49, 0x59, 0x00, (byte) 0xFF}) {
      byte[] tampered = sig.clone();
      tampered[0] = header;
      assertFalse(
          "non-canonical header 0x" + Integer.toHexString(header & 0xFF) + " must be rejected",
          FNDSA512.verify(pk.getH(), msg, tampered));
    }
  }

  @Test
  public void wrongPublicKeyFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = rawSign(msg);
    AsymmetricCipherKeyPair other = freshKeyPair();
    byte[] otherPk = ((FalconPublicKeyParameters) other.getPublic()).getH();
    assertFalse(FNDSA512.verify(otherPk, msg, sig));
  }

  @Test
  public void crossAlgoSignatureRejected() {
    // FN-DSA upper bound is 666 bytes; ML-DSA-44 (2420), ML-DSA-65 (3309),
    // SLH-DSA (7856) all exceed it and must be rejected at the length check.
    byte[] msg = "cross-algo".getBytes();
    int[] foreignLengths = {2420, 3309, 7856};
    for (int len : foreignLengths) {
      byte[] foreign = new byte[len];
      try {
        FNDSA512.verify(pk.getH(), msg, foreign);
        fail("foreign-scheme signature length " + len + " should be rejected for FN-DSA");
      } catch (IllegalArgumentException expected) {
        assertTrue(expected.getMessage().contains("signature length"));
      }
    }
  }

  @Test
  public void emptyMessageVerifiesConsistently() {
    byte[] msg = new byte[0];
    byte[] sig = rawSign(msg);
    assertTrue(keypair.verify(msg, sig));
  }

  @Test
  public void keypairBoundInstanceSignsAndVerifies() {
    FNDSA512 signer = new FNDSA512();
    byte[] msg = "keypair-bound".getBytes();
    byte[] sig = signer.sign(msg);
    assertTrue(sig.length > 0 && sig.length <= FNDSA512.SIGNATURE_MAX_LENGTH);
    assertTrue(signer.verify(msg, sig));
  }

  @Test
  public void fromSeedIsDeterministic() {
    byte[] seed = new byte[FNDSA512.SEED_LENGTH];
    for (int i = 0; i < seed.length; i++) {
      seed[i] = (byte) i;
    }
    FNDSA512 a = new FNDSA512(seed);
    FNDSA512 b = new FNDSA512(seed);
    assertArrayEquals(a.getPublicKey(), b.getPublicKey());
    assertArrayEquals(a.getPrivateKey(), b.getPrivateKey());
  }

  @Test(expected = IllegalArgumentException.class)
  public void invalidSeedLengthRejected() {
    new FNDSA512(new byte[FNDSA512.SEED_LENGTH - 1]);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void derivePublicKeyFromEncodedPrivateKeyUnsupported() {
    FNDSA512.derivePublicKey(sk.getEncoded());
  }

  @Test
  public void computeAddressIs21Bytes() {
    assertEquals(21, FNDSA512.computeAddress(pk.getH()).length);
  }

  @Test
  public void registryDispatchMatchesDirectCalls() {
    byte[] msg = "registry-dispatch".getBytes();
    byte[] sigDirect = FNDSA512.sign(sk.getEncoded(), msg);
    assertTrue(PQSchemeRegistry.verify(PQScheme.FN_DSA_512, pk.getH(), msg, sigDirect));
    byte[] sigViaRegistry = PQSchemeRegistry.sign(PQScheme.FN_DSA_512, sk.getEncoded(), msg);
    assertTrue(FNDSA512.verify(pk.getH(), msg, sigViaRegistry));
    assertEquals(FNDSA512.PUBLIC_KEY_LENGTH,
        PQSchemeRegistry.getPublicKeyLength(PQScheme.FN_DSA_512));
    assertEquals(FNDSA512.SIGNATURE_MAX_LENGTH,
        PQSchemeRegistry.getSignatureLength(PQScheme.FN_DSA_512));
  }

  @Test
  public void registryIsValidSignatureLengthRespectsBounds() {
    assertTrue(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.FN_DSA_512, FNDSA512.SIGNATURE_MIN_LENGTH));
    assertTrue(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.FN_DSA_512, FNDSA512.SIGNATURE_MAX_LENGTH));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(PQScheme.FN_DSA_512, 0));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.FN_DSA_512, FNDSA512.SIGNATURE_MIN_LENGTH - 1));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.FN_DSA_512, FNDSA512.SIGNATURE_MAX_LENGTH + 1));
  }

  @Test
  public void registryComputeAddressMatchesDirect() {
    assertArrayEquals(
        FNDSA512.computeAddress(pk.getH()),
        PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pk.getH()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void seedConstructorRejectsNull() {
    new FNDSA512((byte[]) null);
  }

  @Test
  public void keypairConstructorRejectsNullPrivateKey() {
    try {
      new FNDSA512(null, pk.getH());
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsWrongPrivateKeyLength() {
    try {
      new FNDSA512(new byte[FNDSA512.PRIVATE_KEY_LENGTH - 1], pk.getH());
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsNullPublicKey() {
    try {
      new FNDSA512(sk.getEncoded(), null);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsWrongPublicKeyLength() {
    try {
      new FNDSA512(sk.getEncoded(), new byte[FNDSA512.PUBLIC_KEY_LENGTH + 1]);
      fail("over-long public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsMismatchedHalves() {
    FalconPublicKeyParameters strangerPk = (FalconPublicKeyParameters) freshKeyPair().getPublic();
    try {
      new FNDSA512(sk.getEncoded(), strangerPk.getH());
      fail("mismatched private/public key pair must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("mismatch"));
    }
  }

  @Test
  public void extendedPrivateKeyRoundTripsThroughFromAndGetters() {
    byte[] extended = keypair.getPrivateKeyWithPublicKey();
    assertEquals(FNDSA512.PRIVATE_KEY_WITH_PUBLIC_KEY_LENGTH, extended.length);
    FNDSA512 restored = FNDSA512.fromPrivateKeyWithPublicKey(extended);
    assertArrayEquals(keypair.getPrivateKey(), restored.getPrivateKey());
    assertArrayEquals(keypair.getPublicKey(), restored.getPublicKey());
    // The recovered keypair must produce verifiable signatures and recover its address.
    byte[] msg = "extended-key-roundtrip".getBytes();
    byte[] sig = restored.sign(msg);
    assertTrue(restored.verify(msg, sig));
    assertArrayEquals(keypair.getAddress(), restored.getAddress());
  }

  @Test(expected = IllegalArgumentException.class)
  public void fromExtendedPrivateKeyRejectsNull() {
    FNDSA512.fromPrivateKeyWithPublicKey(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void fromExtendedPrivateKeyRejectsWrongLength() {
    FNDSA512.fromPrivateKeyWithPublicKey(new byte[FNDSA512.PRIVATE_KEY_LENGTH]);
  }

  @Test
  public void derivePublicKeyFromExtendedFormReturnsAppendedPublicKey() {
    byte[] extended = keypair.getPrivateKeyWithPublicKey();
    byte[] derived = FNDSA512.derivePublicKey(extended);
    assertArrayEquals(keypair.getPublicKey(), derived);
  }

  @Test(expected = IllegalArgumentException.class)
  public void derivePublicKeyRejectsNull() {
    FNDSA512.derivePublicKey(null);
  }

  @Test
  public void staticSignAcceptsExtendedPrivateKey() {
    byte[] extended = keypair.getPrivateKeyWithPublicKey();
    byte[] msg = "static-sign-extended".getBytes();
    byte[] sig = FNDSA512.sign(extended, msg);
    assertTrue(sig.length > 0 && sig.length <= FNDSA512.SIGNATURE_MAX_LENGTH);
    assertTrue(FNDSA512.verify(pk.getH(), msg, sig));
  }

  @Test
  public void staticSignRejectsNullPrivateKey() {
    try {
      FNDSA512.sign(null, new byte[] {1});
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void staticSignRejectsWrongPrivateKeyLength() {
    try {
      FNDSA512.sign(new byte[FNDSA512.PRIVATE_KEY_LENGTH - 1], new byte[] {1});
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void staticSignRejectsNullMessage() {
    try {
      FNDSA512.sign(sk.getEncoded(), null);
      fail("null message must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("message"));
    }
  }

  @Test
  public void staticVerifyRejectsNullPublicKey() {
    try {
      FNDSA512.verify(null, new byte[] {1}, new byte[16]);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void unknownPqSchemeIsRejectedAtRegistry() {
    // The proto3 default UNKNOWN_PQ_SCHEME is reserved and must not be
    // interpreted as any registered scheme; producers must set the tag
    // explicitly.
    assertFalse(PQSchemeRegistry.contains(PQScheme.UNKNOWN_PQ_SCHEME));
    try {
      PQSchemeRegistry.getPublicKeyLength(PQScheme.UNKNOWN_PQ_SCHEME);
      fail("UNKNOWN_PQ_SCHEME must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("PQSignature registered"));
    }
  }
}
