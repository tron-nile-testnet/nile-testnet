package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.junit.Before;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

public class MLDSA44Test {

  private static final MLDSAParameters PARAMS = MLDSAParameters.ml_dsa_44;

  private MLDSA44 keypair;
  private MLDSAPublicKeyParameters pk;
  private MLDSAPrivateKeyParameters sk;

  @Before
  public void setUp() {
    AsymmetricCipherKeyPair kp = freshKeyPair();
    pk = (MLDSAPublicKeyParameters) kp.getPublic();
    sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
    keypair = new MLDSA44(sk.getEncoded(), pk.getEncoded());
  }

  private static AsymmetricCipherKeyPair freshKeyPair() {
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), PARAMS));
    return gen.generateKeyPair();
  }

  private byte[] rawSign(byte[] message) {
    MLDSASigner signer = new MLDSASigner();
    signer.init(true, new ParametersWithRandom(sk, new SecureRandom()));
    signer.update(message, 0, message.length);
    try {
      return signer.generateSignature();
    } catch (Exception e) {
      throw new AssertionError("failed to sign in test setup", e);
    }
  }

  @Test
  public void schemeAndLengthsMatchFips204() {
    assertEquals(PQScheme.ML_DSA_44, keypair.getScheme());
    assertEquals(MLDSA44.PUBLIC_KEY_LENGTH, keypair.getPublicKeyLength());
    assertEquals(MLDSA44.SIGNATURE_LENGTH, keypair.getSignatureLength());
    assertEquals(MLDSA44.PRIVATE_KEY_LENGTH, keypair.getPrivateKeyLength());
    assertEquals(MLDSA44.PUBLIC_KEY_LENGTH, pk.getEncoded().length);
  }

  @Test
  public void publicKeyHasFixedLength() {
    for (int i = 0; i < 4; i++) {
      AsymmetricCipherKeyPair kp = freshKeyPair();
      byte[] pkBytes = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
      assertEquals(MLDSA44.PUBLIC_KEY_LENGTH, pkBytes.length);
    }
  }

  @Test
  public void privateKeyEncodingHasFixedLength() {
    for (int i = 0; i < 4; i++) {
      AsymmetricCipherKeyPair kp = freshKeyPair();
      byte[] skBytes = ((MLDSAPrivateKeyParameters) kp.getPrivate()).getEncoded();
      assertEquals(MLDSA44.PRIVATE_KEY_LENGTH, skBytes.length);
    }
  }

  @Test
  public void signProducesVerifiableSignatureAtFixedLength() {
    byte[] msg = "hello, ml-dsa".getBytes();
    byte[] sig = MLDSA44.sign(sk.getEncoded(), msg);
    assertEquals(
        "ML-DSA-44 signatures must be exactly SIGNATURE_LENGTH bytes",
        MLDSA44.SIGNATURE_LENGTH, sig.length);
    assertTrue(MLDSA44.verify(pk.getEncoded(), msg, sig));
  }

  @Test
  public void signatureBoundaryAtExactLengthAcceptedByLengthCheck() {
    byte[] sig = new byte[MLDSA44.SIGNATURE_LENGTH];
    keypair.validateSignature(sig);
  }

  @Test
  public void signatureBoundaryAboveExactRejected() {
    byte[] sig = new byte[MLDSA44.SIGNATURE_LENGTH + 1];
    try {
      keypair.validateSignature(sig);
      fail("signature longer than fixed length should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void shorterThanExactLengthRejectedByLengthCheck() {
    byte[] sig = new byte[MLDSA44.SIGNATURE_LENGTH - 1];
    try {
      keypair.validateSignature(sig);
      fail("signature shorter than fixed length should be rejected");
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
  public void verifyRejectsSignatureOfWrongLength() {
    byte[] msg = new byte[] {1, 2, 3};
    byte[] wrong = new byte[MLDSA44.SIGNATURE_LENGTH + 1];
    try {
      MLDSA44.verify(pk.getEncoded(), msg, wrong);
      fail("wrong-length signature should be rejected at static verify");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void verifyRejectsEmptySignature() {
    byte[] msg = new byte[] {1, 2, 3};
    byte[] empty = new byte[0];
    try {
      MLDSA44.verify(pk.getEncoded(), msg, empty);
      fail("empty signature should be rejected at static verify");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
    }
  }

  @Test
  public void invalidPublicKeyLengthRejected() {
    byte[] badPk = new byte[MLDSA44.PUBLIC_KEY_LENGTH - 1];
    byte[] msg = new byte[] {1};
    byte[] sig = new byte[MLDSA44.SIGNATURE_LENGTH];
    try {
      MLDSA44.verify(badPk, msg, sig);
      fail("short public key should be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void nullMessageRejected() {
    byte[] sig = new byte[MLDSA44.SIGNATURE_LENGTH];
    try {
      MLDSA44.verify(pk.getEncoded(), null, sig);
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
  public void wrongPublicKeyFailsVerification() {
    byte[] msg = "payload".getBytes();
    byte[] sig = rawSign(msg);
    AsymmetricCipherKeyPair other = freshKeyPair();
    byte[] otherPk = ((MLDSAPublicKeyParameters) other.getPublic()).getEncoded();
    assertFalse(MLDSA44.verify(otherPk, msg, sig));
  }

  @Test
  public void crossAlgoSignatureRejected() {
    // ML-DSA-44 signature length is fixed at 2420; FN-DSA-512 (≤752),
    // ML-DSA-65 (3309), SLH-DSA (7856) all differ and must be rejected.
    byte[] msg = "cross-algo".getBytes();
    int[] foreignLengths = {752, 3309, 7856};
    for (int len : foreignLengths) {
      byte[] foreign = new byte[len];
      try {
        MLDSA44.verify(pk.getEncoded(), msg, foreign);
        fail("foreign-scheme signature length " + len + " should be rejected for ML-DSA-44");
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
    MLDSA44 signer = new MLDSA44();
    byte[] msg = "keypair-bound".getBytes();
    byte[] sig = signer.sign(msg);
    assertEquals(MLDSA44.SIGNATURE_LENGTH, sig.length);
    assertTrue(signer.verify(msg, sig));
  }

  @Test
  public void fromSeedIsDeterministic() {
    byte[] seed = new byte[MLDSA44.SEED_LENGTH];
    for (int i = 0; i < seed.length; i++) {
      seed[i] = (byte) i;
    }
    MLDSA44 a = new MLDSA44(seed);
    MLDSA44 b = new MLDSA44(seed);
    assertArrayEquals(a.getPublicKey(), b.getPublicKey());
    assertArrayEquals(a.getPrivateKey(), b.getPrivateKey());
  }

  @Test(expected = IllegalArgumentException.class)
  public void invalidSeedLengthRejected() {
    new MLDSA44(new byte[MLDSA44.SEED_LENGTH - 1]);
  }

  @Test
  public void derivePublicKeyFromExpandedPrivateKey() {
    // Unlike Falcon, ML-DSA's expanded private key contains rho + t0 so the
    // public key (rho ‖ t1) can be recovered directly via BC's
    // MLDSAPrivateKeyParameters.getPublicKey().
    byte[] derived = MLDSA44.derivePublicKey(sk.getEncoded());
    assertArrayEquals(pk.getEncoded(), derived);
  }

  @Test
  public void computeAddressIs21Bytes() {
    assertEquals(21, MLDSA44.computeAddress(pk.getEncoded()).length);
  }

  @Test
  public void registryDispatchMatchesDirectCalls() {
    byte[] msg = "registry-dispatch".getBytes();
    byte[] sigDirect = MLDSA44.sign(sk.getEncoded(), msg);
    assertTrue(PQSchemeRegistry.verify(PQScheme.ML_DSA_44, pk.getEncoded(), msg, sigDirect));
    byte[] sigViaRegistry = PQSchemeRegistry.sign(PQScheme.ML_DSA_44, sk.getEncoded(), msg);
    assertTrue(MLDSA44.verify(pk.getEncoded(), msg, sigViaRegistry));
    assertEquals(MLDSA44.PUBLIC_KEY_LENGTH,
        PQSchemeRegistry.getPublicKeyLength(PQScheme.ML_DSA_44));
    assertEquals(MLDSA44.SIGNATURE_LENGTH, PQSchemeRegistry.getSignatureLength(PQScheme.ML_DSA_44));
  }

  @Test
  public void registryIsValidSignatureLengthRequiresExactEquality() {
    assertTrue(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.ML_DSA_44, MLDSA44.SIGNATURE_LENGTH));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(PQScheme.ML_DSA_44, 0));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.ML_DSA_44, MLDSA44.SIGNATURE_LENGTH - 1));
    assertFalse(PQSchemeRegistry.isValidSignatureLength(
        PQScheme.ML_DSA_44, MLDSA44.SIGNATURE_LENGTH + 1));
    // Variable-length tolerance only applies to FN_DSA_512 — for ML-DSA-44
    // any short length must be rejected.
    assertFalse(PQSchemeRegistry.isValidSignatureLength(PQScheme.ML_DSA_44, 1));
  }

  @Test
  public void registryComputeAddressMatchesDirect() {
    assertArrayEquals(
        MLDSA44.computeAddress(pk.getEncoded()),
        PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, pk.getEncoded()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void seedConstructorRejectsNull() {
    new MLDSA44((byte[]) null);
  }

  @Test
  public void keypairConstructorRejectsNullPrivateKey() {
    try {
      new MLDSA44(null, pk.getEncoded());
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsWrongPrivateKeyLength() {
    try {
      new MLDSA44(new byte[MLDSA44.PRIVATE_KEY_LENGTH - 1], pk.getEncoded());
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsNullPublicKey() {
    try {
      new MLDSA44(sk.getEncoded(), null);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsWrongPublicKeyLength() {
    try {
      new MLDSA44(sk.getEncoded(), new byte[MLDSA44.PUBLIC_KEY_LENGTH + 1]);
      fail("over-long public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void keypairConstructorRejectsMismatchedHalves() {
    MLDSAPublicKeyParameters strangerPk = (MLDSAPublicKeyParameters) freshKeyPair().getPublic();
    try {
      new MLDSA44(sk.getEncoded(), strangerPk.getEncoded());
      fail("mismatched private/public key pair must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("mismatch"));
    }
  }

  @Test
  public void staticSignRejectsNullPrivateKey() {
    try {
      MLDSA44.sign(null, new byte[] {1});
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void staticSignRejectsWrongPrivateKeyLength() {
    try {
      MLDSA44.sign(new byte[MLDSA44.PRIVATE_KEY_LENGTH - 1], new byte[] {1});
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void staticSignRejectsNullMessage() {
    try {
      MLDSA44.sign(sk.getEncoded(), null);
      fail("null message must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("message"));
    }
  }

  @Test
  public void staticVerifyRejectsNullPublicKey() {
    try {
      MLDSA44.verify(null, new byte[] {1}, new byte[MLDSA44.SIGNATURE_LENGTH]);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void derivePublicKeyRejectsNull() {
    try {
      MLDSA44.derivePublicKey(null);
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void derivePublicKeyRejectsWrongLength() {
    try {
      MLDSA44.derivePublicKey(new byte[MLDSA44.PRIVATE_KEY_LENGTH - 1]);
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }
}
