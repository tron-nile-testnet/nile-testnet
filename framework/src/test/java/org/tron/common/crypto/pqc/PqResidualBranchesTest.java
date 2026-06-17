package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

/**
 * Pins the residual, deterministic branches of the PQ scheme classes that the
 * primary {@link MLDSA44Test}/{@link FNDSA512Test}/{@link PQSchemeRegistryTest}
 * suites leave uncovered: the registry's scheme-specific {@code derivePublicKey}
 * fork, the {@code fromKeypair} factory, the signature-min-length accessor, and
 * the verify/consistency error paths that swallow a BouncyCastle exception and
 * map it to a clean rejection.
 */
public class PqResidualBranchesTest {

  private static final MLDSAParameters ML_PARAMS = MLDSAParameters.ml_dsa_44;

  private static AsymmetricCipherKeyPair freshMlKeyPair() {
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), ML_PARAMS));
    return gen.generateKeyPair();
  }

  // --- PQSchemeRegistry residual branches ----------------------------------

  @Test
  public void registryDerivePublicKeyReturnsNullForFalcon() {
    // Falcon's SignatureOps uses the interface default, which returns null:
    // BC has no API to recover h from (f, g) alone.
    byte[] bareSk = new byte[FNDSA512.PRIVATE_KEY_LENGTH];
    assertNull(PQSchemeRegistry.derivePublicKey(PQScheme.FN_DSA_512, bareSk));
  }

  @Test
  public void registryDerivePublicKeyRecoversForMlDsa() {
    AsymmetricCipherKeyPair kp = freshMlKeyPair();
    byte[] sk = ((MLDSAPrivateKeyParameters) kp.getPrivate()).getEncoded();
    byte[] pk = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
    assertArrayEquals(pk, PQSchemeRegistry.derivePublicKey(PQScheme.ML_DSA_44, sk));
  }

  @Test
  public void registryFromKeypairBuildsMlDsaSigner() {
    AsymmetricCipherKeyPair kp = freshMlKeyPair();
    byte[] sk = ((MLDSAPrivateKeyParameters) kp.getPrivate()).getEncoded();
    byte[] pk = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();

    PQSignature signer = PQSchemeRegistry.fromKeypair(PQScheme.ML_DSA_44, sk, pk);
    assertEquals(PQScheme.ML_DSA_44, signer.getScheme());
    assertArrayEquals(pk, signer.getPublicKey());

    byte[] msg = "registry-from-keypair".getBytes();
    byte[] sig = signer.sign(msg);
    org.junit.Assert.assertTrue(signer.verify(msg, sig));
  }

  @Test
  public void registryReportsPerSchemeSignatureMinLength() {
    assertEquals(FNDSA512.SIGNATURE_MIN_LENGTH,
        PQSchemeRegistry.getSignatureMinLength(PQScheme.FN_DSA_512));
    // ML-DSA-44 is fixed-length: min equals the exact length.
    assertEquals(MLDSA44.SIGNATURE_LENGTH,
        PQSchemeRegistry.getSignatureMinLength(PQScheme.ML_DSA_44));
  }

  // --- MLDSA44 residual branches -------------------------------------------

  @Test
  public void mlDsaVerifyReturnsFalseOnStructurallyInvalidSignature() {
    // A correctly-sized but internally garbage signature drives BC's verifier
    // into its RuntimeException path, which verify() maps to a plain false.
    AsymmetricCipherKeyPair kp = freshMlKeyPair();
    byte[] pk = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
    byte[] garbage = new byte[MLDSA44.SIGNATURE_LENGTH];
    for (int i = 0; i < garbage.length; i++) {
      garbage[i] = (byte) 0xff;
    }
    assertFalse(MLDSA44.verify(pk, "msg".getBytes(), garbage));
  }

  @Test
  public void mlDsaKeypairConstructorRejectsUnparseablePrivateKey() {
    // Length is correct so the early length guard passes; the bytes cannot form
    // a valid expanded key, so requireConsistent's derivePublicKey throws and is
    // re-mapped to IllegalArgumentException("malformed").
    AsymmetricCipherKeyPair kp = freshMlKeyPair();
    byte[] pk = ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded();
    byte[] badSk = new byte[MLDSA44.PRIVATE_KEY_LENGTH];
    for (int i = 0; i < badSk.length; i++) {
      badSk[i] = (byte) 0xff;
    }
    try {
      new MLDSA44(badSk, pk);
      fail("unparseable private key must be rejected");
    } catch (IllegalArgumentException expected) {
      org.junit.Assert.assertTrue(
          expected.getMessage().contains("malformed")
              || expected.getMessage().contains("mismatch"));
    }
  }

  // --- FNDSA512 residual branches ------------------------------------------

  @Test
  public void falconVerifyReturnsFalseOnWrongHeaderByte() {
    // A signature whose first byte is not SIGNATURE_HEADER is rejected up front
    // without invoking BC — covers the header guard's false branch.
    byte[] pk = new byte[FNDSA512.PUBLIC_KEY_LENGTH];
    byte[] sig = new byte[FNDSA512.SIGNATURE_MIN_LENGTH];
    sig[0] = (byte) (FNDSA512.SIGNATURE_HEADER ^ 0x01);
    assertFalse(FNDSA512.verify(pk, "msg".getBytes(), sig));
  }

  @Test
  public void falconVerifyReturnsFalseWhenBcThrows() {
    // Correct header byte but otherwise garbage: BC's verifier throws, and
    // verify() maps the RuntimeException to false.
    byte[] pk = new byte[FNDSA512.PUBLIC_KEY_LENGTH];
    byte[] sig = new byte[FNDSA512.SIGNATURE_MIN_LENGTH];
    sig[0] = FNDSA512.SIGNATURE_HEADER;
    for (int i = 1; i < sig.length; i++) {
      sig[i] = (byte) 0xff;
    }
    assertFalse(FNDSA512.verify(pk, "msg".getBytes(), sig));
  }
}
