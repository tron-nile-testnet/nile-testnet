package org.tron.common.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.PQScheme;

public class LocalWitnessesTest {

  // Real Falcon-512 keypair generated once per test class. We exercise the
  // (priv, pub) keypair config path with bytes that satisfy the BC ops, so the
  // tests below never hit cross-platform FFT determinism concerns.
  private static String priv;
  private static String pub;
  private static String priv2;
  private static String pub2;

  @BeforeClass
  public static void generateKeypairs() {
    FNDSA512 k1 = new FNDSA512();
    FNDSA512 k2 = new FNDSA512();
    priv = Hex.toHexString(k1.getPrivateKey());
    pub = Hex.toHexString(k1.getPublicKey());
    priv2 = Hex.toHexString(k2.getPrivateKey());
    pub2 = Hex.toHexString(k2.getPublicKey());
  }

  @Test
  public void fnDsa512AcceptsValidKeypair() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(Collections.singletonList(new PqKeypair(PQScheme.FN_DSA_512, priv, pub)));
    assertEquals(1, lw.getPqKeypairs().size());
    assertEquals(PQScheme.FN_DSA_512, lw.getPqKeypairs().get(0).getScheme());
  }

  @Test
  public void fnDsa512AcceptsMultipleKeypairs() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(Arrays.asList(
        new PqKeypair(PQScheme.FN_DSA_512, priv, pub),
        new PqKeypair(PQScheme.FN_DSA_512, priv2, pub2)));
    assertEquals(2, lw.getPqKeypairs().size());
  }

  @Test
  public void wrongLengthPrivateKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String shortPriv = priv.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(PQScheme.FN_DSA_512, shortPriv, pub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ private key"));
    // FN-DSA-512 private key is 1280 bytes; validation reports the byte length.
    assertTrue(err.getMessage().contains("1280"));
  }

  @Test
  public void wrongLengthPublicKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String shortPub = pub.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(PQScheme.FN_DSA_512, priv, shortPub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ public key"));
    // FN-DSA-512 public key is 896 bytes; validation reports the byte length.
    assertTrue(err.getMessage().contains("896"));
  }

  @Test
  public void oddLengthPrivateKeyRejectedAsLengthError() {
    LocalWitnesses lw = new LocalWitnesses();
    // Drop a single nibble -> odd hex length. fromHexString would left-pad this
    // to the right byte count, so without an explicit length check it would slip
    // through and fail later as a keypair mismatch. It must fail here instead.
    String oddPriv = priv.substring(1);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(PQScheme.FN_DSA_512, oddPriv, pub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ private key"));
    assertTrue(err.getMessage().contains("1280"));
  }

  @Test
  public void nullPrivateKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(PQScheme.FN_DSA_512, null, pub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ private key"));
    assertTrue(err.getMessage().contains("1280"));
  }

  @Test
  public void nonHexPrivateKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String badPriv = "zz" + priv.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(PQScheme.FN_DSA_512, badPriv, pub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("hex"));
  }

  @Test
  public void unsupportedSchemeRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(PQScheme.UNRECOGNIZED, priv, pub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("unsupported PQ signature scheme"));
  }

  @Test
  public void nullSchemeRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(null, priv, pub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("unsupported PQ signature scheme"));
  }

  @Test
  public void emptyKeypairsAreNoop() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(Collections.emptyList());
    lw.setPqKeypairs(null);
    assertEquals(0, lw.getPqKeypairs().size());
  }

  @Test
  public void zeroXPrefixedHexAccepted() {
    // validatePqKey strips a leading "0x" before measuring the length, so
    // hex strings with the prefix must be accepted.
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(Collections.singletonList(
        new PqKeypair(PQScheme.FN_DSA_512, "0x" + priv, "0x" + pub)));
    assertEquals(1, lw.getPqKeypairs().size());
  }

  @Test
  public void blankKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(
            new PqKeypair(PQScheme.FN_DSA_512, "", pub))));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ private key"));
  }

  @Test
  public void sameWitnessAddressForEcdsaAndPqRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    // Distinct array instances with identical content: must be compared by value
    // (Arrays.equals), not by reference.
    lw.setWitnessAccountAddress(new byte[] {0x41, 1, 2, 3});
    lw.setPqWitnessAccountAddress(new byte[] {0x41, 1, 2, 3});
    TronError err = assertThrows(TronError.class, lw::checkWitnessAddressConflict);
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("only one key"));
  }

  @Test
  public void distinctWitnessAddressesAccepted() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setWitnessAccountAddress(new byte[] {0x41, 1, 2, 3});
    lw.setPqWitnessAccountAddress(new byte[] {0x41, 4, 5, 6});
    lw.checkWitnessAddressConflict(); // no throw
  }

  @Test
  public void onlyOneWitnessAddressSetAccepted() {
    LocalWitnesses ecdsaOnly = new LocalWitnesses();
    ecdsaOnly.setWitnessAccountAddress(new byte[] {0x41, 1, 2, 3});
    ecdsaOnly.checkWitnessAddressConflict(); // pq address null -> no throw

    LocalWitnesses pqOnly = new LocalWitnesses();
    pqOnly.setPqWitnessAccountAddress(new byte[] {0x41, 1, 2, 3});
    pqOnly.checkWitnessAddressConflict(); // ecdsa address null -> no throw
  }

  @Test
  public void noWitnessAddressSetAccepted() {
    new LocalWitnesses().checkWitnessAddressConflict(); // both null -> no throw
  }
}
