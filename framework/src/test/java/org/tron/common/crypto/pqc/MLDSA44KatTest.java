package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.tron.common.crypto.Hash;
import org.tron.protos.Protocol.PQScheme;

/**
 * Known-Answer Tests (KAT) for ML-DSA-44 / FIPS 204 / Dilithium-2.
 *
 * <p>Five seed vectors covering boundary patterns (incrementing, all-zero,
 * all-ones, all-{@code 0xAA}, descending) lock in the deterministic
 * seed → keypair derivation pinned by BouncyCastle 1.84's
 * {@code MLDSAKeyPairGenerator}. Reference {@code pk}/{@code sk} digests and
 * the V2 fingerprint address are captured from this same codebase / BC 1.84;
 * the role of the test is regression detection — any change in seeding,
 * encoding, or fingerprint derivation lights up.
 *
 * <p>ML-DSA signing is randomized (hedged) so signature bytes cannot be pinned.
 * Sign / verify is exercised per-vector and cross-vector to confirm signatures
 * only verify under their own key.
 */
public class MLDSA44KatTest {

  private static final class KatVector {
    final String label;
    final byte[] seed;
    final String pkSha256;
    final String skSha256;

    KatVector(String label, byte[] seed, String pkSha256, String skSha256) {
      this.label = label;
      this.seed = seed;
      this.pkSha256 = pkSha256;
      this.skSha256 = skSha256;
    }
  }

  private static byte[] seedIncrementing() {
    byte[] s = new byte[MLDSA44.SEED_LENGTH];
    for (int i = 0; i < s.length; i++) {
      s[i] = (byte) i;
    }
    return s;
  }

  private static byte[] seedDescending() {
    byte[] s = new byte[MLDSA44.SEED_LENGTH];
    for (int i = 0; i < s.length; i++) {
      s[i] = (byte) (MLDSA44.SEED_LENGTH - 1 - i);
    }
    return s;
  }

  private static byte[] seedFilled(int b) {
    byte[] s = new byte[MLDSA44.SEED_LENGTH];
    Arrays.fill(s, (byte) b);
    return s;
  }

  private static final KatVector[] VECTORS = {
      new KatVector("incrementing", seedIncrementing(),
          "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46",
          "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b"),
      new KatVector("all_zero", seedFilled(0x00),
          "eb4e7302842153b0fa19e8620739ad258af4929c26dd89079a7ec7d4282208e1",
          "0f9086044d77b6d610c7e92418d9f70a398c69febc7e99f8254aaea98dcfbe77"),
      new KatVector("all_ff", seedFilled(0xff),
          "62c4f1b3164db7fa896a3343e900eb3e13c9f76de122020feba37ee063d49ef0",
          "6433074c5ffc9e0f2b1d68bb3fda84e439da0a2d93f508a101e9b44835f0b22c"),
      new KatVector("all_aa", seedFilled(0xaa),
          "ad4aff7ef5aa8895fb4f59c2c211afe55419d0d8709bfa0ee4d8f496e92600a7",
          "d976fecd6cda24ca928a43e2bcd3eb53e6dfb24a759333f818f6496abc27feb5"),
      new KatVector("descending", seedDescending(),
          "4b002454d4516328cb1bf3667959879140dc9e6b3f405e985f707dd49918c818",
          "1d144d5f05beb34beb1b909ecd469e0484f485a3c68db6e27da464418f7d69ea"),
  };

  private static byte[] sha256(byte[] in) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(in);
    } catch (Exception e) {
      throw new AssertionError("SHA-256 unavailable", e);
    }
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) {
      sb.append(String.format("%02x", x));
    }
    return sb.toString();
  }

  @Test
  public void allVectorsDeriveExpectedPublicAndPrivateKey() {
    for (KatVector v : VECTORS) {
      MLDSA44 k = new MLDSA44(v.seed);
      assertEquals(v.label + ": pk length", MLDSA44.PUBLIC_KEY_LENGTH, k.getPublicKey().length);
      assertEquals(v.label + ": sk length", MLDSA44.PRIVATE_KEY_LENGTH, k.getPrivateKey().length);
      assertEquals(v.label + ": pk SHA-256 must match KAT vector",
          v.pkSha256, hex(sha256(k.getPublicKey())));
      assertEquals(v.label + ": sk SHA-256 must match KAT vector",
          v.skSha256, hex(sha256(k.getPrivateKey())));
    }
  }

  @Test
  public void allVectorsDeriveExpectedAddress() {
    for (KatVector v : VECTORS) {
      MLDSA44 k = new MLDSA44(v.seed);
      byte[] addr = k.getAddress();
      assertEquals(v.label + ": address length", 21, addr.length);

      byte[] viaRegistry = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, k.getPublicKey());
      assertArrayEquals(v.label + ": registry dispatch must match instance", addr, viaRegistry);
    }
  }

  @Test
  public void addressIsExactly0x41PlusKeccak256RightmostBytesOfPublicKey() {
    for (KatVector v : VECTORS) {
      MLDSA44 k = new MLDSA44(v.seed);
      byte[] pk = k.getPublicKey();
      byte[] hash = Hash.sha3(pk);
      byte[] expected = new byte[21];
      expected[0] = 0x41;
      System.arraycopy(hash, hash.length - 20, expected, 1, 20);
      assertArrayEquals(v.label + ": address must be 0x41 ‖ Keccak-256(pk)[12..32]",
          expected, k.getAddress());
    }
  }

  @Test
  public void allVectorsAreReproducibleAcrossInstances() {
    for (KatVector v : VECTORS) {
      MLDSA44 a = new MLDSA44(v.seed);
      MLDSA44 b = new MLDSA44(v.seed);
      assertArrayEquals(v.label + ": pk reproducible", a.getPublicKey(), b.getPublicKey());
      assertArrayEquals(v.label + ": sk reproducible", a.getPrivateKey(), b.getPrivateKey());
      assertArrayEquals(v.label + ": addr reproducible", a.getAddress(), b.getAddress());
    }
  }

  @Test
  public void distinctSeedsProduceDistinctKeysAndAddresses() {
    Set<String> pkDigests = new HashSet<>();
    Set<String> skDigests = new HashSet<>();
    Set<String> addresses = new HashSet<>();
    for (KatVector v : VECTORS) {
      pkDigests.add(v.pkSha256);
      skDigests.add(v.skSha256);
      addresses.add(hex(new MLDSA44(v.seed).getAddress()));
    }
    assertEquals("KAT pk digests must be pairwise distinct", VECTORS.length, pkDigests.size());
    assertEquals("KAT sk digests must be pairwise distinct", VECTORS.length, skDigests.size());
    assertEquals("KAT addresses must be pairwise distinct", VECTORS.length, addresses.size());
  }

  @Test
  public void signaturesFromKatKeysVerifyUnderTheirOwnPublicKey() {
    byte[][] messages = {
        new byte[0], "x".getBytes(), "tron-ml-dsa-kat-message".getBytes(), new byte[1024]};
    for (KatVector v : VECTORS) {
      MLDSA44 k = new MLDSA44(v.seed);
      for (byte[] msg : messages) {
        byte[] sig = k.sign(msg);
        assertEquals(v.label + ": signature must be fixed 2420 bytes",
            MLDSA44.SIGNATURE_LENGTH, sig.length);
        assertTrue(v.label + ": signature must verify under its own pk",
            MLDSA44.verify(k.getPublicKey(), msg, sig));
        assertTrue(v.label + ": registry verify must accept own signature",
            PQSchemeRegistry.verify(
                PQScheme.ML_DSA_44, k.getPublicKey(), msg, sig));
      }
    }
  }

  @Test
  public void signatureFromVectorAFailsUnderVectorBPublicKey() {
    byte[] msg = "tron-ml-dsa-kat-cross".getBytes();
    MLDSA44[] keys = new MLDSA44[VECTORS.length];
    byte[][] sigs = new byte[VECTORS.length][];
    for (int i = 0; i < VECTORS.length; i++) {
      keys[i] = new MLDSA44(VECTORS[i].seed);
      sigs[i] = keys[i].sign(msg);
    }
    for (int i = 0; i < VECTORS.length; i++) {
      for (int j = 0; j < VECTORS.length; j++) {
        if (i == j) {
          assertTrue(VECTORS[i].label + ": self-verify must succeed",
              MLDSA44.verify(keys[i].getPublicKey(), msg, sigs[i]));
        } else {
          assertFalse("signature from " + VECTORS[i].label
                  + " must NOT verify under " + VECTORS[j].label,
              MLDSA44.verify(keys[j].getPublicKey(), msg, sigs[i]));
        }
      }
    }
  }

  @Test
  public void distinctSeedsAtRuntimeAlsoProduceDistinctRuntimePublicKeys() {
    // Belt-and-braces: the sanity check above only compared hard-coded digests.
    // Re-derive at runtime and confirm they're still pairwise distinct.
    byte[][] pks = new byte[VECTORS.length][];
    for (int i = 0; i < VECTORS.length; i++) {
      pks[i] = new MLDSA44(VECTORS[i].seed).getPublicKey();
    }
    for (int i = 0; i < VECTORS.length; i++) {
      for (int j = i + 1; j < VECTORS.length; j++) {
        assertFalse(
            VECTORS[i].label + " and " + VECTORS[j].label
                + " produced identical pk bytes",
            Arrays.equals(pks[i], pks[j]));
        assertNotEquals(
            VECTORS[i].label + " and " + VECTORS[j].label
                + " produced identical pk digests",
            hex(sha256(pks[i])), hex(sha256(pks[j])));
      }
    }
  }
}
