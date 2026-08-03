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
 * Known-Answer Tests (KAT) for FN-DSA / Falcon-512.
 *
 * <p>Five seed vectors covering boundary patterns (incrementing, all-zero,
 * all-ones, all-{@code 0xAA}, descending) lock in the deterministic
 * seed → keypair derivation pinned by BouncyCastle 1.79's
 * {@code FalconKeyPairGenerator}. Reference {@code pk}/{@code sk} digests and
 * the V2 fingerprint address are captured from this same codebase / BC 1.79;
 * the role of the test is regression detection — any change in seeding,
 * encoding, or fingerprint derivation lights up.
 *
 * <p>Falcon signing is randomized so signature bytes cannot be pinned. Sign /
 * verify is exercised per-vector and cross-vector to confirm signatures only
 * verify under their own key.
 */
public class FNDSA512KatTest {

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
    byte[] s = new byte[FNDSA512.SEED_LENGTH];
    for (int i = 0; i < s.length; i++) {
      s[i] = (byte) i;
    }
    return s;
  }

  private static byte[] seedDescending() {
    byte[] s = new byte[FNDSA512.SEED_LENGTH];
    for (int i = 0; i < s.length; i++) {
      s[i] = (byte) (FNDSA512.SEED_LENGTH - 1 - i);
    }
    return s;
  }

  private static byte[] seedFilled(int b) {
    byte[] s = new byte[FNDSA512.SEED_LENGTH];
    Arrays.fill(s, (byte) b);
    return s;
  }

  private static final KatVector[] VECTORS = {
      new KatVector("incrementing", seedIncrementing(),
          "1cc09837c6931f9c5988e59ad0acd4e8bc5f13e274573d0edb444822cd4afc90",
          "960a83b03e1a8a075002be97f7a92959a2b60c91184cabac06172d8821c32d6a"),
      new KatVector("all_zero", seedFilled(0x00),
          "708a446d675ee40027562aa2f853b9de0d9c876a08187133bb227c6d372aa1f2",
          "fb05b4c139c8fd08b9ae3ecf3da9cc375623aeef38b20ecdb5bbd8c7c02e7324"),
      new KatVector("all_ff", seedFilled(0xff),
          "4744e8d541a208ae10f62f5175c6eda7b695f3fd32b2145a38f8b16665a350b0",
          "e9adaa331dd9dc8d5881578e25bee75050105d7885bc7eac4e5e7f7fbba5612d"),
      new KatVector("all_aa", seedFilled(0xaa),
          "0894fd3551559bf8dbfd2ca828081c4f6998a16d65e63c595cf24178a2f952d3",
          "b2c4678087cba90219fb590bf618a88eb663db96c1ad9c572ff86d38e8d78e1f"),
      new KatVector("descending", seedDescending(),
          "d2191201811bf061040a012d1799dcdacb055e844d99164e0ddc45c71007d829",
          "dce0af30c51875158f3ea7c24b4ced289f49ce6123148994dc2a79548e678c2f"),
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
      FNDSA512 k = new FNDSA512(v.seed);
      assertEquals(v.label + ": pk length", FNDSA512.PUBLIC_KEY_LENGTH, k.getPublicKey().length);
      assertEquals(v.label + ": sk length", FNDSA512.PRIVATE_KEY_LENGTH, k.getPrivateKey().length);
      assertEquals(v.label + ": pk SHA-256 must match KAT vector",
          v.pkSha256, hex(sha256(k.getPublicKey())));
      assertEquals(v.label + ": sk SHA-256 must match KAT vector",
          v.skSha256, hex(sha256(k.getPrivateKey())));
    }
  }

  @Test
  public void allVectorsDeriveExpectedAddress() {
    for (KatVector v : VECTORS) {
      FNDSA512 k = new FNDSA512(v.seed);
      byte[] addr = k.getAddress();
      assertEquals(v.label + ": address length", 21, addr.length);

      byte[] viaRegistry = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, k.getPublicKey());
      assertArrayEquals(v.label + ": registry dispatch must match instance", addr, viaRegistry);
    }
  }

  @Test
  public void addressIsExactly0x41PlusKeccak256RightmostBytesOfPublicKey() {
    for (KatVector v : VECTORS) {
      FNDSA512 k = new FNDSA512(v.seed);
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
      FNDSA512 a = new FNDSA512(v.seed);
      FNDSA512 b = new FNDSA512(v.seed);
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
      addresses.add(hex(new FNDSA512(v.seed).getAddress()));
    }
    assertEquals("KAT pk digests must be pairwise distinct", VECTORS.length, pkDigests.size());
    assertEquals("KAT sk digests must be pairwise distinct", VECTORS.length, skDigests.size());
    assertEquals("KAT addresses must be pairwise distinct", VECTORS.length, addresses.size());
  }

  @Test
  public void signaturesFromKatKeysVerifyUnderTheirOwnPublicKey() {
    byte[][] messages = {
        new byte[0], "x".getBytes(), "tron-fn-dsa-kat-message".getBytes(), new byte[1024]};
    for (KatVector v : VECTORS) {
      FNDSA512 k = new FNDSA512(v.seed);
      for (byte[] msg : messages) {
        byte[] sig = k.sign(msg);
        assertTrue(v.label + ": signature must be non-empty", sig.length > 0);
        assertTrue(v.label + ": signature must respect 752-byte upper bound",
            sig.length <= FNDSA512.SIGNATURE_MAX_LENGTH);
        assertTrue(v.label + ": signature must verify under its own pk",
            FNDSA512.verify(k.getPublicKey(), msg, sig));
        assertTrue(v.label + ": registry verify must accept own signature",
            PQSchemeRegistry.verify(
                PQScheme.FN_DSA_512, k.getPublicKey(), msg, sig));
      }
    }
  }

  @Test
  public void signatureFromVectorAFailsUnderVectorBPublicKey() {
    byte[] msg = "tron-fn-dsa-kat-cross".getBytes();
    FNDSA512[] keys = new FNDSA512[VECTORS.length];
    byte[][] sigs = new byte[VECTORS.length][];
    for (int i = 0; i < VECTORS.length; i++) {
      keys[i] = new FNDSA512(VECTORS[i].seed);
      sigs[i] = keys[i].sign(msg);
    }
    for (int i = 0; i < VECTORS.length; i++) {
      for (int j = 0; j < VECTORS.length; j++) {
        if (i == j) {
          assertTrue(VECTORS[i].label + ": self-verify must succeed",
              FNDSA512.verify(keys[i].getPublicKey(), msg, sigs[i]));
        } else {
          assertFalse("signature from " + VECTORS[i].label
                  + " must NOT verify under " + VECTORS[j].label,
              FNDSA512.verify(keys[j].getPublicKey(), msg, sigs[i]));
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
      pks[i] = new FNDSA512(VECTORS[i].seed).getPublicKey();
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
