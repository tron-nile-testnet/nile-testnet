package org.tron.core.consensus;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import org.junit.Test;
import org.tron.consensus.base.Param;
import org.tron.consensus.base.Param.Miner;
import org.tron.protos.Protocol.PQScheme;

/**
 * Covers the post-quantum branches of {@link Param.Miner} and its nested
 * {@code PQMiner}. The ECDSA miner path is already exercised indirectly by the
 * consensus/DPoS tests; these cases pin the PQ-specific constructor, the
 * scheme-agnostic address accessors, and the defensive key-byte copying.
 */
public class ParamPqMinerTest {

  private static final ByteString PQ_KEY_ADDR = ByteString.copyFromUtf8("pq-key-address");
  private static final ByteString PQ_WITNESS_ADDR = ByteString.copyFromUtf8("pq-witness-address");
  private static final ByteString ECDSA_KEY_ADDR = ByteString.copyFromUtf8("ecdsa-key-address");
  private static final ByteString ECDSA_WITNESS_ADDR =
      ByteString.copyFromUtf8("ecdsa-witness-address");

  private static Miner newPqMiner(byte[] priv, byte[] pub) {
    return Param.getInstance().new Miner(
        PQScheme.FN_DSA_512, priv, pub, PQ_KEY_ADDR, PQ_WITNESS_ADDR);
  }

  private static Miner newEcdsaMiner() {
    return Param.getInstance().new Miner(new byte[] {1, 2, 3}, ECDSA_KEY_ADDR, ECDSA_WITNESS_ADDR);
  }

  @Test
  public void getInstanceReturnsSingleton() {
    assertSame(Param.getInstance(), Param.getInstance());
  }

  @Test
  public void pqMinerIsFlaggedAsPq() {
    Miner miner = newPqMiner(new byte[] {4, 5}, new byte[] {6, 7});
    assertTrue(miner.isPq());
    assertNotNull(miner.getPq());
  }

  @Test
  public void ecdsaMinerIsNotPq() {
    Miner miner = newEcdsaMiner();
    assertFalse(miner.isPq());
    assertNull(miner.getPq());
  }

  @Test
  public void pqMinerExposesSchemeAndAddresses() {
    Miner miner = newPqMiner(new byte[] {8}, new byte[] {9});
    assertEquals(PQScheme.FN_DSA_512, miner.getPq().getScheme());
    assertEquals(PQ_KEY_ADDR, miner.getPq().getPrivateKeyAddress());
    assertEquals(PQ_WITNESS_ADDR, miner.getPq().getWitnessAddress());
  }

  @Test
  public void effectiveAddressesRouteThroughPqIdentity() {
    Miner miner = newPqMiner(new byte[] {10}, new byte[] {11});
    assertEquals(PQ_WITNESS_ADDR, miner.getEffectiveWitnessAddress());
    assertEquals(PQ_KEY_ADDR, miner.getEffectivePrivateKeyAddress());
  }

  @Test
  public void effectiveAddressesRouteThroughEcdsaFields() {
    Miner miner = newEcdsaMiner();
    assertEquals(ECDSA_WITNESS_ADDR, miner.getEffectiveWitnessAddress());
    assertEquals(ECDSA_KEY_ADDR, miner.getEffectivePrivateKeyAddress());
  }

  @Test
  public void pqMinerToleratesNullKeyMaterial() {
    Miner miner = newPqMiner(null, null);
    assertNull(miner.getPq().getPrivateKey());
    assertNull(miner.getPq().getPublicKey());
  }
}
