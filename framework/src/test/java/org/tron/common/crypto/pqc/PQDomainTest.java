package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

public class PQDomainTest {

  private static final byte[] TARGET = Hex.decode(
      "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd");

  @Test
  public void everyDomainBindsTheSameTargetDifferently() {
    Set<String> bound = new HashSet<>();
    for (PQDomain domain : PQDomain.values()) {
      byte[] digest = domain.bind(TARGET);
      assertEquals(32, digest.length);
      assertFalse(Hex.toHexString(digest).equals(Hex.toHexString(TARGET)));
      bound.add(Hex.toHexString(digest));
    }
    assertEquals(PQDomain.values().length, bound.size());
  }

  @Test
  public void bindingIsDeterministic() {
    assertArrayEquals(PQDomain.TRANSACTION.bind(TARGET), PQDomain.TRANSACTION.bind(TARGET));
  }

  @Test
  public void messageSignatureIsRejectedAsTransactionSignature() {
    for (PQScheme scheme : new PQScheme[] {PQScheme.FN_DSA_512, PQScheme.ML_DSA_44}) {
      PQSignature key = PQSchemeRegistry.fromSeed(scheme,
          new byte[PQSchemeRegistry.getSeedLength(scheme)]);
      byte[] messageSig = PQSchemeRegistry.sign(scheme, key.getPrivateKey(),
          PQDomain.MESSAGE, TARGET);
      assertTrue(PQSchemeRegistry.verify(scheme, key.getPublicKey(),
          PQDomain.MESSAGE, TARGET, messageSig));
      for (PQDomain other : new PQDomain[] {PQDomain.TRANSACTION, PQDomain.BLOCK,
          PQDomain.RELAY}) {
        assertFalse(scheme + " " + other, PQSchemeRegistry.verify(scheme, key.getPublicKey(),
            other, TARGET, messageSig));
      }
    }
  }

  @Test
  public void rawHashSignatureIsRejectedInEveryDomain() {
    for (PQScheme scheme : new PQScheme[] {PQScheme.FN_DSA_512, PQScheme.ML_DSA_44}) {
      PQSignature key = PQSchemeRegistry.fromSeed(scheme,
          new byte[PQSchemeRegistry.getSeedLength(scheme)]);
      byte[] rawSig = key.sign(TARGET);
      for (PQDomain domain : PQDomain.values()) {
        assertFalse(scheme + " " + domain, PQSchemeRegistry.verify(scheme, key.getPublicKey(),
            domain, TARGET, rawSig));
      }
    }
  }
}
