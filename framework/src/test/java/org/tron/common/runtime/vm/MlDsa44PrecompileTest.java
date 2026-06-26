package org.tron.common.runtime.vm;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;

/**
 * Unit tests for the ML-DSA-44 verify precompile (FIPS 204 / Dilithium-2).
 * Address 0x02000018: standard 1312-byte FIPS public key layout.
 */
public class MlDsa44PrecompileTest {

  private static final DataWord MLDSA_DRAFT_ADDR = new DataWord(
      "0000000000000000000000000000000000000000000000000000000002000018");

  private static final byte[] MESSAGE_HASH = new byte[32];

  static {
    for (int i = 0; i < 32; i++) {
      MESSAGE_HASH[i] = (byte) i;
    }
  }

  @Before
  public void enableProposal() {
    VMConfig.initAllowMlDsa44(1L);
  }

  @After
  public void disableProposal() {
    VMConfig.initAllowMlDsa44(0L);
  }

  @Test
  public void switchOff_returnsNull() {
    VMConfig.initAllowMlDsa44(0L);
    Assert.assertNull(PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR));
  }

  @Test
  public void draftAddress18StillReturnsContract() {
    Assert.assertNotNull(PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR));
  }

  @Test
  public void draftAddress18ValidSignature_returnsOne() {
    MLDSA44 key = new MLDSA44();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] input = buildInput(MESSAGE_HASH, sig, key.getPublicKey());

    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR);
    Pair<Boolean, byte[]> result = pc.execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ONE().getData(), result.getRight());
    Assert.assertEquals(3000, pc.getEnergyForData(input));
  }

  @Test
  public void draftAddress18TamperedMessage_returnsZero() {
    MLDSA44 key = new MLDSA44();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] tampered = MESSAGE_HASH.clone();
    tampered[0] ^= 0x01;
    byte[] input = buildInput(tampered, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void draftAddress18TamperedSignature_returnsZero() {
    MLDSA44 key = new MLDSA44();
    byte[] sig = key.sign(MESSAGE_HASH);
    sig[0] ^= 0x01;
    byte[] input = buildInput(MESSAGE_HASH, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void draftAddress18WrongPublicKey_returnsZero() {
    MLDSA44 signer = new MLDSA44();
    MLDSA44 other = new MLDSA44();
    byte[] sig = signer.sign(MESSAGE_HASH);
    byte[] input = buildInput(MESSAGE_HASH, sig, other.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void draftAddress18NullInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR).execute(null);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void draftAddress18ShortInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR).execute(new byte[100]);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void draftAddress18WrongLengthInput_returnsZero() {
    // ML-DSA-44 input is fixed-length 3764B; any other length must be rejected.
    int expected = 32 + MLDSA44.SIGNATURE_LENGTH + MLDSA44.PUBLIC_KEY_LENGTH;
    byte[] oneByteShort = new byte[expected - 1];
    Pair<Boolean, byte[]> r1 =
        PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR).execute(oneByteShort);
    Assert.assertTrue(r1.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), r1.getRight());
  }

  @Test
  public void draftAddress18TrailingBytes_returnsZero() {
    // Strict equality: even one extra trailing byte must be rejected.
    MLDSA44 key = new MLDSA44();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] valid = buildInput(MESSAGE_HASH, sig, key.getPublicKey());
    byte[] padded = new byte[valid.length + 1];
    System.arraycopy(valid, 0, padded, 0, valid.length);

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(MLDSA_DRAFT_ADDR).execute(padded);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  /** Encodes input as [msg 32B | sig 2420B | pk 1312B]. */
  private static byte[] buildInput(byte[] msg, byte[] sig, byte[] pk) {
    int total = 32 + sig.length + pk.length;
    byte[] out = new byte[total];
    System.arraycopy(msg, 0, out, 0, 32);
    System.arraycopy(sig, 0, out, 32, sig.length);
    System.arraycopy(pk, 0, out, 32 + sig.length, pk.length);
    return out;
  }
}
