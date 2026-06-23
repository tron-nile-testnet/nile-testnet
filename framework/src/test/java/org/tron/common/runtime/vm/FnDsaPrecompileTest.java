package org.tron.common.runtime.vm;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;

/**
 * Unit tests for the FN-DSA / Falcon-512 (0x02000016) verify precompile (EIP-8052 / TRON extension).
 * Input layout (fixed-length): [msg 32B | sig 666B (zero-padded) | pk 896B] = 1594B total.
 * The 666-byte sig slot holds the EIP-8052 <em>headerless</em> body (salt ‖ s2): BC's
 * leading 0x39 header is stripped on the way in and re-inserted by the precompile.
 * Stateless — no chain DB.
 */
public class FnDsaPrecompileTest {

  private static final DataWord FNDSA_ADDR = new DataWord(
      "0000000000000000000000000000000000000000000000000000000002000016");

  private static final int INPUT_LEN =
      32 + FNDSA512.SIGNATURE_MAX_LENGTH - 1 + FNDSA512.PUBLIC_KEY_LENGTH;

  private static final byte[] MESSAGE_HASH = new byte[32];

  static {
    for (int i = 0; i < 32; i++) {
      MESSAGE_HASH[i] = (byte) i;
    }
  }

  @Before
  public void enableProposal() {
    VMConfig.initAllowFnDsa512(1L);
  }

  @After
  public void disableProposal() {
    VMConfig.initAllowFnDsa512(0L);
  }

  @Test
  public void switchOff_returnsNull() {
    VMConfig.initAllowFnDsa512(0L);
    Assert.assertNull(PrecompiledContracts.getContractForAddress(FNDSA_ADDR));
  }

  @Test
  public void switchOn_returnsContract() {
    Assert.assertNotNull(PrecompiledContracts.getContractForAddress(FNDSA_ADDR));
  }

  @Test
  public void validSignature_returnsOne() {
    FNDSA512 key = new FNDSA512();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] input = buildInput(MESSAGE_HASH, sig, key.getPublicKey());

    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(FNDSA_ADDR);
    Pair<Boolean, byte[]> result = pc.execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ONE().getData(), result.getRight());
    Assert.assertEquals(170, pc.getEnergyForData(input));
  }

  @Test
  public void tamperedMessage_returnsZero() {
    FNDSA512 key = new FNDSA512();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] tampered = MESSAGE_HASH.clone();
    tampered[0] ^= 0x01;
    byte[] input = buildInput(tampered, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void tamperedSignature_returnsZero() {
    FNDSA512 key = new FNDSA512();
    byte[] sig = key.sign(MESSAGE_HASH);
    // sig[0] is the 0x39 header, stripped by buildInput; flip a salt byte instead.
    sig[1] ^= 0x01;
    byte[] input = buildInput(MESSAGE_HASH, sig, key.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void wrongPublicKey_returnsZero() {
    FNDSA512 signer = new FNDSA512();
    FNDSA512 other = new FNDSA512();
    byte[] sig = signer.sign(MESSAGE_HASH);
    byte[] input = buildInput(MESSAGE_HASH, sig, other.getPublicKey());

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void nullInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(null);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void shortInput_returnsZero() {
    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(new byte[INPUT_LEN - 1]);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void trailingBytes_returnsZero() {
    // Strict equality (matches 0x100 P256Verify / EIP-7951): appending even one byte
    // to an otherwise-valid input must be rejected to prevent non-canonical encodings.
    FNDSA512 key = new FNDSA512();
    byte[] sig = key.sign(MESSAGE_HASH);
    byte[] valid = buildInput(MESSAGE_HASH, sig, key.getPublicKey());
    byte[] padded = new byte[valid.length + 1];
    System.arraycopy(valid, 0, padded, 0, valid.length);

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(padded);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void emptySigSlot_returnsZero() {
    // All-zero sig slot -> recovered length 0, below the headerless minimum.
    FNDSA512 key = new FNDSA512();
    byte[] input = new byte[INPUT_LEN];
    System.arraycopy(MESSAGE_HASH, 0, input, 0, 32);
    System.arraycopy(key.getPublicKey(), 0, input,
        32 + FNDSA512.SIGNATURE_MAX_LENGTH - 1, FNDSA512.PUBLIC_KEY_LENGTH);

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  @Test
  public void sigSlotShorterThanMin_returnsZero() {
    // Recovered headerless body length 32 (last non-zero at offset 31 of sig slot) is
    // below the headerless minimum (SIGNATURE_MIN_LENGTH - 1 = 616) — too short to
    // contain a syntactically well-formed compressed_s2 body.
    FNDSA512 key = new FNDSA512();
    byte[] input = new byte[INPUT_LEN];
    System.arraycopy(MESSAGE_HASH, 0, input, 0, 32);
    input[32 + 31] = (byte) 0xFF;
    System.arraycopy(key.getPublicKey(), 0, input,
        32 + FNDSA512.SIGNATURE_MAX_LENGTH - 1, FNDSA512.PUBLIC_KEY_LENGTH);

    Pair<Boolean, byte[]> result =
        PrecompiledContracts.getContractForAddress(FNDSA_ADDR).execute(input);

    Assert.assertTrue(result.getLeft());
    Assert.assertArrayEquals(DataWord.ZERO().getData(), result.getRight());
  }

  /**
   * Encodes input as [msg 32B | sig 666B (zero-padded) | pk 896B]. The caller passes
   * a BC-native headered signature ({@code 0x39 ‖ salt ‖ s2}); this strips the leading
   * 0x39 header to produce the EIP-8052 headerless body the precompile expects, then
   * zero-pads the tail to fill the 666-byte slot.
   */
  private static byte[] buildInput(byte[] msg, byte[] sig, byte[] pk) {
    byte[] out = new byte[INPUT_LEN];
    System.arraycopy(msg, 0, out, 0, 32);
    System.arraycopy(sig, 1, out, 32, sig.length - 1);
    System.arraycopy(pk, 0, out, 32 + FNDSA512.SIGNATURE_MAX_LENGTH - 1, pk.length);
    return out;
  }
}
