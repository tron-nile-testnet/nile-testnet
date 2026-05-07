package org.tron.common.runtime.vm;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.config.ConfigLoader;
import org.tron.core.vm.config.VMConfig;

@Slf4j
public class AllowTvmOsakaTest extends VMTestBase {

  private static final PrecompiledContracts.PrecompiledContract modExp =
      new PrecompiledContracts.ModExp();

  private static byte[] toLenBytes(int value) {
    byte[] b = new byte[32];
    b[28] = (byte) ((value >> 24) & 0xFF);
    b[29] = (byte) ((value >> 16) & 0xFF);
    b[30] = (byte) ((value >> 8) & 0xFF);
    b[31] = (byte) (value & 0xFF);
    return b;
  }

  @Test
  public void testEIP7823() {
    ConfigLoader.disable = true;
    VMConfig.initAllowTvmOsaka(1);

    try {
      // all-zero lengths: should succeed
      Pair<Boolean, byte[]> result = modExp.execute(
          ByteUtil.merge(toLenBytes(0), toLenBytes(0), toLenBytes(0)));
      Assert.assertTrue(result.getLeft());

      // baseLen == 1024: boundary, should succeed
      result = modExp.execute(
          ByteUtil.merge(toLenBytes(1024), toLenBytes(0), toLenBytes(0)));
      Assert.assertTrue(result.getLeft());

      // baseLen == 1025: just over the limit, should fail
      result = modExp.execute(
          ByteUtil.merge(toLenBytes(1025), toLenBytes(0), toLenBytes(0)));
      Assert.assertFalse(result.getLeft());

      // oversized expLen only: should fail
      result = modExp.execute(
          ByteUtil.merge(toLenBytes(0), toLenBytes(1025), toLenBytes(0)));
      Assert.assertFalse(result.getLeft());

      // oversized modLen only: should fail
      result = modExp.execute(
          ByteUtil.merge(toLenBytes(0), toLenBytes(0), toLenBytes(1025)));
      Assert.assertFalse(result.getLeft());
    } finally {
      VMConfig.initAllowTvmOsaka(0);
      ConfigLoader.disable = false;
    }
  }

  @Test
  public void testEIP7823DisabledShouldPass() {
    ConfigLoader.disable = true;
    VMConfig.initAllowTvmOsaka(0);

    try {
      // all limits exceeded while osaka is disabled: should succeed (no restriction)
      Pair<Boolean, byte[]> result = modExp.execute(
          ByteUtil.merge(toLenBytes(2048), toLenBytes(2048), toLenBytes(2048)));
      Assert.assertTrue(result.getLeft());
    } finally {
      ConfigLoader.disable = false;
    }
  }

  // P256VERIFY address per TIP-7951 / EIP-7951.
  private static final DataWord P256_VERIFY_ADDR =
      new DataWord(
          "0000000000000000000000000000000000000000000000000000000000000100");

  // First entry from the geth conformance vectors — known-valid signature.
  private static final String VALID_P256_INPUT =
      "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4d"
          + "a73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac"
          + "36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d60"
          + "4aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff3"
          + "7618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e";
  private static final byte[] EXPECTED_VALID_OUTPUT = ByteUtil.merge(
      new byte[31], new byte[]{0x01});

  @Test
  public void testP256VerifyEnabled() {
    ConfigLoader.disable = true;
    VMConfig.initAllowTvmOsaka(1);
    try {
      PrecompiledContracts.PrecompiledContract contract =
          PrecompiledContracts.getContractForAddress(P256_VERIFY_ADDR);
      Assert.assertNotNull("P256VERIFY must be registered when osaka is on",
          contract);
      Assert.assertTrue(contract instanceof PrecompiledContracts.P256Verify);

      Pair<Boolean, byte[]> result = contract.execute(
          ByteArray.fromHexString(VALID_P256_INPUT));
      Assert.assertTrue(result.getLeft());
      Assert.assertArrayEquals(EXPECTED_VALID_OUTPUT, result.getRight());
      Assert.assertEquals(6900L, contract.getEnergyForData(
          ByteArray.fromHexString(VALID_P256_INPUT)));
    } finally {
      VMConfig.initAllowTvmOsaka(0);
      ConfigLoader.disable = false;
    }
  }

  @Test
  public void testP256VerifyDisabledShouldReturnNull() {
    ConfigLoader.disable = true;
    VMConfig.initAllowTvmOsaka(0);
    try {
      Assert.assertNull(
          "P256VERIFY must NOT be registered when osaka is off",
          PrecompiledContracts.getContractForAddress(P256_VERIFY_ADDR));
    } finally {
      ConfigLoader.disable = false;
    }
  }
}
