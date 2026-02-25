package org.tron.common.runtime.vm;

import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.utils.ByteUtil;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.config.ConfigLoader;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.program.Program;

@Slf4j
public class AllowTvmOsakaTest extends VMTestBase {

  @Test
  public void testEIP7823() {
    ConfigLoader.disable = true;
    VMConfig.initAllowTvmOsaka(1);

    byte[] baseLen = new byte[32];
    byte[] expLen = new byte[32];
    byte[] modLen = new byte[32];

    PrecompiledContracts.PrecompiledContract modExp = new PrecompiledContracts.ModExp();

    // Valid lens
    try {
      modExp.execute(ByteUtil.merge(baseLen, expLen, modLen));
    } catch (Exception e) {
      Assert.fail();
    }

    // Invalid lens
    try {
      baseLen[0] = 0x01;
      modExp.execute(ByteUtil.merge(baseLen, expLen, modLen));
    } catch (Exception e) {
      Assert.assertTrue(e instanceof Program.PrecompiledContractException);
      return;
    } finally {
      VMConfig.initAllowTvmOsaka(0);
      ConfigLoader.disable = false;
    }

    Assert.fail();
  }
}
