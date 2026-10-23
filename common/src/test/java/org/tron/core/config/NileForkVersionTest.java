package org.tron.core.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.tron.core.config.Parameter.ChainConstant;
import org.tron.core.config.Parameter.ForkBlockVersionEnum;

public class NileForkVersionTest {

  @Test
  public void historicalForkNumbersRemainStable() {
    assertSame(ForkBlockVersionEnum.VERSION_4_8_1,
        ForkBlockVersionEnum.getForkBlockVersionEnum(33));
    assertSame(ForkBlockVersionEnum.VERSION_4_8_0_1,
        ForkBlockVersionEnum.getForkBlockVersionEnum(34));
    assertSame(ForkBlockVersionEnum.VERSION_4_8_2_PQ1,
        ForkBlockVersionEnum.getForkBlockVersionEnum(37));
    assertSame(ForkBlockVersionEnum.VERSION_4_8_2_2_PQ1,
        ForkBlockVersionEnum.getForkBlockVersionEnum(38));
    assertSame(ForkBlockVersionEnum.VERSION_4_8_2_3_PQ1,
        ForkBlockVersionEnum.getForkBlockVersionEnum(39));
  }

  @Test
  public void newForkUsesNextNileBlockVersion() {
    ForkBlockVersionEnum fork = ForkBlockVersionEnum.valueOf("VERSION_4_8_2_4_PQ1");
    assertEquals(40, fork.getValue());
    assertEquals(40, ChainConstant.BLOCK_VERSION);
    assertSame(fork, ForkBlockVersionEnum.getForkBlockVersionEnum(ChainConstant.BLOCK_VERSION));
    assertEquals(ForkBlockVersionEnum.VERSION_4_8_2_3_PQ1.getHardForkTime(), fork.getHardForkTime());
    assertEquals(70, fork.getHardForkRate());
  }

  @Test
  public void forkNumbersAreUniqueAndIncreasing() {
    Set<Integer> versions = new HashSet<>();
    int previous = 0;
    for (ForkBlockVersionEnum fork : ForkBlockVersionEnum.values()) {
      assertTrue("Duplicate fork number: " + fork.getValue(), versions.add(fork.getValue()));
      assertTrue("Fork order changed: " + fork.name(), fork.getValue() > previous);
      previous = fork.getValue();
    }
    assertEquals(previous, ChainConstant.BLOCK_VERSION);
  }
}
