package org.tron.core.config.args;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import org.junit.Test;
import org.tron.core.exception.TronError;

public class LocalWitnessConfigTest {

  private static Config withRef(String hocon) {
    return ConfigFactory.parseString(hocon).withFallback(ConfigFactory.defaultReference());
  }

  private static Config withRef() {
    return ConfigFactory.defaultReference();
  }

  @Test
  public void testDefaults() {
    Config empty = withRef();
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(empty);
    assertTrue(lw.getPrivateKeys().isEmpty());
    assertNull(lw.getAccountAddress());
    assertNull(lw.getPqAccountAddress());
    assertTrue(lw.getKeystores().isEmpty());
    assertTrue(lw.getPqKeyFiles().isEmpty());
  }

  @Test
  public void testWithPqAccountAddress() {
    Config config = withRef("localPqWitness.accountAddress = \"TPqAddr\"");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertNull(lw.getAccountAddress());
    assertEquals("TPqAddr", lw.getPqAccountAddress());
  }

  @Test
  public void testEcdsaAndPqAccountAddressCanCoexist() {
    Config config = withRef(
        "localWitnessAccountAddress = \"TEcdsaAddr\"\n"
            + "localPqWitness.accountAddress = \"TPqAddr\"");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertEquals("TEcdsaAddr", lw.getAccountAddress());
    assertEquals("TPqAddr", lw.getPqAccountAddress());
  }

  @Test
  public void testWithPrivateKeys() {
    Config config = withRef(
        "localwitness = [\"key1\", \"key2\"]\n"
            + "localWitnessAccountAddress = \"TAddr123\"");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertEquals(2, lw.getPrivateKeys().size());
    assertEquals("key1", lw.getPrivateKeys().get(0));
    assertEquals("TAddr123", lw.getAccountAddress());
  }

  @Test
  public void testWithKeystores() {
    Config config = withRef(
        "localwitnesskeystore = [\"/path/to/keystore1\"]");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertEquals(1, lw.getKeystores().size());
  }

  @Test
  public void testWithPqKeyFiles() {
    Config config = withRef(
        "localPqWitness.keys = [ \"keys/sr1.json\", \"keys/sr2.json\" ]");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertEquals(2, lw.getPqKeyFiles().size());
    assertEquals("keys/sr1.json", lw.getPqKeyFiles().get(0));
    assertEquals("keys/sr2.json", lw.getPqKeyFiles().get(1));
    // Scheme validity and key material (file contents, hex length, public-key
    // recovery) are left to WitnessInitializer; fromConfig only checks that the
    // paths are non-blank.
  }

  @Test
  public void testBlankPqKeyFilePathRejected() {
    Config config = withRef("localPqWitness.keys = [ \"\" ]");
    TronError err = assertThrows(TronError.class,
        () -> LocalWitnessConfig.fromConfig(config));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("non-blank JSON key file path"));
  }
}
