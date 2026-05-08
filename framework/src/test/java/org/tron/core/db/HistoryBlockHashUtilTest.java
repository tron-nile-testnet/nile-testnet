package org.tron.core.db;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.CodeCapsule;
import org.tron.core.capsule.ContractCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.vm.program.Storage;
import org.tron.protos.Protocol;
import org.tron.protos.contract.SmartContractOuterClass.SmartContract;

public class HistoryBlockHashUtilTest extends BaseTest {

  static {
    Args.setParam(new String[]{"--output-directory", dbPath()}, TestConstants.TEST_CONF);
  }

  @Before
  public void resetState() {
    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;
    chainBaseManager.getCodeStore().delete(addr);
    chainBaseManager.getContractStore().delete(addr);
    chainBaseManager.getAccountStore().delete(addr);
    chainBaseManager.getDynamicPropertiesStore().saveBlockHashHistoryInstalled(0L);
    // Storage.commit() translates a zero write into a row delete (see
    // Storage#commit), so writing ZERO to every slot the suite touches is
    // the cheapest way to clear leftover state between tests.
    Storage storage = new Storage(addr, chainBaseManager.getStorageRowStore());
    for (long slot : new long[]{0L, 99L, 499L, 776L}) {
      storage.put(new DataWord(slot), DataWord.ZERO());
    }
    storage.commit();
  }

  private DataWord readSlot(long slot) {
    Storage storage = new Storage(
        HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS,
        chainBaseManager.getStorageRowStore());
    return storage.getValue(new DataWord(slot));
  }

  @Test
  public void deployCreatesCodeContractAndAccount() {
    HistoryBlockHashUtil.deploy(dbManager);

    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;

    assertTrue(chainBaseManager.getCodeStore().has(addr));
    CodeCapsule code = chainBaseManager.getCodeStore().get(addr);
    assertNotNull(code);
    assertArrayEquals(HistoryBlockHashUtil.HISTORY_STORAGE_CODE, code.getData());

    ContractCapsule contract = chainBaseManager.getContractStore().get(addr);
    assertNotNull(contract);
    SmartContract proto = contract.getInstance();
    assertEquals(HistoryBlockHashUtil.HISTORY_STORAGE_NAME, proto.getName());
    assertArrayEquals(addr, proto.getContractAddress().toByteArray());
    assertEquals("version must be 0", 0, proto.getVersion());
    assertEquals(100L, proto.getConsumeUserResourcePercent());
    assertArrayEquals("originAddress must be the EIP-2935 system caller",
        HistoryBlockHashUtil.HISTORY_DEPLOYER_ADDRESS,
        proto.getOriginAddress().toByteArray());

    assertTrue(chainBaseManager.getAccountStore().has(addr));
    AccountCapsule account = chainBaseManager.getAccountStore().get(addr);
    assertEquals(HistoryBlockHashUtil.HISTORY_STORAGE_NAME,
        account.getAccountName().toStringUtf8());
    assertEquals(Protocol.AccountType.Contract, account.getType());
    assertTrue("install marker must flip after a successful deploy",
        chainBaseManager.getDynamicPropertiesStore().isBlockHashHistoryInstalled());
  }

  @Test
  public void writeStoresParentHashAtCorrectSlot() {
    HistoryBlockHashUtil.deploy(dbManager);

    long blockNum = 100L;
    byte[] parentHash = new byte[32];
    Arrays.fill(parentHash, (byte) 0xab);

    BlockCapsule block = new BlockCapsule(
        blockNum,
        Sha256Hash.wrap(parentHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));

    HistoryBlockHashUtil.write(dbManager, block);

    DataWord readBack = readSlot(99L);
    assertNotNull(readBack);
    assertArrayEquals(parentHash, readBack.getData());
  }

  @Test
  public void writeUsesRingBufferModulo() {
    HistoryBlockHashUtil.deploy(dbManager);

    // (8192 - 1) % 8191 = 0
    long blockNum = 8192L;
    byte[] parentHash = new byte[32];
    Arrays.fill(parentHash, (byte) 0xcd);

    BlockCapsule block = new BlockCapsule(
        blockNum,
        Sha256Hash.wrap(parentHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));

    HistoryBlockHashUtil.write(dbManager, block);

    DataWord readBack = readSlot(0L);
    assertNotNull(readBack);
    assertArrayEquals(parentHash, readBack.getData());
  }

  @Test
  public void beforeDeployNothingIsWritten() {
    assertFalse(chainBaseManager.getCodeStore()
        .has(HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS));
    assertFalse(chainBaseManager.getContractStore()
        .has(HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS));
    assertFalse(chainBaseManager.getAccountStore()
        .has(HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS));
  }

  /**
   * If {@code deploy()} never ran (e.g. flag flipped without the deploy path),
   * {@code write()} must not mutate {@code StorageRowStore} at the canonical
   * address — otherwise the next call to {@code deploy()} would land on top of
   * partially-written state.
   */
  @Test
  public void writeIsNoOpBeforeDeploy() {
    long blockNum = 100L;
    byte[] parentHash = new byte[32];
    Arrays.fill(parentHash, (byte) 0xab);
    BlockCapsule block = new BlockCapsule(
        blockNum,
        Sha256Hash.wrap(parentHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));

    HistoryBlockHashUtil.write(dbManager, block);

    assertNull("write() must be a no-op without an installed BlockHashHistory",
        readSlot(99L));
  }

  /**
   * Defense-in-depth: when foreign bytecode sits at the canonical address,
   * {@code deploy()} skips and the install marker stays 0, so {@code write()}
   * must refuse to overwrite that contract's storage every block. Triggering
   * the collision in practice requires a SHA-3 pre-image of the address, but
   * the marker check is a single cached store hit.
   */
  @Test
  public void writeIsNoOpOnForeignCode() {
    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;
    byte[] foreignCode = Hex.decode("60016002");
    chainBaseManager.getCodeStore().put(addr, new CodeCapsule(foreignCode));

    HistoryBlockHashUtil.deploy(dbManager);

    assertFalse("install marker must stay 0 when deploy skipped",
        chainBaseManager.getDynamicPropertiesStore().isBlockHashHistoryInstalled());

    long blockNum = 100L;
    byte[] parentHash = new byte[32];
    Arrays.fill(parentHash, (byte) 0xcd);
    BlockCapsule block = new BlockCapsule(
        blockNum,
        Sha256Hash.wrap(parentHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));

    HistoryBlockHashUtil.write(dbManager, block);

    assertNull("write() must not overwrite a foreign contract's storage",
        readSlot(99L));
    assertArrayEquals("foreign code must remain intact",
        foreignCode, chainBaseManager.getCodeStore().get(addr).getData());
  }
}
