package org.tron.core.db;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import java.util.Arrays;
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
import org.tron.core.store.DynamicPropertiesStore;
import org.tron.core.store.StoreFactory;
import org.tron.core.vm.program.Storage;
import org.tron.core.vm.repository.RepositoryImpl;
import org.tron.protos.Protocol;
import org.tron.protos.contract.SmartContractOuterClass.SmartContract;

/**
 * TIP-2935 end-to-end: activation deploys the contract, subsequent blocks
 * populate the ring buffer via the pre-tx hook, and the VM repository reads
 * back written hashes through the same {@code Storage.compose()} layer that
 * production {@code SLOAD} uses.
 */
public class HistoryBlockHashIntegrationTest extends BaseTest {

  static {
    Args.setParam(new String[]{"--output-directory", dbPath()}, TestConstants.TEST_CONF);
  }

  @Before
  public void resetState() {
    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;
    chainBaseManager.getDynamicPropertiesStore().saveAllowTvmPrague(0L);
    chainBaseManager.getDynamicPropertiesStore().saveBlockHashHistoryInstalled(0L);
    chainBaseManager.getCodeStore().delete(addr);
    chainBaseManager.getContractStore().delete(addr);
    chainBaseManager.getAccountStore().delete(addr);
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
  public void activationDeploysContractAndFlagIsSet() {
    DynamicPropertiesStore dps = chainBaseManager.getDynamicPropertiesStore();
    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;

    assertEquals(0L, dps.getAllowTvmPrague());
    assertFalse(chainBaseManager.getCodeStore().has(addr));

    dps.saveAllowTvmPrague(1L);
    HistoryBlockHashUtil.deploy(dbManager);

    assertEquals(1L, dps.getAllowTvmPrague());
    assertTrue(chainBaseManager.getCodeStore().has(addr));
    CodeCapsule code = chainBaseManager.getCodeStore().get(addr);
    assertNotNull(code);
    assertArrayEquals(HistoryBlockHashUtil.HISTORY_STORAGE_CODE, code.getData());
  }

  @Test
  public void writeAfterActivationFillsStorageSlot() {
    chainBaseManager.getDynamicPropertiesStore().saveAllowTvmPrague(1L);
    HistoryBlockHashUtil.deploy(dbManager);

    long blockNum = 500L;
    byte[] parentHash = new byte[32];
    Arrays.fill(parentHash, (byte) 0x5a);
    BlockCapsule block = new BlockCapsule(
        blockNum,
        Sha256Hash.wrap(parentHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));

    HistoryBlockHashUtil.write(dbManager, block);

    DataWord readBack = readSlot(499L);
    assertNotNull(readBack);
    assertArrayEquals(parentHash, readBack.getData());
  }

  @Test
  public void vmRepositoryReadsBackWrittenHash() {
    // Full round-trip: direct-write through Storage -> VM Repository -> getStorageValue.
    // Proves write and read go through the same Storage.compose() layer.
    chainBaseManager.getDynamicPropertiesStore().saveAllowTvmPrague(1L);
    HistoryBlockHashUtil.deploy(dbManager);

    long blockNum = 777L;
    byte[] parentHash = new byte[32];
    Arrays.fill(parentHash, (byte) 0x77);
    BlockCapsule block = new BlockCapsule(
        blockNum,
        Sha256Hash.wrap(parentHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));
    HistoryBlockHashUtil.write(dbManager, block);

    RepositoryImpl repo = RepositoryImpl.createRoot(StoreFactory.getInstance());

    // (777 - 1) % 8191 = 776
    DataWord slotKey = new DataWord(776L);
    DataWord readBack = repo.getStorageValue(
        HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS, slotKey);

    assertNotNull("VM repository failed to read stored hash", readBack);
    assertArrayEquals("VM read-back != direct-written hash",
        parentHash, readBack.getData());
  }

  @Test
  public void noWriteBeforeActivation() {
    assertEquals(0L,
        chainBaseManager.getDynamicPropertiesStore().getAllowTvmPrague());
    assertFalse(chainBaseManager.getDynamicPropertiesStore()
        .isBlockHashHistoryInstalled());

    long blockNum = 100L;
    byte[] parentHash = new byte[32];
    Arrays.fill(parentHash, (byte) 0xff);
    BlockCapsule block = new BlockCapsule(
        blockNum,
        Sha256Hash.wrap(parentHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));

    // Manager calls write() unconditionally; the install marker stays 0
    // before activation, so write() must early-return.
    HistoryBlockHashUtil.write(dbManager, block);

    assertNull(readSlot(99L));
  }

  /**
   * Block 1 is the first block to go through {@code applyBlock -> processBlock}.
   * Its parent is the genesis block, so slot 0 must hold the genesis block hash.
   */
  @Test
  public void writeForBlock1StoresGenesisHashAtSlot0() {
    chainBaseManager.getDynamicPropertiesStore().saveAllowTvmPrague(1L);
    HistoryBlockHashUtil.deploy(dbManager);

    byte[] genesisHash = new byte[32];
    Arrays.fill(genesisHash, (byte) 0x01);
    BlockCapsule block1 = new BlockCapsule(
        1L,
        Sha256Hash.wrap(genesisHash),
        System.currentTimeMillis(),
        ByteString.copyFrom(new byte[21]));

    HistoryBlockHashUtil.write(dbManager, block1);

    DataWord readBack = readSlot(0L);
    assertNotNull(readBack);
    assertArrayEquals(genesisHash, readBack.getData());
  }

  /**
   * Genesis never goes through {@code applyBlock}, but the guard keeps
   * {@code (0 - 1) % 8191 = -1} from ever corrupting a slot if it ever did.
   */
  @Test
  public void writeIsNoOpForGenesisBlock() {
    chainBaseManager.getDynamicPropertiesStore().saveAllowTvmPrague(1L);
    HistoryBlockHashUtil.deploy(dbManager);

    byte[] zeroHash = new byte[32];
    BlockCapsule genesis = new BlockCapsule(
        0L,
        Sha256Hash.wrap(zeroHash),
        0L,
        ByteString.copyFrom(new byte[21]));

    HistoryBlockHashUtil.write(dbManager, genesis);

    assertNull(readSlot(0L));
  }

  /**
   * Collision guard: if foreign bytecode already sits at the canonical address
   * (theoretically impossible short of a hash pre-image), activation must skip
   * the deploy entirely — leaving the foreign code intact and writing nothing
   * to ContractStore / AccountStore — rather than silently merging into a
   * broken contract. Same expectation applies to foreign contract metadata.
   */
  @Test
  public void deploySkipsWhenForeignBytecodePresent() {
    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;
    byte[] foreignCode = new byte[]{0x60, 0x00};
    chainBaseManager.getCodeStore().put(addr, new CodeCapsule(foreignCode));

    HistoryBlockHashUtil.deploy(dbManager);

    assertArrayEquals(foreignCode,
        chainBaseManager.getCodeStore().get(addr).getData());
    assertFalse(chainBaseManager.getContractStore().has(addr));
    assertFalse(chainBaseManager.getAccountStore().has(addr));
  }

  @Test
  public void deploySkipsWhenForeignContractPresent() {
    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;
    SmartContract foreign = SmartContract.newBuilder()
        .setName("NotBlockHashHistory")
        .setContractAddress(ByteString.copyFrom(addr))
        .setOriginAddress(ByteString.copyFrom(addr))
        .build();
    chainBaseManager.getContractStore().put(addr, new ContractCapsule(foreign));

    HistoryBlockHashUtil.deploy(dbManager);

    assertEquals("NotBlockHashHistory",
        chainBaseManager.getContractStore().get(addr).getInstance().getName());
    assertFalse(chainBaseManager.getCodeStore().has(addr));
    assertFalse(chainBaseManager.getAccountStore().has(addr));
  }

  /**
   * Anyone can transfer TRX to {@code HISTORY_STORAGE_ADDRESS} before the
   * proposal fires, leaving an EOA at the canonical address. Activation must
   * upgrade the type to {@code Contract} in place — preserving balance —
   * rather than failing or zeroing the account.
   */
  @Test
  public void deployUpgradesPreExistingNormalAccountPreservingBalance() {
    byte[] addr = HistoryBlockHashUtil.HISTORY_STORAGE_ADDRESS;
    long balance = 12345L;
    AccountCapsule eoa = new AccountCapsule(
        ByteString.copyFrom(addr), Protocol.AccountType.Normal);
    eoa.setBalance(balance);
    chainBaseManager.getAccountStore().put(addr, eoa);

    HistoryBlockHashUtil.deploy(dbManager);

    AccountCapsule after = chainBaseManager.getAccountStore().get(addr);
    assertEquals(Protocol.AccountType.Contract, after.getType());
    assertEquals(balance, after.getBalance());
    assertTrue(chainBaseManager.getCodeStore().has(addr));
    assertTrue(chainBaseManager.getContractStore().has(addr));
  }

}
