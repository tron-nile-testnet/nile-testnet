package org.tron.common.runtime.vm;

import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.utils.StringUtil;
import org.tron.common.utils.client.utils.AbiUtil;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.store.StoreFactory;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.PrecompiledContracts.ValidateMultiPQSig;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.repository.Repository;
import org.tron.core.vm.repository.RepositoryImpl;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.PQScheme;

/**
 * Unit tests for the unified 0x0200001a algorithm-agnostic Permission multi-sign
 * precompile. Replaces the per-scheme {@code ValidateMultiFnDsa512Test} and
 * {@code ValidateMultiMlDsa44Test}: a single call may now mix ECDSA, FN-DSA-512
 * and ML-DSA-44 entries against the same {@code Permission.keys[]}, dispatched
 * per entry by an explicit {@code uint8[]} scheme tag.
 */
@Slf4j
public class ValidateMultiPQSigTest extends BaseTest {

  private static final DataWord ADDR_0X0200001A = new DataWord(
      "000000000000000000000000000000000000000000000000000000000200001a");

  private static final String METHOD_SIGN =
      "validatemultipqsign(address,uint256,bytes32,bytes[],uint8[],bytes[],bytes[])";

  private static final int TAG_FN_DSA_512 = PQScheme.FN_DSA_512.getNumber();
  private static final int TAG_ML_DSA_44 = PQScheme.ML_DSA_44.getNumber();

  private static final byte[] longData;

  static {
    Args.setParam(new String[]{"--output-directory", dbPath(), "--debug"}, TestConstants.TEST_CONF);
    longData = new byte[1000];
    Arrays.fill(longData, (byte) 7);
  }

  private final ValidateMultiPQSig contract = new ValidateMultiPQSig();

  @Before
  public void before() {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1);
    dbManager.getDynamicPropertiesStore().saveTotalSignNum(5);
    VMConfig.initAllowFnDsa512(1L);
    VMConfig.initAllowMlDsa44(1L);
  }

  @After
  public void after() {
    VMConfig.initAllowFnDsa512(0L);
    VMConfig.initAllowMlDsa44(0L);
  }

  // ---------- registration / gating ----------

  @Test
  public void bothSwitchesOff_returnsNull() {
    VMConfig.initAllowFnDsa512(0L);
    VMConfig.initAllowMlDsa44(0L);
    Assert.assertNull(PrecompiledContracts.getContractForAddress(ADDR_0X0200001A));
  }

  @Test
  public void onlyFalconSwitchOn_returnsContract() {
    VMConfig.initAllowMlDsa44(0L);
    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(ADDR_0X0200001A);
    Assert.assertNotNull(pc);
    Assert.assertTrue(pc instanceof ValidateMultiPQSig);
  }

  @Test
  public void onlyDilithiumSwitchOn_returnsContract() {
    VMConfig.initAllowFnDsa512(0L);
    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(ADDR_0X0200001A);
    Assert.assertNotNull(pc);
    Assert.assertTrue(pc instanceof ValidateMultiPQSig);
  }

  @Test
  public void bothSwitchesOn_returnsContract() {
    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(ADDR_0X0200001A);
    Assert.assertNotNull(pc);
    Assert.assertTrue(pc instanceof ValidateMultiPQSig);
  }

  // ---------- happy paths ----------

  @Test
  public void unknownAccount_returnsZero() {
    ECKey owner = new ECKey();
    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(new ECKey().sign(toSign).toByteArray()));
    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList()).getRight());
  }

  @Test
  public void pureEcdsaThresholdReached_returnsOne() {
    ECKey k1 = new ECKey();
    ECKey k2 = new ECKey();
    ECKey owner = new ECKey();
    setupPermission(owner, Arrays.asList(k1.getAddress(), k2.getAddress()),
        Arrays.asList(1, 1), 2,
        Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = Arrays.asList(
        Hex.toHexString(k1.sign(toSign).toByteArray()),
        Hex.toHexString(k2.sign(toSign).toByteArray()));

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList()).getRight());
  }

  @Test
  public void pureFalconThresholdReached_returnsOne() {
    FNDSA512 pq1 = new FNDSA512();
    FNDSA512 pq2 = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr1 = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq1.getPublicKey());
    byte[] addr2 = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pq2.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        2, Arrays.asList(addr1, addr2), Arrays.asList(1, 1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(padFalconSig(pq1.sign(toSign))),
        Hex.toHexString(padFalconSig(pq2.sign(toSign))));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(pq1.getPublicKey()),
        Hex.toHexString(pq2.getPublicKey()));
    List<Integer> schemes = Arrays.asList(TAG_FN_DSA_512, TAG_FN_DSA_512);

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void pureDilithiumThresholdReached_returnsOne() {
    MLDSA44 pq1 = new MLDSA44();
    MLDSA44 pq2 = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] addr1 = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, pq1.getPublicKey());
    byte[] addr2 = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, pq2.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        2, Arrays.asList(addr1, addr2), Arrays.asList(1, 1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(pq1.sign(toSign)),
        Hex.toHexString(pq2.sign(toSign)));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(pq1.getPublicKey()),
        Hex.toHexString(pq2.getPublicKey()));
    List<Integer> schemes = Arrays.asList(TAG_ML_DSA_44, TAG_ML_DSA_44);

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void mixedEcdsaFalconDilithium_returnsOne() {
    // Core motivation: a single permission whose keys[] mixes ECDSA, Falcon
    // and Dilithium entries can now reach threshold in one precompile call.
    ECKey k1 = new ECKey();
    FNDSA512 falcon = new FNDSA512();
    MLDSA44 dilithium = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] falconAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    byte[] dilithiumAddr = PQSchemeRegistry.computeAddress(
        PQScheme.ML_DSA_44, dilithium.getPublicKey());

    setupPermission(owner,
        Collections.singletonList(k1.getAddress()), Collections.singletonList(1),
        3, Arrays.asList(falconAddr, dilithiumAddr), Arrays.asList(1, 1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(k1.sign(toSign).toByteArray()));
    List<Integer> schemes = Arrays.asList(TAG_FN_DSA_512, TAG_ML_DSA_44);
    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))),
        Hex.toHexString(dilithium.sign(toSign)));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(falcon.getPublicKey()),
        Hex.toHexString(dilithium.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs, schemes, pqSigs, pqPks).getRight());
  }

  // ---------- energy ----------

  @Test
  public void energyChargesPerSchemeTag() {
    // 1 × ECDSA (1500) + 1 × Falcon (220) + 1 × Dilithium (470) = 2190
    ECKey k1 = new ECKey();
    FNDSA512 falcon = new FNDSA512();
    MLDSA44 dilithium = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] falconAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    byte[] dilithiumAddr = PQSchemeRegistry.computeAddress(
        PQScheme.ML_DSA_44, dilithium.getPublicKey());
    setupPermission(owner,
        Collections.singletonList(k1.getAddress()), Collections.singletonList(1),
        3, Arrays.asList(falconAddr, dilithiumAddr), Arrays.asList(1, 1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(k1.sign(toSign).toByteArray()));
    List<Integer> schemes = Arrays.asList(TAG_FN_DSA_512, TAG_ML_DSA_44);
    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))),
        Hex.toHexString(dilithium.sign(toSign)));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(falcon.getPublicKey()),
        Hex.toHexString(dilithium.getPublicKey()));

    byte[] input = encodeInput(owner.getAddress(), 2, data, ecdsaSigs, schemes, pqSigs, pqPks);
    Assert.assertEquals(2190L, contract.getEnergyForData(input));
  }

  @Test
  public void energyUnknownTagChargesWorstCase() {
    // A junk tag must be priced at the worst-case PQ cost so an attacker
    // cannot underpay by submitting tags the dispatcher will reject.
    ECKey k1 = new ECKey();
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] falconAddr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner,
        Collections.singletonList(k1.getAddress()), Collections.singletonList(1),
        2, Collections.singletonList(falconAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(k1.sign(toSign).toByteArray()));
    // Two PQ entries: one legit Falcon, one junk-tagged. Junk slot still occupies
    // a sig + pk slot (we use Falcon-shaped bytes so encodeBytesArray is happy).
    List<Integer> schemes = Arrays.asList(TAG_FN_DSA_512, 99);
    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))),
        Hex.toHexString(padFalconSig(falcon.sign(toSign))));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(falcon.getPublicKey()),
        Hex.toHexString(falcon.getPublicKey()));

    byte[] input = encodeInput(owner.getAddress(), 2, data, ecdsaSigs, schemes, pqSigs, pqPks);
    // 1500 + 220 (Falcon) + 470 (junk priced at worst case) = 2190
    Assert.assertEquals(2190L, contract.getEnergyForData(input));
  }

  // ---------- per-entry rejection ----------

  @Test
  public void unknownPqSchemeTag_returnsZero() {
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Collections.singletonList(99);  // unregistered tag
    List<String> pqSigs = Collections.singletonList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void unknownPqSchemeZeroTag_returnsZero() {
    // Proto3 default UNKNOWN_PQ_SCHEME (=0) must be rejected explicitly so
    // producers can't sneak through unset scheme tags.
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Collections.singletonList(0);
    List<String> pqSigs = Collections.singletonList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void mismatchedSchemeAndPqSigArrayLengths_returnsZero() {
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    // 2 schemes but only 1 sig / 1 pk → schemeCnt mismatch.
    List<Integer> schemes = Arrays.asList(TAG_FN_DSA_512, TAG_FN_DSA_512);
    List<String> pqSigs = Collections.singletonList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void falconEntryWhileFalconDisabled_returnsZero() {
    // 0x0200001a stays registered because ML-DSA is still active, but a Falcon entry
    // must be rejected per-entry when its proposal isn't passed.
    VMConfig.initAllowFnDsa512(0L);
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Collections.singletonList(TAG_FN_DSA_512);
    List<String> pqSigs = Collections.singletonList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void dilithiumEntryWhileDilithiumDisabled_returnsZero() {
    VMConfig.initAllowMlDsa44(0L);
    MLDSA44 dilithium = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, dilithium.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Collections.singletonList(TAG_ML_DSA_44);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(dilithium.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(dilithium.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void onlyAllowedSchemeStillWorksWhenOtherDisabled() {
    // Falcon disabled, Dilithium active; pure-Dilithium call must still succeed.
    VMConfig.initAllowFnDsa512(0L);
    MLDSA44 d1 = new MLDSA44();
    MLDSA44 d2 = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] addr1 = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, d1.getPublicKey());
    byte[] addr2 = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, d2.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        2, Arrays.asList(addr1, addr2), Arrays.asList(1, 1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Arrays.asList(TAG_ML_DSA_44, TAG_ML_DSA_44);
    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(d1.sign(toSign)), Hex.toHexString(d2.sign(toSign)));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(d1.getPublicKey()), Hex.toHexString(d2.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  // ---------- length / slot rules ----------

  @Test
  public void falconSigSlotExact666_returnsOne() {
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    byte[] padded = padFalconSig(falcon.sign(toSign));
    Assert.assertEquals(FNDSA512.SIGNATURE_MAX_LENGTH - 1, padded.length);

    List<Integer> schemes = Collections.singletonList(TAG_FN_DSA_512);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(padded));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ONE().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void falconSigSlotNot666_returnsZero() {
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    // Trim the slot one byte short of 666 — must be rejected (slot length exact).
    byte[] shortSlot = Arrays.copyOf(padFalconSig(falcon.sign(toSign)),
        FNDSA512.SIGNATURE_MAX_LENGTH - 2);

    List<Integer> schemes = Collections.singletonList(TAG_FN_DSA_512);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(shortSlot));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void falconSigAllZero_returnsZero() {
    // All-zero 666-byte slot: recoverFalconSigLen returns 0, below the headerless
    // minimum.
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);

    byte[] zeros = new byte[FNDSA512.SIGNATURE_MAX_LENGTH - 1];
    List<Integer> schemes = Collections.singletonList(TAG_FN_DSA_512);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(zeros));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void dilithiumSigWrongLength_returnsZero() {
    MLDSA44 d1 = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, d1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);

    byte[] wrongLen = new byte[MLDSA44.SIGNATURE_LENGTH - 1];
    Arrays.fill(wrongLen, (byte) 0x42);
    List<Integer> schemes = Collections.singletonList(TAG_ML_DSA_44);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(wrongLen));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(d1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void falconSigLabelledDilithium_returnsZero() {
    // Falcon sig in a Dilithium-tagged entry → slot length 666 != 2420 → reject.
    FNDSA512 falcon = new FNDSA512();
    MLDSA44 d1 = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, d1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Collections.singletonList(TAG_ML_DSA_44);
    List<String> pqSigs = Collections.singletonList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(d1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void wrongPqPublicKeyLength_returnsZero() {
    MLDSA44 d1 = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, d1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    byte[] truncatedPk = Arrays.copyOf(d1.getPublicKey(), d1.getPublicKey().length - 1);

    List<Integer> schemes = Collections.singletonList(TAG_ML_DSA_44);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(d1.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(truncatedPk));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  // ---------- dedup / failure semantics ----------

  @Test
  public void crossEntryDedupSameAddress_doesNotDoubleCount() {
    // Same Falcon key submitted twice — dedup keys on derived address (PQ
    // signing is randomized so two valid sigs from one key are normal).
    // Threshold 2, weight 1 → second occurrence is ignored, threshold not met.
    FNDSA512 falcon = new FNDSA512();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, falcon.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        2, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Arrays.asList(TAG_FN_DSA_512, TAG_FN_DSA_512);
    List<String> pqSigs = Arrays.asList(
        Hex.toHexString(padFalconSig(falcon.sign(toSign))),
        Hex.toHexString(padFalconSig(falcon.sign(toSign))));
    List<String> pqPks = Arrays.asList(
        Hex.toHexString(falcon.getPublicKey()),
        Hex.toHexString(falcon.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void pqSignatureForgery_returnsZero() {
    MLDSA44 d1 = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] addr = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, d1.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(addr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    byte[] forged = d1.sign(toSign);
    forged[10] ^= 0x01;

    List<Integer> schemes = Collections.singletonList(TAG_ML_DSA_44);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(forged));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(d1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void pqKeyNotInPermission_returnsZero() {
    MLDSA44 inPerm = new MLDSA44();
    MLDSA44 outsider = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] inAddr = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, inPerm.getPublicKey());
    setupPermission(owner, Collections.emptyList(), Collections.emptyList(),
        1, Collections.singletonList(inAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<Integer> schemes = Collections.singletonList(TAG_ML_DSA_44);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(outsider.sign(toSign)));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(outsider.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void totalCountOverMaxSize_returnsZero() {
    ECKey owner = new ECKey();
    List<byte[]> ecdsaAddrs = new ArrayList<>();
    List<Integer> ecdsaWeights = new ArrayList<>();
    List<ECKey> ecdsaKeys = new ArrayList<>();
    for (int i = 0; i < 6; i++) {
      ECKey k = new ECKey();
      ecdsaKeys.add(k);
      ecdsaAddrs.add(k.getAddress());
      ecdsaWeights.add(1);
    }
    setupPermission(owner, ecdsaAddrs, ecdsaWeights, 6,
        Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = new ArrayList<>();
    for (ECKey k : ecdsaKeys) {
      ecdsaSigs.add(Hex.toHexString(k.sign(toSign).toByteArray()));
    }

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList()).getRight());
  }

  @Test
  public void bothArraysEmpty_returnsZero() {
    ECKey k1 = new ECKey();
    ECKey owner = new ECKey();
    setupPermission(owner, Collections.singletonList(k1.getAddress()),
        Collections.singletonList(1), 1,
        Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data,
            Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList(), Collections.emptyList()).getRight());
  }

  @Test
  public void mixedFailingPqAborts_returnsZero() {
    // Mirrors 0x09 semantics: a verify failure on any entry aborts the whole
    // call with DATA_FALSE even if other entries would alone reach threshold.
    ECKey k1 = new ECKey();
    ECKey k2 = new ECKey();
    MLDSA44 d1 = new MLDSA44();
    ECKey owner = new ECKey();
    byte[] pqAddr = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, d1.getPublicKey());
    setupPermission(owner,
        Arrays.asList(k1.getAddress(), k2.getAddress()), Arrays.asList(1, 1),
        2, Collections.singletonList(pqAddr), Collections.singletonList(1));

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);

    List<String> ecdsaSigs = Arrays.asList(
        Hex.toHexString(k1.sign(toSign).toByteArray()),
        Hex.toHexString(k2.sign(toSign).toByteArray()));
    byte[] forged = d1.sign(toSign);
    forged[0] ^= 0x55;
    List<Integer> schemes = Collections.singletonList(TAG_ML_DSA_44);
    List<String> pqSigs = Collections.singletonList(Hex.toHexString(forged));
    List<String> pqPks = Collections.singletonList(Hex.toHexString(d1.getPublicKey()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs, schemes, pqSigs, pqPks).getRight());
  }

  @Test
  public void thresholdNotReached_returnsZero() {
    ECKey k1 = new ECKey();
    ECKey k2 = new ECKey();
    ECKey owner = new ECKey();
    setupPermission(owner, Arrays.asList(k1.getAddress(), k2.getAddress()),
        Arrays.asList(1, 1), 2, Collections.emptyList(), Collections.emptyList());

    byte[] data = Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), longData);
    byte[] toSign = computeHash(owner.getAddress(), 2, data);
    List<String> ecdsaSigs = Collections.singletonList(
        Hex.toHexString(k1.sign(toSign).toByteArray()));

    Assert.assertArrayEquals(DataWord.ZERO().getData(),
        runContract(owner.getAddress(), 2, data, ecdsaSigs,
            Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList()).getRight());
  }

  // -------- helpers --------

  /**
   * Pin a Falcon signature into the precompile's 666-byte slot using the EIP-8052
   * headerless convention: strip BC's leading 0x39 header so the slot holds
   * {@code salt ‖ s2}, then zero-pad. The body ends in a non-zero
   * {@code compressed_s2} terminator, so the precompile recovers its length.
   */
  private static byte[] padFalconSig(byte[] sig) {
    if (sig.length > FNDSA512.SIGNATURE_MAX_LENGTH) {
      throw new IllegalStateException("Falcon sig longer than slot: " + sig.length);
    }
    byte[] slot = new byte[FNDSA512.SIGNATURE_MAX_LENGTH - 1];
    System.arraycopy(sig, 1, slot, 0, sig.length - 1);
    return slot;
  }

  private void setupPermission(ECKey owner,
                               List<byte[]> ecdsaKeyAddrs, List<Integer> ecdsaWeights,
                               int threshold,
                               List<byte[]> pqKeyAddrs, List<Integer> pqWeights) {
    AccountCapsule account = new AccountCapsule(ByteString.copyFrom(owner.getAddress()),
        Protocol.AccountType.Normal, System.currentTimeMillis(), true,
        dbManager.getDynamicPropertiesStore());

    Protocol.Permission.Builder perm = Protocol.Permission.newBuilder()
        .setType(Protocol.Permission.PermissionType.Active)
        .setId(2)
        .setPermissionName("active")
        .setThreshold(threshold)
        .setOperations(ByteString.copyFrom(ByteArray.fromHexString(
            "0000000000000000000000000000000000000000000000000000000000000000")));
    for (int i = 0; i < ecdsaKeyAddrs.size(); i++) {
      perm.addKeys(Protocol.Key.newBuilder()
          .setAddress(ByteString.copyFrom(ecdsaKeyAddrs.get(i)))
          .setWeight(ecdsaWeights.get(i)).build());
    }
    for (int i = 0; i < pqKeyAddrs.size(); i++) {
      perm.addKeys(Protocol.Key.newBuilder()
          .setAddress(ByteString.copyFrom(pqKeyAddrs.get(i)))
          .setWeight(pqWeights.get(i)).build());
    }
    account.updatePermissions(account.getPermissionById(0), null,
        Collections.singletonList(perm.build()));
    dbManager.getAccountStore().put(owner.getAddress(), account);
  }

  private byte[] computeHash(byte[] address, int permissionId, byte[] data) {
    byte[] combined = ByteUtil.merge(address, ByteArray.fromInt(permissionId), data);
    return Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(), combined);
  }

  private byte[] encodeInput(byte[] ownerAddr, int permissionId, byte[] data,
                             List<String> ecdsaSigs, List<Integer> schemes,
                             List<String> pqSigs, List<String> pqPks) {
    List<Object> parameters = Arrays.asList(
        StringUtil.encode58Check(ownerAddr),
        permissionId,
        "0x" + Hex.toHexString(data),
        toHexList(ecdsaSigs),
        toObjList(schemes),
        toHexList(pqSigs),
        toHexList(pqPks));
    return Hex.decode(AbiUtil.parseParameters(METHOD_SIGN, parameters));
  }

  private Pair<Boolean, byte[]> runContract(byte[] ownerAddr, int permissionId, byte[] data,
                                            List<String> ecdsaSigs, List<Integer> schemes,
                                            List<String> pqSigs, List<String> pqPks) {
    byte[] input = encodeInput(ownerAddr, permissionId, data, ecdsaSigs, schemes, pqSigs, pqPks);
    Repository deposit = RepositoryImpl.createRoot(StoreFactory.getInstance());
    contract.setRepository(deposit);
    Pair<Boolean, byte[]> ret = contract.execute(input);
    logger.info("0x0200001a result: {}", Hex.toHexString(ret.getRight()));
    return ret;
  }

  private static List<Object> toHexList(List<String> hexes) {
    List<Object> out = new ArrayList<>(hexes.size());
    for (String h : hexes) {
      out.add(h.startsWith("0x") ? h : ("0x" + h));
    }
    return out;
  }

  private static List<Object> toObjList(List<Integer> ints) {
    List<Object> out = new ArrayList<>(ints.size());
    for (Integer i : ints) {
      out.add(i);
    }
    return out;
  }
}
