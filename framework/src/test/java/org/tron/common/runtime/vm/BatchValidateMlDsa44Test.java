package org.tron.common.runtime.vm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.client.utils.AbiUtil;
import org.tron.core.vm.PQPrecompiledContracts.BatchValidateMlDsa44;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;
import org.tron.protos.Protocol.PQScheme;

/**
 * Unit tests for the 0x02000019 batch independent ML-DSA-44 verify precompile.
 * Returns a 256-bit bitmap where bit i is set iff
 * {@code derive(pk_i) == expectedAddr_i && MLDSA44.verify(pk_i, hash, sig_i)}.
 * Stateless — no chain DB.
 */
@Slf4j
public class BatchValidateMlDsa44Test {

  private static final DataWord ADDR_0X02000019 = new DataWord(
      "0000000000000000000000000000000000000000000000000000000002000019");

  private static final String METHOD_SIGN =
      "batchvalidatemldsa44(bytes32,bytes[],bytes[],bytes32[])";

  private static final byte[] HASH;

  static {
    HASH = new byte[32];
    for (int i = 0; i < 32; i++) {
      HASH[i] = (byte) (i + 1);
    }
  }

  private final BatchValidateMlDsa44 contract = new BatchValidateMlDsa44();

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
    Assert.assertNull(PrecompiledContracts.getContractForAddress(ADDR_0X02000019));
  }

  @Test
  public void switchOn_returnsContract() {
    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(ADDR_0X02000019);
    Assert.assertNotNull(pc);
    Assert.assertTrue(pc instanceof BatchValidateMlDsa44);
  }

  @Test
  public void constantCall_allValid_setsAllBits() {
    contract.setConstantCall(true);
    int n = 4;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      MLDSA44 k = new MLDSA44();
      sigs.add(Hex.toHexString(k.sign(HASH)));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    for (int i = 0; i < n; i++) {
      Assert.assertEquals("bit " + i, 1, res[i]);
    }
    for (int i = n; i < 32; i++) {
      Assert.assertEquals("padding bit " + i, 0, res[i]);
    }
  }

  @Test
  public void constantCall_mismatchedAddress_clearsBit() {
    contract.setConstantCall(true);
    MLDSA44 k1 = new MLDSA44();
    MLDSA44 k2 = new MLDSA44();
    List<String> sigs = Arrays.asList(
        Hex.toHexString(k1.sign(HASH)),
        Hex.toHexString(k2.sign(HASH)));
    List<String> pks = Arrays.asList(
        Hex.toHexString(k1.getPublicKey()),
        Hex.toHexString(k2.getPublicKey()));
    // entry 1's address is wrong
    List<String> addrs = Arrays.asList(
        addrAsBytes32Hex(k1.getPublicKey()),
        addrAsBytes32Hex(k1.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(1, res[0]);
    Assert.assertEquals(0, res[1]);
  }

  @Test
  public void constantCall_tamperedSignature_clearsBit() {
    contract.setConstantCall(true);
    MLDSA44 k = new MLDSA44();
    byte[] sig = k.sign(HASH);
    sig[0] ^= 0x01;
    List<String> sigs = Collections1(Hex.toHexString(sig));
    List<String> pks = Collections1(Hex.toHexString(k.getPublicKey()));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(0, res[0]);
  }

  @Test
  public void constantCall_wrongPkLength_clearsBit() {
    contract.setConstantCall(true);
    MLDSA44 k = new MLDSA44();
    byte[] truncatedPk = Arrays.copyOf(k.getPublicKey(), k.getPublicKey().length - 1);
    List<String> sigs = Collections1(Hex.toHexString(k.sign(HASH)));
    List<String> pks = Collections1(Hex.toHexString(truncatedPk));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(0, res[0]);
  }

  @Test
  public void asyncPath_allValid_setsAllBits() {
    contract.setConstantCall(false);
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 10_000_000L);
    int n = 4;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      MLDSA44 k = new MLDSA44();
      sigs.add(Hex.toHexString(k.sign(HASH)));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    for (int i = 0; i < n; i++) {
      Assert.assertEquals("bit " + i, 1, res[i]);
    }
  }

  @Test
  public void mismatchedArrayLengths_returnsZero() {
    contract.setConstantCall(true);
    MLDSA44 k = new MLDSA44();
    List<String> sigs = Collections1(Hex.toHexString(k.sign(HASH)));
    List<String> pks = Arrays.asList(
        Hex.toHexString(k.getPublicKey()), Hex.toHexString(k.getPublicKey()));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertArrayEquals(new byte[32], res);
  }

  @Test
  public void overMaxSize_returnsZero() {
    contract.setConstantCall(true);
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 60_000_000L);
    int n = 17;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      MLDSA44 k = new MLDSA44();
      sigs.add(Hex.toHexString(k.sign(HASH)));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertArrayEquals(new byte[32], res);
  }

  @Test
  public void energyScalesWithCount() {
    contract.setConstantCall(true);
    int n = 3;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      MLDSA44 k = new MLDSA44();
      sigs.add(Hex.toHexString(k.sign(HASH)));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    byte[] input = encode(HASH, sigs, pks, addrs);
    Assert.assertEquals(3L * 470L, contract.getEnergyForData(input));
  }

  @Test
  public void emptyArrays_returnsAllZero() {
    contract.setConstantCall(true);
    byte[] res = run(HASH, new ArrayList<>(), new ArrayList<>(), new ArrayList<>()).getRight();
    Assert.assertArrayEquals(new byte[32], res);
  }

  @Test
  public void differentHash_clearsAllBits() {
    contract.setConstantCall(true);
    int n = 3;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      MLDSA44 k = new MLDSA44();
      // Sign HASH...
      sigs.add(Hex.toHexString(k.sign(HASH)));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    // ...but verify against a different hash.
    byte[] otherHash = new byte[32];
    Arrays.fill(otherHash, (byte) 0xAA);

    byte[] res = run(otherHash, sigs, pks, addrs).getRight();
    Assert.assertArrayEquals(new byte[32], res);
  }

  @Test
  public void atMaxSize16_setsAllBits() {
    contract.setConstantCall(true);
    int n = 16;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      MLDSA44 k = new MLDSA44();
      sigs.add(Hex.toHexString(k.sign(HASH)));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 60_000_000L);
    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    for (int i = 0; i < n; i++) {
      Assert.assertEquals("bit " + i, 1, res[i]);
    }
    for (int i = n; i < 32; i++) {
      Assert.assertEquals("padding bit " + i, 0, res[i]);
    }
  }

  @Test
  public void asyncPath_mixedValidInvalid() {
    contract.setConstantCall(false);
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 20_000_000L);
    int n = 4;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      MLDSA44 k = new MLDSA44();
      byte[] sig = k.sign(HASH);
      // Tamper entries 1 and 3.
      if (i == 1 || i == 3) {
        sig[0] ^= 0x01;
      }
      sigs.add(Hex.toHexString(sig));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(1, res[0]);
    Assert.assertEquals(0, res[1]);
    Assert.assertEquals(1, res[2]);
    Assert.assertEquals(0, res[3]);
  }

  @Test
  public void sigWrongLength_clearsBit() {
    // ML-DSA-44 signatures are fixed at 2420 B; any other length must fail.
    contract.setConstantCall(true);
    MLDSA44 k = new MLDSA44();
    byte[] wrongLen = new byte[MLDSA44.SIGNATURE_LENGTH - 1];
    Arrays.fill(wrongLen, (byte) 0x99);
    List<String> sigs = Collections1(Hex.toHexString(wrongLen));
    List<String> pks = Collections1(Hex.toHexString(k.getPublicKey()));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(0, res[0]);
  }

  // -------- helpers --------

  private Pair<Boolean, byte[]> run(byte[] hash, List<String> sigs,
                                    List<String> pks, List<String> addrs) {
    byte[] input = encode(hash, sigs, pks, addrs);
    // Preserve any longer budget callers set (e.g. atMaxSize16 and asyncPath_*
    // need 20-60s for 16 parallel ML-DSA-44 verifies on slow CI; Dilithium-2
    // verify is ~2× slower than Falcon-512 verify).
    if (contract.getVmShouldEndInUs() == 0) {
      contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 10_000_000L);
    }
    Pair<Boolean, byte[]> ret = contract.execute(input);
    logger.info("0x02000019 bitmap: {}", Hex.toHexString(ret.getRight()));
    return ret;
  }

  private byte[] encode(byte[] hash, List<String> sigs, List<String> pks, List<String> addrs) {
    List<Object> parameters = Arrays.asList(
        "0x" + Hex.toHexString(hash),
        toHexList(sigs),
        toHexList(pks),
        toHexList(addrs));
    return Hex.decode(AbiUtil.parseParameters(METHOD_SIGN, parameters));
  }

  private static List<Object> toHexList(List<String> hexes) {
    List<Object> out = new ArrayList<>(hexes.size());
    for (String h : hexes) {
      out.add(h.startsWith("0x") ? h : ("0x" + h));
    }
    return out;
  }

  private static List<String> Collections1(String s) {
    List<String> l = new ArrayList<>(1);
    l.add(s);
    return l;
  }

  /**
   * Build a bytes32 hex string whose low 21 bytes hold the derived TRON address
   * (high 11 bytes left zero). Matches {@code DataWord.equalAddressByteArray}'s
   * "compare last 20 bytes" semantics.
   */
  private static String addrAsBytes32Hex(byte[] pk) {
    byte[] addr21 = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, pk);
    byte[] padded = new byte[32];
    System.arraycopy(addr21, 0, padded, 32 - addr21.length, addr21.length);
    return "0x" + Hex.toHexString(padded);
  }
}
