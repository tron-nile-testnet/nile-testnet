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
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.client.utils.AbiUtil;
import org.tron.core.vm.PQPrecompiledContracts.BatchValidateFnDsa512;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;
import org.tron.protos.Protocol.PQScheme;

/**
 * Unit tests for the 0x02000017 batch independent Falcon-512 verify precompile.
 * Returns a 256-bit bitmap where bit i is set iff
 * {@code derive(pk_i) == expectedAddr_i && FNDSA512.verify(pk_i, hash, sig_i)}.
 * Stateless — no chain DB.
 */
@Slf4j
public class BatchValidateFnDsa512Test {

  private static final DataWord ADDR_0X02000017 = new DataWord(
      "0000000000000000000000000000000000000000000000000000000002000017");

  private static final String METHOD_SIGN =
      "batchvalidatefndsa512(bytes32,bytes[],bytes[],bytes32[])";

  private static final byte[] HASH;

  static {
    HASH = new byte[32];
    for (int i = 0; i < 32; i++) {
      HASH[i] = (byte) (i + 1);
    }
  }

  private final BatchValidateFnDsa512 contract = new BatchValidateFnDsa512();

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
    Assert.assertNull(PrecompiledContracts.getContractForAddress(ADDR_0X02000017));
  }

  @Test
  public void switchOn_returnsContract() {
    PrecompiledContract pc = PrecompiledContracts.getContractForAddress(ADDR_0X02000017);
    Assert.assertNotNull(pc);
    Assert.assertTrue(pc instanceof BatchValidateFnDsa512);
  }

  @Test
  public void constantCall_allValid_setsAllBits() {
    contract.setConstantCall(true);
    int n = 4;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      FNDSA512 k = new FNDSA512();
      sigs.add(Hex.toHexString(padSlot(k.sign(HASH))));
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
    FNDSA512 k1 = new FNDSA512();
    FNDSA512 k2 = new FNDSA512();
    List<String> sigs = Arrays.asList(
        Hex.toHexString(padSlot(k1.sign(HASH))),
        Hex.toHexString(padSlot(k2.sign(HASH))));
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
    FNDSA512 k = new FNDSA512();
    byte[] sig = padSlot(k.sign(HASH));
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
    FNDSA512 k = new FNDSA512();
    byte[] truncatedPk = Arrays.copyOf(k.getPublicKey(), k.getPublicKey().length - 1);
    List<String> sigs = Collections1(Hex.toHexString(padSlot(k.sign(HASH))));
    List<String> pks = Collections1(Hex.toHexString(truncatedPk));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(0, res[0]);
  }

  @Test
  public void asyncPath_allValid_setsAllBits() {
    contract.setConstantCall(false);
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 5_000_000L);
    int n = 4;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      FNDSA512 k = new FNDSA512();
      sigs.add(Hex.toHexString(padSlot(k.sign(HASH))));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    for (int i = 0; i < n; i++) {
      Assert.assertEquals("bit " + i, 1, res[i]);
    }
  }

  @Test
  public void mismatchedArrayLengths_reverts() {
    contract.setConstantCall(true);
    FNDSA512 k = new FNDSA512();
    List<String> sigs = Collections1(Hex.toHexString(padSlot(k.sign(HASH))));
    List<String> pks = Arrays.asList(
        Hex.toHexString(k.getPublicKey()), Hex.toHexString(k.getPublicKey()));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    Pair<Boolean, byte[]> result = run(HASH, sigs, pks, addrs);
    Assert.assertFalse(result.getLeft());
  }

  @Test
  public void overMaxSize_reverts() {
    contract.setConstantCall(true);
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 30_000_000L);
    int n = 17;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      FNDSA512 k = new FNDSA512();
      sigs.add(Hex.toHexString(padSlot(k.sign(HASH))));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    Pair<Boolean, byte[]> result = run(HASH, sigs, pks, addrs);
    Assert.assertFalse(result.getLeft());
  }

  @Test
  public void energyScalesWithCount() {
    contract.setConstantCall(true);
    int n = 3;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      FNDSA512 k = new FNDSA512();
      sigs.add(Hex.toHexString(padSlot(k.sign(HASH))));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    byte[] input = encode(HASH, sigs, pks, addrs);
    Assert.assertEquals(3L * 220L, contract.getEnergyForData(input));
  }

  @Test
  public void emptyArrays_reverts() {
    contract.setConstantCall(true);
    Pair<Boolean, byte[]> result =
        run(HASH, new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
    Assert.assertFalse(result.getLeft());
  }

  @Test
  public void differentHash_clearsAllBits() {
    contract.setConstantCall(true);
    int n = 3;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      FNDSA512 k = new FNDSA512();
      // Sign HASH...
      sigs.add(Hex.toHexString(padSlot(k.sign(HASH))));
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
      FNDSA512 k = new FNDSA512();
      sigs.add(Hex.toHexString(padSlot(k.sign(HASH))));
      pks.add(Hex.toHexString(k.getPublicKey()));
      addrs.add(addrAsBytes32Hex(k.getPublicKey()));
    }
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 30_000_000L);
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
    contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 10_000_000L);
    int n = 4;
    List<String> sigs = new ArrayList<>(n);
    List<String> pks = new ArrayList<>(n);
    List<String> addrs = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      FNDSA512 k = new FNDSA512();
      byte[] sig = padSlot(k.sign(HASH));
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
  public void sigTooLong_clearsBit() {
    contract.setConstantCall(true);
    FNDSA512 k = new FNDSA512();
    byte[] oversized = new byte[800];
    Arrays.fill(oversized, (byte) 0x99);
    List<String> sigs = Collections1(Hex.toHexString(oversized));
    List<String> pks = Collections1(Hex.toHexString(k.getPublicKey()));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(0, res[0]);
  }

  @Test
  public void slotShorterThan666_clearsBit() {
    contract.setConstantCall(true);
    FNDSA512 k = new FNDSA512();
    byte[] sig = k.sign(HASH);
    byte[] shortSlot = Arrays.copyOf(sig, FNDSA512.SIGNATURE_MAX_LENGTH - 2);
    List<String> sigs = Collections1(Hex.toHexString(shortSlot));
    List<String> pks = Collections1(Hex.toHexString(k.getPublicKey()));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(0, res[0]);
  }

  @Test
  public void allZeroSlot_clearsBit() {
    contract.setConstantCall(true);
    FNDSA512 k = new FNDSA512();
    byte[] zeroSlot = new byte[FNDSA512.SIGNATURE_MAX_LENGTH - 1];
    List<String> sigs = Collections1(Hex.toHexString(zeroSlot));
    List<String> pks = Collections1(Hex.toHexString(k.getPublicKey()));
    List<String> addrs = Collections1(addrAsBytes32Hex(k.getPublicKey()));

    byte[] res = run(HASH, sigs, pks, addrs).getRight();
    Assert.assertEquals(0, res[0]);
  }

  @Test
  public void oversizedElementBytesLen_returnsDataFalse_noOom() {
    // TB-03: element bytesLen = Integer.MAX_VALUE must not cause OOM.
    // extractBytesArray must detect bytesLen > data.length and return [],
    // so the precompile returns DATA_FALSE instead of crashing the JVM.
    contract.setConstantCall(true);
    byte[] input = new byte[12 * 32];
    setWord(input, 1, 128);              // sigs array offset = word 4
    setWord(input, 2, 224);              // pks array offset  = word 7
    setWord(input, 3, 320);              // addrs array offset = word 10
    setWord(input, 4, 1);               // sigs count = 1
    setWord(input, 5, 32);              // sigs[0] relative offset (1 word past count)
    setWord(input, 6, Integer.MAX_VALUE); // sigs[0] bytesLen attack vector
    setWord(input, 7, 1);               // pks count = 1
    setWord(input, 8, 32);              // pks[0] relative offset
    setWord(input, 9, 1);               // pks[0] bytesLen (benign)
    setWord(input, 10, 1);              // addrs count = 1

    Pair<Boolean, byte[]> result = contract.execute(input);
    Assert.assertFalse(result.getLeft());
    Assert.assertArrayEquals(new byte[0], result.getRight());
  }

  @Test
  public void elementPayloadPastInput_returnsDataFalse_noZeroPadding() {
    // copyOfRange zero-pads when to > data.length; malformed bytes must not
    // be accepted as if the missing tail were real zero bytes.
    contract.setConstantCall(true);
    byte[] input = new byte[12 * 32];
    setWord(input, 1, 128);              // sigs array offset = word 4
    setWord(input, 2, 224);              // pks array offset  = word 7
    setWord(input, 3, 320);              // addrs array offset = word 10
    setWord(input, 4, 1);                // sigs count = 1
    setWord(input, 5, 192);              // sigs[0] relative offset = word 6
    setWord(input, 7, 1);                // pks count = 1
    setWord(input, 8, 32);               // pks[0] relative offset
    setWord(input, 9, 1);                // pks[0] bytesLen (benign)
    setWord(input, 10, 1);               // addrs count = 1
    setWord(input, 11, 1);               // sigs[0] bytesLen, payload starts at EOF

    Pair<Boolean, byte[]> result = contract.execute(input);
    Assert.assertFalse(result.getLeft());
    Assert.assertArrayEquals(new byte[0], result.getRight());
  }

  @Test
  public void elementLengthWordPastInput_returnsDataFalse_noBoundsException() {
    contract.setConstantCall(true);
    byte[] input = new byte[12 * 32];
    setWord(input, 1, 128);              // sigs array offset = word 4
    setWord(input, 2, 224);              // pks array offset  = word 7
    setWord(input, 3, 320);              // addrs array offset = word 10
    setWord(input, 4, 1);                // sigs count = 1
    setWord(input, 5, 224);              // sigs[0] length word would be word 12
    setWord(input, 7, 1);                // pks count = 1
    setWord(input, 8, 32);               // pks[0] relative offset
    setWord(input, 9, 1);                // pks[0] bytesLen (benign)
    setWord(input, 10, 1);               // addrs count = 1

    Pair<Boolean, byte[]> result = contract.execute(input);
    Assert.assertFalse(result.getLeft());
    Assert.assertArrayEquals(new byte[0], result.getRight());
  }

  @Test
  public void nonAlignedElementPointer_returnsDataFalse() {
    // bytesOffsetBytes % WORD_SIZE != 0 guard in extractBytesArrayChecked.
    contract.setConstantCall(true);
    byte[] input = new byte[12 * 32];
    setWord(input, 1, 128);
    setWord(input, 2, 224);
    setWord(input, 3, 320);
    setWord(input, 4, 1);   // sigs count = 1
    setWord(input, 5, 15);  // pointer = 15: not a multiple of 32
    setWord(input, 7, 1);
    setWord(input, 8, 32);
    setWord(input, 9, 1);
    setWord(input, 10, 1);

    Pair<Boolean, byte[]> result = contract.execute(input);
    Assert.assertFalse(result.getLeft());
    Assert.assertArrayEquals(new byte[0], result.getRight());
  }

  @Test
  public void pointerWordsExceedInput_returnsDataFalse() {
    // (long)offset + len + 1 > words.length guard in extractBytesArrayChecked.
    // All three arrays point to word 4 (count = 8); the 8 per-element pointer
    // words would need words[5..12], but the buffer only has words[0..11].
    contract.setConstantCall(true);
    byte[] input = new byte[12 * 32];
    setWord(input, 1, 128);  // sigArrayWord = pkArrayWord = addrArrayWord = 4
    setWord(input, 2, 128);
    setWord(input, 3, 128);
    setWord(input, 4, 8);   // count = 8; 4 + 8 + 1 = 13 > 12 = words.length

    Pair<Boolean, byte[]> result = contract.execute(input);
    Assert.assertFalse(result.getLeft());
    Assert.assertArrayEquals(new byte[0], result.getRight());
  }

  // -------- helpers --------

  /**
   * Pin a Falcon-512 signature into the precompile's fixed 666-byte slot using the
   * EIP-8052 headerless convention enforced by 0x02000016 / 0x02000017 / 0x0200001a:
   * strip BC's leading
   * 0x39 header so the slot holds {@code salt ‖ s2}; the tail is zero-padded.
   */
  private static byte[] padSlot(byte[] sig) {
    if (sig.length > FNDSA512.SIGNATURE_MAX_LENGTH) {
      throw new IllegalStateException("Falcon sig longer than slot: " + sig.length);
    }
    byte[] slot = new byte[FNDSA512.SIGNATURE_MAX_LENGTH - 1];
    System.arraycopy(sig, 1, slot, 0, sig.length - 1);
    return slot;
  }


  private Pair<Boolean, byte[]> run(byte[] hash, List<String> sigs,
                                    List<String> pks, List<String> addrs) {
    byte[] input = encode(hash, sigs, pks, addrs);
    // Preserve any longer budget callers set (e.g. atMaxSize16_setsAllBits and
    // asyncPath_* need 10-30s for 16 parallel Falcon-512 verifies on slow CI).
    if (contract.getVmShouldEndInUs() == 0) {
      contract.setVmShouldEndInUs(System.nanoTime() / 1000 + 5_000_000L);
    }
    Pair<Boolean, byte[]> ret = contract.execute(input);
    logger.info("0x02000017 bitmap: {}", Hex.toHexString(ret.getRight()));
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
    byte[] addr21 = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pk);
    byte[] padded = new byte[32];
    System.arraycopy(addr21, 0, padded, 32 - addr21.length, addr21.length);
    return "0x" + Hex.toHexString(padded);
  }

  /** Write {@code value} as a big-endian int into the last 4 bytes of word {@code wordIdx}. */
  private static void setWord(byte[] buf, int wordIdx, int value) {
    int pos = wordIdx * 32 + 28;
    buf[pos]     = (byte) (value >>> 24);
    buf[pos + 1] = (byte) (value >>> 16);
    buf[pos + 2] = (byte) (value >>> 8);
    buf[pos + 3] = (byte)  value;
  }
}
