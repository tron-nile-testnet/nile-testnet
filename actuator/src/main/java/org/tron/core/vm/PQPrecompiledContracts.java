package org.tron.core.vm;

import static java.util.Arrays.copyOfRange;
import static org.tron.common.math.StrictMathWrapper.multiplyExact;
import static org.tron.common.runtime.vm.DataWord.WORD_SIZE;
import static org.tron.common.utils.ByteUtil.EMPTY_BYTE_ARRAY;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.es.ExecutorServiceManager;
import org.tron.common.math.StrictMathWrapper;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.vm.VMConstant;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.program.Program;
import org.tron.core.vm.program.Program.OutOfTimeException;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Permission;

@Slf4j(topic = "VM")
public class PQPrecompiledContracts {

  /**
   * Best-effort cancellation of all submitted batch-verify tasks. Tasks that
   * have not yet started execution are removed from the worker queue; tasks
   * already running receive an interrupt but BouncyCastle's PQ verify routines
   * do not poll the interrupt flag and will run to completion.
   */
  static void cancelAll(List<? extends Future<?>> futures) {
    for (Future<?> f : futures) {
      f.cancel(true);
    }
  }

  /**
   * Returns the logical Falcon-512 signature length packed at the start of a
   * fixed slot {@code data[from..to)}: the offset of the last non-zero byte
   * (exclusive). Canonical Falcon encodings always end in a non-zero byte
   * ({@code compressed_s2}'s unary terminator), so anything beyond is zero
   * padding. Returns 0 if the slot is all zero. Shared by 0x02000016, 0x02000017, and 0x0200001a
   * because every precompile slot for Falcon sigs is the same 666-byte slot.
   */
  static int recoverFalconSigLen(byte[] data, int from, int to) {
    for (int i = to - 1; i >= from; i--) {
      if (data[i] != 0) {
        return i - from + 1;
      }
    }
    return 0;
  }

  /**
   * Reconstructs the BC-native Falcon-512 signature from an EIP-8052 headerless
   * slot. The slot {@code data[from..to)} holds {@code salt ‖ s2_compressed}
   * (no leading {@code 0x39}) zero-padded to
   * {@code SIGNATURE_MAX_LENGTH - SIGNATURE_HEADER_LENGTH};
   * the logical body ends at the last non-zero byte. Returns
   * {@code 0x39 ‖ body} so BC's {@code FalconSigner} (which requires the header)
   * can verify it, or {@code null} if the recovered body length is out of range.
   * Shared by 0x02000016, 0x02000017, and 0x0200001a.
   */
  static byte[] falconSlotToHeaderedSig(byte[] data, int from, int to) {
    int bodyLen = recoverFalconSigLen(data, from, to);
    if (bodyLen < FNDSA512.SIGNATURE_MIN_LENGTH - FNDSA512.SIGNATURE_HEADER_LENGTH
        || bodyLen > FNDSA512.SIGNATURE_MAX_LENGTH - FNDSA512.SIGNATURE_HEADER_LENGTH) {
      return null;
    }
    byte[] sig = new byte[bodyLen + FNDSA512.SIGNATURE_HEADER_LENGTH];
    sig[0] = FNDSA512.SIGNATURE_HEADER;
    System.arraycopy(data, from, sig, FNDSA512.SIGNATURE_HEADER_LENGTH, bodyLen);
    return sig;
  }

  /**
   * Structural pre-check for ABI head: word-aligned length and room for the
   * fixed head. The PQ precompiles cannot reuse the ABI encoding check from {@code PrecompiledContracts}
   * because their {@code bytes[]} entries (PQ signatures, 1..752 bytes) are
   * variable-length, so the trailing divisibility check does not apply.
   */
  static boolean isValidAbiHead(byte[] data, int headWords) {
    return data != null
        && data.length % WORD_SIZE == 0
        && data.length >= multiplyExact(headWords, WORD_SIZE);
  }

  /**
   * Verifies that the array offset stored at {@code words[offsetWordIndex]} is
   * word-aligned, falls inside the dynamic data region (≥ head), and points to
   * a length word that still fits inside {@code words}. Sister check to
   * {@code PrecompiledContracts.isValidAbiEncoding} for ABIs whose items are not uniform width.
   */
  static boolean isValidArrayOffset(DataWord[] words, int offsetWordIndex, int headWords) {
    long offsetBytes = words[offsetWordIndex].longValueSafe();
    if (offsetBytes < (long) headWords * WORD_SIZE || offsetBytes % WORD_SIZE != 0) {
      return false;
    }
    long lengthWordIdx = offsetBytes / WORD_SIZE;
    return lengthWordIdx < words.length;
  }

  static byte[][] extractBytesArrayChecked(DataWord[] words, int offset, byte[] data) {
    if (offset > words.length - 1) {
      return new byte[0][];
    }
    int len = words[offset].intValueSafe();
    if ((long) offset + len + 1 > words.length) {
      return new byte[0][];
    }
    byte[][] bytesArray = new byte[len][];
    for (int i = 0; i < len; i++) {
      int bytesOffsetBytes = words[offset + i + 1].intValueSafe();
      if (bytesOffsetBytes % WORD_SIZE != 0) {
        return new byte[0][];
      }
      int bytesOffset = bytesOffsetBytes / WORD_SIZE;
      if ((long) offset + bytesOffset + 1 > words.length - 1) {
        return new byte[0][];
      }
      int bytesLen = words[offset + bytesOffset + 1].intValueSafe();
      long fromL = ((long) bytesOffset + offset + 2) * WORD_SIZE;
      long toL = fromL + bytesLen;
      if (fromL > data.length || toL > data.length) {
        return new byte[0][];
      }
      bytesArray[i] = PrecompiledContracts.extractBytes(data, (int) fromL, bytesLen);
    }
    return bytesArray;
  }

  /**
   * Verifies a FN-DSA / Falcon-512 signature (FIPS-206 draft). EIP-8052 / TRON extension.
   *
   * <p>Input layout (fixed-length, EIP-8052):
   * <pre>
   *   [msg 32B | sig 666B (zero-padded) | pk 896B]  total = 1594B
   * </pre>
   * The 666-byte sig slot holds the <strong>EIP-8052 headerless</strong> encoding
   * {@code salt(40B) ‖ s2_compressed}: unlike BouncyCastle's native form there is
   * <em>no</em> leading {@code 0x39} header byte. The headerless body is logically
   * variable (≤ 665B after the salt); encoders write it into the prefix of the slot
   * and zero-pad the tail to length 666. The {@code compressed_s2} encoding always
   * ends in a non-zero byte (its unary terminator bit), so the logical body length
   * is recovered by scanning the slot backwards for the first non-zero byte. Before
   * verifying, the precompile re-inserts the {@code 0x39} header that BC's
   * {@code FalconSigner} requires (it rejects any first byte ≠ {@code 0x30 + logn}).
   * Total input length must equal exactly 1594 (no trailing bytes; matches 0x100
   * P256Verify / EIP-7951 strictness).
   *
   * <p>Returns a 32-byte word: 1 on valid signature, 0 otherwise. Malformed
   * input (wrong total length, sig slot all zero, recovered length out of
   * range, BC verification failure) returns 0 without error.
   */
  public static class VerifyFnDsa512 extends PrecompiledContracts.PrecompiledContract {

    private static final int MSG_LEN = 32;
    private static final int SIG_SLOT_LEN =
        FNDSA512.SIGNATURE_MAX_LENGTH - FNDSA512.SIGNATURE_HEADER_LENGTH;
    private static final int PK_LEN = FNDSA512.PUBLIC_KEY_LENGTH;
    private static final int INPUT_LEN = MSG_LEN + SIG_SLOT_LEN + PK_LEN;
    private static final long ENERGY = 170;

    @Override
    public long getEnergyForData(byte[] data) {
      return ENERGY;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != INPUT_LEN) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      try {
        byte[] msg = copyOfRange(data, 0, MSG_LEN);
        int sigStart = MSG_LEN;
        int sigEnd = MSG_LEN + SIG_SLOT_LEN;
        // The slot carries the EIP-8052 headerless body (salt ‖ s2); reconstruct
        // the BC-headered form (re-inserts 0x39) BC's FalconSigner requires.
        byte[] sig = falconSlotToHeaderedSig(data, sigStart, sigEnd);
        if (sig == null) {
          return Pair.of(true, DataWord.ZERO().getData());
        }
        byte[] pk = copyOfRange(data, sigEnd, INPUT_LEN);
        boolean ok = FNDSA512.verify(pk, msg, sig);
        return Pair.of(true, ok ? DataWord.ONE().getData() : DataWord.ZERO().getData());
      } catch (Throwable t) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
    }

  }


  /**
   * 0x02000017 BatchValidateFnDsa512 — independent per-element Falcon-512 verify.
   *
   * <p>Returns a 256-bit bitmap (matching 0x09) where bit {@code i} is set iff
   * {@code derive(pk_i) == expectedAddr_i} AND {@code FNDSA512.verify(pk_i, hash, sig_i)}.
   *
   * <p>ABI:
   * <pre>
   *   batchValidateFnDsa512(
   *       bytes32   hash,                  // word[0]
   *       bytes[]   signatures,            // word[1] = offset; each 666 B EIP-8052 headerless
   *                                        //          slot (salt‖s2, no 0x39), zero-padded;
   *                                        //          body ends at last non-zero byte
   *       bytes[]   publicKeys,            // word[2] = offset; each 896 B
   *       bytes32[] expectedAddresses      // word[3] = offset; 21-byte addr in low 21 bytes
   *   ) returns (bytes32)
   * </pre>
   *
   * <p>Falcon sigs are pinned to the 666-byte slot from {@code VerifyFnDsa512} (0x02000016)
   * for cross-precompile consistency; {@link #falconSlotToHeaderedSig} recovers the
   * headerless body and re-inserts the {@code 0x39} header before BC verification.
   *
   * <p>Uses a dedicated thread pool when not in a constant call and enforces
   * {@code getCPUTimeLeftInNanoSecond()} timeout. {@code MAX_SIZE = 16}. Energy is
   * {@code cnt × 220}.
   */
  public static class BatchValidateFnDsa512 extends PrecompiledContracts.PrecompiledContract {

    private static final ExecutorService workers;
    private static final String workersName = "pq-batch-validate-fndsa512";

    static {
      workers = ExecutorServiceManager.newFixedThreadPool(workersName,
          Runtime.getRuntime().availableProcessors() / 2 + 1);
    }

    private static final int ENERGY_PER_SIGN = 220;
    private static final int MAX_SIZE = 16;
    private static final int PK_LEN = FNDSA512.PUBLIC_KEY_LENGTH;
    private static final int SIG_SLOT_LEN =
        FNDSA512.SIGNATURE_MAX_LENGTH - FNDSA512.SIGNATURE_HEADER_LENGTH;
    // hash, sigArrayOffset, pkArrayOffset, addrArrayOffset.
    private static final int ABI_HEAD_WORDS = 4;

    @Override
    public long getEnergyForData(byte[] data) {
      try {
        DataWord[] words = DataWord.parseArray(data);
        int cnt = words[words[1].intValueSafe() / WORD_SIZE].intValueSafe();
        int effectiveCnt = cnt > MAX_SIZE ? MAX_SIZE : cnt;
        return (long) effectiveCnt * ENERGY_PER_SIGN;
      } catch (Throwable t) {
        return (long) MAX_SIZE * ENERGY_PER_SIGN;
      }
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      try {
        return doExecute(data);
      } catch (Throwable t) {
        if (t instanceof OutOfTimeException) {
          throw (OutOfTimeException) t;
        }
        if (t instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
    }

    private Pair<Boolean, byte[]> doExecute(byte[] data)
        throws InterruptedException, ExecutionException {
      if (!isValidAbiHead(data, ABI_HEAD_WORDS)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      DataWord[] words = DataWord.parseArray(data);
      if (!isValidArrayOffset(words, 1, ABI_HEAD_WORDS)
          || !isValidArrayOffset(words, 2, ABI_HEAD_WORDS)
          || !isValidArrayOffset(words, 3, ABI_HEAD_WORDS)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      byte[] hash = words[0].getData();

      int sigArrayWord = words[1].intValueSafe() / WORD_SIZE;
      int pkArrayWord = words[2].intValueSafe() / WORD_SIZE;
      int addrArrayWord = words[3].intValueSafe() / WORD_SIZE;

      int sigArraySize = words[sigArrayWord].intValueSafe();
      int pkArraySize = words[pkArrayWord].intValueSafe();
      int addrArraySize = words[addrArrayWord].intValueSafe();

      if (sigArraySize > MAX_SIZE || pkArraySize > MAX_SIZE
          || addrArraySize > MAX_SIZE
          || sigArraySize != pkArraySize || sigArraySize != addrArraySize) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      byte[][] signatures = extractBytesArrayChecked(words, sigArrayWord, data);
      byte[][] publicKeys = extractBytesArrayChecked(words, pkArrayWord, data);
      byte[][] addresses = PrecompiledContracts.extractBytes32Array(words, addrArrayWord);

      int cnt = signatures.length;
      if (cnt == 0 || publicKeys.length != cnt || addresses.length != cnt) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      byte[] res = new byte[WORD_SIZE];
      if (isConstantCall()) {
        for (int i = 0; i < cnt; i++) {
          if (verifyOne(signatures[i], publicKeys[i], hash, addresses[i])) {
            res[i] = 1;
          }
        }
      } else {
        CountDownLatch countDownLatch = new CountDownLatch(cnt);
        List<Future<PqVerifyResult>> futures = new ArrayList<>(cnt);

        for (int i = 0; i < cnt; i++) {
          Future<PqVerifyResult> future =
              workers.submit(
                  new PqVerifyTask(countDownLatch, hash, signatures[i],
                      publicKeys[i], addresses[i], i));
          futures.add(future);
        }

        boolean withNoTimeout = countDownLatch
            .await(getCPUTimeLeftInNanoSecond(), TimeUnit.NANOSECONDS);

        if (!withNoTimeout) {
          cancelAll(futures);
          logger.info("BatchValidateFnDsa512 timeout");
          throw Program.Exception.notEnoughTime("call BatchValidateFnDsa512 precompile method");
        }

        for (Future<PqVerifyResult> future : futures) {
          PqVerifyResult r = future.get();
          if (r.success) {
            res[r.nonce] = 1;
          }
        }
      }
      return Pair.of(true, res);
    }

    private static boolean verifyOne(byte[] sig, byte[] pk, byte[] hash,
        byte[] expectedAddr) {
      if (pk == null || pk.length != PK_LEN || sig == null || sig.length != SIG_SLOT_LEN) {
        return false;
      }
      // The slot is the EIP-8052 headerless body; rebuild the BC-headered sig.
      byte[] canonicalSig = falconSlotToHeaderedSig(sig, 0, sig.length);
      if (canonicalSig == null) {
        return false;
      }
      try {
        byte[] derived = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pk);
        if (!DataWord.equalAddressByteArray(derived, expectedAddr)) {
          return false;
        }
        return FNDSA512.verify(pk, hash, canonicalSig);
      } catch (Throwable t) {
        return false;
      }
    }

    @AllArgsConstructor
    private static class PqVerifyTask implements Callable<PqVerifyResult> {

      private CountDownLatch countDownLatch;
      private byte[] hash;
      private byte[] signature;
      private byte[] publicKey;
      private byte[] expectedAddr;
      private int nonce;

      @Override
      public PqVerifyResult call() {
        try {
          return new PqVerifyResult(
              verifyOne(signature, publicKey, hash, expectedAddr), nonce);
        } finally {
          countDownLatch.countDown();
        }
      }
    }

    @AllArgsConstructor
    private static class PqVerifyResult {

      private boolean success;
      private int nonce;
    }
  }

  /**
   * Verifies an ML-DSA-44 signature (FIPS 204 / CRYSTALS-Dilithium-2).
   *
   * <p>Input layout: {@code [msg 32B | sig 2420B | pk 1312B]} — total 3764 B,
   * strict equality. Returns a 32-byte word (1 on valid, 0 otherwise);
   * malformed input returns 0 without error.
   *
   * <p><b>Diverges from EIP-8051 on pk only.</b> {@code msg} and {@code sig}
   * match EIP-8051; {@code pk} uses the standard FIPS-204 §4 encoding
   * {@code rho ‖ t1} (1312 B) instead of EIP-8051's 20512 B expanded form
   * (precomputed {@code A_hat = ExpandA(rho)}). BC 1.84's {@code MLDSASigner}
   * only accepts the standard form; we pay the per-call {@code ExpandA}
   * cost so 1312 B Dilithium-2 keys work unchanged.
   */
  public static class VerifyMlDsa44 extends PrecompiledContracts.PrecompiledContract {

    private static final int MSG_LEN = 32;
    private static final int SIG_LEN = MLDSA44.SIGNATURE_LENGTH;
    private static final int PK_LEN = MLDSA44.PUBLIC_KEY_LENGTH;
    private static final int INPUT_LEN = MSG_LEN + SIG_LEN + PK_LEN;
    private static final long ENERGY = 420;

    @Override
    public long getEnergyForData(byte[] data) {
      return ENERGY;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != INPUT_LEN) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      try {
        byte[] msg = copyOfRange(data, 0, MSG_LEN);
        byte[] sig = copyOfRange(data, MSG_LEN, MSG_LEN + SIG_LEN);
        byte[] pk = copyOfRange(data, MSG_LEN + SIG_LEN, INPUT_LEN);
        boolean ok = MLDSA44.verify(pk, msg, sig);
        return Pair.of(true,
            ok ? DataWord.ONE().getData() : DataWord.ZERO().getData());
      } catch (Throwable t) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
    }
  }

  /**
   * 0x02000019 BatchValidateMlDsa44 — independent per-element ML-DSA-44 verify.
   * Returns a 256-bit bitmap where bit {@code i} is set iff
   * {@code derive(pk_i) == expectedAddr_i} AND {@code MLDSA44.verify(pk_i, hash, sig_i)}.
   * Same ABI shape as 0x02000017, with sigs 2420 B and pks 1312 B.
   * {@code MAX_SIZE = 16}; energy is {@code cnt × 470}.
   */
  public static class BatchValidateMlDsa44 extends PrecompiledContracts.PrecompiledContract {

    private static final ExecutorService workers;
    private static final String workersName = "pq-batch-validate-mldsa44";

    static {
      workers = ExecutorServiceManager.newFixedThreadPool(workersName,
          Runtime.getRuntime().availableProcessors() / 2 + 1);
    }

    private static final int ENERGY_PER_SIGN = 470;
    private static final int MAX_SIZE = 16;
    private static final int PK_LEN = MLDSA44.PUBLIC_KEY_LENGTH;
    private static final int SIG_LEN = MLDSA44.SIGNATURE_LENGTH;
    // hash, sigArrayOffset, pkArrayOffset, addrArrayOffset.
    private static final int ABI_HEAD_WORDS = 4;

    @Override
    public long getEnergyForData(byte[] data) {
      try {
        DataWord[] words = DataWord.parseArray(data);
        int cnt = words[words[1].intValueSafe() / WORD_SIZE].intValueSafe();
        int effectiveCnt = cnt > MAX_SIZE ? MAX_SIZE : cnt;
        return (long) effectiveCnt * ENERGY_PER_SIGN;
      } catch (Throwable t) {
        return (long) MAX_SIZE * ENERGY_PER_SIGN;
      }
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      try {
        return doExecute(data);
      } catch (Throwable t) {
        if (t instanceof OutOfTimeException) {
          throw (OutOfTimeException) t;
        }
        if (t instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
    }

    private Pair<Boolean, byte[]> doExecute(byte[] data)
        throws InterruptedException, ExecutionException {
      if (!isValidAbiHead(data, ABI_HEAD_WORDS)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      DataWord[] words = DataWord.parseArray(data);
      if (!isValidArrayOffset(words, 1, ABI_HEAD_WORDS)
          || !isValidArrayOffset(words, 2, ABI_HEAD_WORDS)
          || !isValidArrayOffset(words, 3, ABI_HEAD_WORDS)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      byte[] hash = words[0].getData();

      int sigArrayWord = words[1].intValueSafe() / WORD_SIZE;
      int pkArrayWord = words[2].intValueSafe() / WORD_SIZE;
      int addrArrayWord = words[3].intValueSafe() / WORD_SIZE;

      int sigArraySize = words[sigArrayWord].intValueSafe();
      int pkArraySize = words[pkArrayWord].intValueSafe();
      int addrArraySize = words[addrArrayWord].intValueSafe();

      if (sigArraySize > MAX_SIZE || pkArraySize > MAX_SIZE || addrArraySize > MAX_SIZE
          || sigArraySize != pkArraySize || sigArraySize != addrArraySize) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      byte[][] signatures = extractBytesArrayChecked(words, sigArrayWord, data);
      byte[][] publicKeys = extractBytesArrayChecked(words, pkArrayWord, data);
      byte[][] addresses = PrecompiledContracts.extractBytes32Array(words, addrArrayWord);

      int cnt = signatures.length;
      if (cnt == 0 || publicKeys.length != cnt || addresses.length != cnt) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      byte[] res = new byte[WORD_SIZE];
      if (isConstantCall()) {
        for (int i = 0; i < cnt; i++) {
          if (verifyOne(signatures[i], publicKeys[i], hash, addresses[i])) {
            res[i] = 1;
          }
        }
      } else {
        CountDownLatch countDownLatch = new CountDownLatch(cnt);
        List<Future<PqVerifyResult>> futures = new ArrayList<>(cnt);

        for (int i = 0; i < cnt; i++) {
          Future<PqVerifyResult> future =
              workers.submit(new PqVerifyTask(countDownLatch, hash, signatures[i],
                      publicKeys[i], addresses[i], i));
          futures.add(future);
        }

        boolean withNoTimeout = countDownLatch
            .await(getCPUTimeLeftInNanoSecond(), TimeUnit.NANOSECONDS);

        if (!withNoTimeout) {
          cancelAll(futures);
          logger.info("BatchValidateMlDsa44 timeout");
          throw Program.Exception.notEnoughTime("call BatchValidateMlDsa44 precompile method");
        }

        for (Future<PqVerifyResult> future : futures) {
          PqVerifyResult r = future.get();
          if (r.success) {
            res[r.nonce] = 1;
          }
        }
      }
      return Pair.of(true, res);
    }

    private static boolean verifyOne(byte[] sig, byte[] pk, byte[] hash, byte[] expectedAddr) {
      if (pk == null || pk.length != PK_LEN || sig == null || sig.length != SIG_LEN) {
        return false;
      }
      try {
        byte[] derived = PQSchemeRegistry.computeAddress(PQScheme.ML_DSA_44, pk);
        if (!DataWord.equalAddressByteArray(derived, expectedAddr)) {
          return false;
        }
        return MLDSA44.verify(pk, hash, sig);
      } catch (Throwable t) {
        return false;
      }
    }

    @AllArgsConstructor
    private static class PqVerifyTask implements Callable<PqVerifyResult> {

      private CountDownLatch countDownLatch;
      private byte[] hash;
      private byte[] signature;
      private byte[] publicKey;
      private byte[] expectedAddr;
      private int nonce;

      @Override
      public PqVerifyResult call() {
        try {
          return new PqVerifyResult(
              verifyOne(signature, publicKey, hash, expectedAddr), nonce);
        } finally {
          countDownLatch.countDown();
        }
      }
    }

    @AllArgsConstructor
    private static class PqVerifyResult {

      private boolean success;
      private int nonce;
    }
  }


  /**
   * 0x0200001a ValidateMultiPQSig — algorithm-agnostic Permission multi-sign. Accepts
   * ECDSA plus any registered post-quantum scheme (FN-DSA-512, ML-DSA-44, ...)
   * against {@link Permission}{@code .keys[]} in a single call, dispatched per
   * entry by an explicit {@code uint8[]} scheme tag array (PQScheme number).
   *
   * <p>ABI:
   * <pre>
   *   validateMultiPqSign(
   *       address account,        // word[0]
   *       uint256 permissionId,   // word[1]
   *       bytes32 data,           // word[2]
   *       bytes[] ecdsaSigs,      // word[3] = offset; 65 B each
   *       uint8[] pqSchemes,      // word[4] = offset; FN_DSA_512=1, ML_DSA_44=2
   *       bytes[] pqSigs,         // word[5] = offset; per-scheme fixed slot
   *       bytes[] pqPks           // word[6] = offset; per-scheme exact length
   *   ) returns (bytes32)         // 1 on (totalWeight >= threshold), 0 otherwise
   * </pre>
   *
   * <p>Falcon sigs follow the EIP-8052 666-byte headerless slot convention
   * (matches 0x02000016/0x02000017): the slot holds {@code salt ‖ s2_compressed} with no
   * leading {@code 0x39}, zero-padded, the body ending at the last non-zero byte
   * (Falcon's {@code compressed_s2} always ends with a non-zero terminator);
   * {@link #falconSlotToHeaderedSig} re-inserts the header before verification.
   * Dilithium sigs are exactly 2420 B and Dilithium pks 1312 B.
   *
   * <p>{@code MAX_SIZE = 5} across ECDSA + PQ entries combined. Energy is
   * {@code ecdsaCnt × 1500 + sum_i pqEnergy(scheme_i)} with FN-DSA-512 = 220
   * and ML-DSA-44 = 470. Unknown tags are charged at worst case so an attacker
   * cannot underpay by encoding a tag the dispatcher will then reject.
   *
   * <p>Per-entry runtime gate: a Falcon entry returns {@code DATA_FALSE} when
   * {@code allowFnDsa512()} is false even though 0x0200001a itself is registered as
   * long as one PQ proposal is active. Same for ML-DSA-44.
   */
  public static class ValidateMultiPQSig extends PrecompiledContracts.PrecompiledContract {

    private static final int ECDSA_ENERGY_PER_SIGN = 1500;
    private static final int FN_DSA_512_ENERGY = 220;
    private static final int ML_DSA_44_ENERGY = 470;
    private static final int WORST_PQ_ENERGY = ML_DSA_44_ENERGY;
    private static final int WORST_ENERGY_PER_SIGN =
        StrictMathWrapper.max(ECDSA_ENERGY_PER_SIGN, WORST_PQ_ENERGY);
    private static final int MAX_SIZE = 5;
    // address, permissionId, data, ecdsaOff, schemeOff, pqSigOff, pqPkOff.
    private static final int ABI_HEAD_WORDS = 7;

    private static final Map<PQScheme, Integer> PQ_ENERGY;

    static {
      EnumMap<PQScheme, Integer> m = new EnumMap<>(PQScheme.class);
      m.put(PQScheme.FN_DSA_512, FN_DSA_512_ENERGY);
      m.put(PQScheme.ML_DSA_44, ML_DSA_44_ENERGY);
      PQ_ENERGY = m;
    }

    @Override
    public long getEnergyForData(byte[] data) {
      try {
        DataWord[] words = DataWord.parseArray(data);
        int ecdsaCnt = words[words[3].intValueSafe() / WORD_SIZE].intValueSafe();
        int schemeOff = words[4].intValueSafe() / WORD_SIZE;
        int pqCnt = words[schemeOff].intValueSafe();
        // Neither count is negative (intValueSafe clamps negatives to MAX_VALUE),
        // but MAX_VALUE + MAX_VALUE overflows int. Use long for the sum.
        long totalCnt = (long) ecdsaCnt + (long) pqCnt;
        if (totalCnt > MAX_SIZE) {
          return (long) MAX_SIZE * WORST_ENERGY_PER_SIGN;
        }
        long energy = (long) ecdsaCnt * ECDSA_ENERGY_PER_SIGN;
        for (int i = 0; i < pqCnt; i++) {
          int tag = words[schemeOff + 1 + i].intValueSafe();
          PQScheme s = PQScheme.forNumber(tag);
          Integer cost = s == null ? null : PQ_ENERGY.get(s);
          energy += cost == null ? WORST_PQ_ENERGY : cost;
        }
        return energy;
      } catch (Throwable t) {
        return (long) MAX_SIZE * WORST_ENERGY_PER_SIGN;
      }
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] rawData) {
      if (!isValidAbiHead(rawData, ABI_HEAD_WORDS)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      try {
        DataWord[] words = DataWord.parseArray(rawData);
        if (!isValidArrayOffset(words, 3, ABI_HEAD_WORDS)
            || !isValidArrayOffset(words, 4, ABI_HEAD_WORDS)
            || !isValidArrayOffset(words, 5, ABI_HEAD_WORDS)
            || !isValidArrayOffset(words, 6, ABI_HEAD_WORDS)) {
          return Pair.of(false, EMPTY_BYTE_ARRAY);
        }
        byte[] address = words[0].toTronAddress();
        int permissionId = words[1].intValueSafe();
        if (permissionId > VMConstant.MAX_PERMISSION_ID) {
          return Pair.of(false, EMPTY_BYTE_ARRAY);
        }
        byte[] data = words[2].getData();

        byte[] combine = ByteUtil.merge(address, ByteArray.fromInt(permissionId),
            data);
        byte[] hash = Sha256Hash.hash(CommonParameter
            .getInstance().isECKeyCryptoEngine(), combine);

        int ecdsaArrayWord = words[3].intValueSafe() / WORD_SIZE;
        int schemeArrayWord = words[4].intValueSafe() / WORD_SIZE;
        int pqSigArrayWord = words[5].intValueSafe() / WORD_SIZE;
        int pqPkArrayWord = words[6].intValueSafe() / WORD_SIZE;

        int ecdsaCnt = words[ecdsaArrayWord].intValueSafe();
        int schemeCnt = words[schemeArrayWord].intValueSafe();
        int pqSigCnt = words[pqSigArrayWord].intValueSafe();
        int pqPkCnt = words[pqPkArrayWord].intValueSafe();

        // Use long for the sum to defeat int overflow (e.g.
        // Integer.MAX_VALUE + 1 wraps to Integer.MIN_VALUE).
        long totalCnt = (long) ecdsaCnt + (long) schemeCnt;
        if (ecdsaCnt > MAX_SIZE || schemeCnt > MAX_SIZE
            || schemeCnt != pqSigCnt || schemeCnt != pqPkCnt
            || totalCnt == 0 || totalCnt > MAX_SIZE) {
          return Pair.of(false, EMPTY_BYTE_ARRAY);
        }

        byte[][] ecdsaSigs = PrecompiledContracts.extractSigArray(words,
            ecdsaArrayWord, rawData);
        byte[][] pqSigs = extractBytesArrayChecked(words, pqSigArrayWord, rawData);
        byte[][] pqPks = extractBytesArrayChecked(words, pqPkArrayWord, rawData);
        if (pqSigs.length != schemeCnt || pqPks.length != schemeCnt) {
          return Pair.of(false, EMPTY_BYTE_ARRAY);
        }
        int[] schemes = new int[schemeCnt];
        for (int i = 0; i < schemeCnt; i++) {
          schemes[i] = words[schemeArrayWord + 1 + i].intValueSafe();
        }

        AccountCapsule account = this.getDeposit().getAccount(address);
        if (account == null) {
          return Pair.of(true, DATA_FALSE);
        }
        Permission permission = account.getPermissionById(permissionId);
        if (permission == null) {
          return Pair.of(true, DATA_FALSE);
        }

        long totalWeight = 0L;
        List<byte[]> seenAddrs = new ArrayList<>();

        for (byte[] sign : ecdsaSigs) {
          byte[] recoveredAddr = PrecompiledContracts.recoverAddrBySign(sign, hash);
          if (ByteArray.matrixContains(seenAddrs, recoveredAddr)) {
            continue;
          }
          long weight = TransactionCapsule.getWeight(permission, recoveredAddr);
          if (weight == 0) {
            return Pair.of(true, DATA_FALSE);
          }
          totalWeight += weight;
          seenAddrs.add(recoveredAddr);
        }

        for (int i = 0; i < schemes.length; i++) {
          PQScheme scheme = PQScheme.forNumber(schemes[i]);
          if (scheme == null || scheme == PQScheme.UNKNOWN_PQ_SCHEME
              || !PQSchemeRegistry.contains(scheme)) {
            return Pair.of(false, EMPTY_BYTE_ARRAY);
          }
          // Per-entry runtime gate: the scheme's proposal must be active even
          // though 0x0200001a was registered under (allowFnDsa512 || allowMlDsa44).
          if (scheme == PQScheme.FN_DSA_512 && !VMConfig.allowFnDsa512()) {
            return Pair.of(true, DATA_FALSE);
          }
          if (scheme == PQScheme.ML_DSA_44 && !VMConfig.allowMlDsa44()) {
            return Pair.of(true, DATA_FALSE);
          }
          byte[] sig = pqSigs[i];
          byte[] pk = pqPks[i];
          int expectedPkLen = PQSchemeRegistry.getPublicKeyLength(scheme);
          int expectedSigSlot = scheme == PQScheme.FN_DSA_512
              ? FNDSA512.SIGNATURE_MAX_LENGTH - FNDSA512.SIGNATURE_HEADER_LENGTH
              : PQSchemeRegistry.getSignatureLength(scheme);
          if (pk == null || pk.length != expectedPkLen
              || sig == null || sig.length != expectedSigSlot) {
            return Pair.of(false, EMPTY_BYTE_ARRAY);
          }
          if (scheme == PQScheme.FN_DSA_512) {
            // The Falcon slot is the EIP-8052 headerless body; rebuild the
            // BC-headered sig (re-inserts 0x39) before verification.
            sig = falconSlotToHeaderedSig(sig, 0, sig.length);
            if (sig == null) {
              return Pair.of(false, EMPTY_BYTE_ARRAY);
            }
          }
          byte[] derivedAddr;
          try {
            derivedAddr = PQSchemeRegistry.computeAddress(scheme, pk);
          } catch (Throwable t) {
            return Pair.of(false, EMPTY_BYTE_ARRAY);
          }
          // Both Falcon and Dilithium signing are randomized → the same key
          // can produce many valid sigs for one message, so dedup keys on the
          // derived address only (the sig blob is not a stable identity).
          if (ByteArray.matrixContains(seenAddrs, derivedAddr)) {
            continue;
          }
          long weight = TransactionCapsule.getWeight(permission, derivedAddr);
          if (weight == 0) {
            return Pair.of(true, DATA_FALSE);
          }
          if (!PQSchemeRegistry.verify(scheme, pk, hash, sig)) {
            return Pair.of(true, DATA_FALSE);
          }
          totalWeight += weight;
          seenAddrs.add(derivedAddr);
        }

        if (totalWeight >= permission.getThreshold()) {
          return Pair.of(true, dataOne());
        }
      } catch (Throwable t) {
        if (t instanceof OutOfTimeException) {
          throw t;
        }
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      return Pair.of(true, DATA_FALSE);
    }
  }
}
