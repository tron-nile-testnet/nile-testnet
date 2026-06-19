package org.tron.core.vm;

import static java.util.Arrays.copyOfRange;
import static org.tron.common.crypto.ckzg4844.CKZG4844JNI.BLS_MODULUS;
import static org.tron.common.crypto.ckzg4844.CKZG4844JNI.FIELD_ELEMENTS_PER_BLOB;
import static org.tron.common.math.Maths.max;
import static org.tron.common.math.Maths.min;
import static org.tron.common.math.StrictMathWrapper.multiplyExact;
import static org.tron.common.math.StrictMathWrapper.subtractExact;
import static org.tron.common.runtime.vm.DataWord.WORD_SIZE;
import static org.tron.common.utils.BIUtil.addSafely;
import static org.tron.common.utils.BIUtil.isLessThan;
import static org.tron.common.utils.BIUtil.isZero;
import static org.tron.common.utils.ByteUtil.EMPTY_BYTE_ARRAY;
import static org.tron.common.utils.ByteUtil.bytesToBigInteger;
import static org.tron.common.utils.ByteUtil.longTo32Bytes;
import static org.tron.common.utils.ByteUtil.merge;
import static org.tron.common.utils.ByteUtil.numberOfLeadingZeros;
import static org.tron.common.utils.ByteUtil.parseBytes;
import static org.tron.common.utils.ByteUtil.parseWord;
import static org.tron.common.utils.ByteUtil.stripLeadingZeroes;
import static org.tron.core.config.Parameter.ChainConstant.TRX_PRECISION;
import static org.tron.core.vm.VMConstant.SIG_LENGTH;

import com.google.protobuf.ByteString;

import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.tron.common.crypto.ckzg4844.CKZG4844JNI;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.tron.common.crypto.Blake2bfMessageDigest;
import org.tron.common.crypto.Hash;
import org.tron.common.crypto.Rsv;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.SignatureInterface;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.zksnark.BN128;
import org.tron.common.crypto.zksnark.BN128Fp;
import org.tron.common.crypto.zksnark.BN128G1;
import org.tron.common.crypto.zksnark.BN128G2;
import org.tron.common.crypto.zksnark.Fp;
import org.tron.common.crypto.zksnark.PairingCheck;
import org.tron.common.es.ExecutorServiceManager;
import org.tron.common.math.StrictMathWrapper;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.utils.BIUtil;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.zksnark.JLibrustzcash;
import org.tron.common.zksnark.LibrustzcashParam;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.db.TransactionTrace;
import org.tron.core.exception.ZksnarkException;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.program.Program;
import org.tron.core.vm.program.Program.OutOfTimeException;
import org.tron.core.vm.repository.Repository;
import org.tron.core.vm.utils.FreezeV2Util;
import org.tron.core.vm.utils.MUtil;
import org.tron.core.vm.utils.VoteRewardUtil;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Permission;

@Slf4j(topic = "VM")
public class PrecompiledContracts {

  private static final ECRecover ecRecover = new ECRecover();
  private static final Sha256 sha256 = new Sha256();
  private static final Ripempd160 ripempd160 = new Ripempd160();
  private static final Identity identity = new Identity();
  private static final ModExp modExp = new ModExp();
  private static final BN128Addition altBN128Add = new BN128Addition();
  private static final BN128Multiplication altBN128Mul = new BN128Multiplication();
  private static final BN128Pairing altBN128Pairing = new BN128Pairing();

  private static final BatchValidateSign batchValidateSign = new BatchValidateSign();
  private static final ValidateMultiSign validateMultiSign = new ValidateMultiSign();

  private static final VerifyMintProof verifyMintProof = new VerifyMintProof();
  private static final VerifyTransferProof verifyTransferProof = new VerifyTransferProof();
  private static final VerifyBurnProof verifyBurnProof = new VerifyBurnProof();

  private static final MerkleHash merkleHash = new MerkleHash();

  private static final RewardBalance rewardBalance = new RewardBalance();
  private static final IsSrCandidate isSrCandidate = new IsSrCandidate();
  private static final VoteCount voteCount = new VoteCount();
  private static final UsedVoteCount usedVoteCount = new UsedVoteCount();
  private static final ReceivedVoteCount receivedVoteCount = new ReceivedVoteCount();
  private static final TotalVoteCount totalVoteCount = new TotalVoteCount();

  private static final EthRipemd160 ethRipemd160 = new EthRipemd160();
  private static final Blake2F blake2F = new Blake2F();
  private static final KZGPointEvaluation kzgPointEvaluation = new KZGPointEvaluation();
  private static final P256Verify p256Verify = new P256Verify();

  private static final VerifyFnDsa512 verifyFnDsa512 = new VerifyFnDsa512();
  private static final BatchValidateFnDsa512 batchValidateFnDsa512 = new BatchValidateFnDsa512();

  private static final VerifyMlDsa44 verifyMlDsa44 = new VerifyMlDsa44();
  private static final BatchValidateMlDsa44 batchValidateMlDsa44 = new BatchValidateMlDsa44();
  private static final ValidateMultiPQSig validateMultiPqSig = new ValidateMultiPQSig();

  // FreezeV2 PrecompileContracts
  private static final GetChainParameter getChainParameter = new GetChainParameter();
  private static final AvailableUnfreezeV2Size availableUnfreezeV2Size =
      new AvailableUnfreezeV2Size();
  private static final UnfreezableBalanceV2 unfreezableBalanceV2 = new UnfreezableBalanceV2();
  private static final ExpireUnfreezeBalanceV2 expireUnfreezeBalanceV2 =
      new ExpireUnfreezeBalanceV2();
  private static final DelegatableResource delegatableResource = new DelegatableResource();
  private static final ResourceV2 resourceV2 = new ResourceV2();
  private static final CheckUnDelegateResource checkUnDelegateResource =
      new CheckUnDelegateResource();
  private static final ResourceUsage resourceUsage = new ResourceUsage();
  private static final TotalResource totalResource = new TotalResource();
  private static final TotalDelegatedResource totalDelegatedResource = new TotalDelegatedResource();
  private static final TotalAcquiredResource totalAcquiredResource = new TotalAcquiredResource();

  private static final DataWord ecRecoverAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000001");
  private static final DataWord sha256Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000002");
  private static final DataWord ripempd160Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000003");
  private static final DataWord identityAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000004");
  private static final DataWord modExpAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000005");
  private static final DataWord altBN128AddAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000006");
  private static final DataWord altBN128MulAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000007");
  private static final DataWord altBN128PairingAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000008");
  private static final DataWord batchValidateSignAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000009");
  private static final DataWord validateMultiSignAddr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000000000a");
  private static final DataWord verifyMintProofAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000001");
  private static final DataWord verifyTransferProofAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000002");
  private static final DataWord verifyBurnProofAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000003");
  private static final DataWord merkleHashAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000004");
  private static final DataWord rewardBalanceAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000005");
  private static final DataWord isSrCandidateAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000006");
  private static final DataWord voteCountAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000007");
  private static final DataWord usedVoteCountAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000008");
  private static final DataWord receivedVoteCountAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000009");
  private static final DataWord totalVoteCountAddr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000100000a");

  // FreezeV2 PrecompileContracts
  private static final DataWord getChainParameterAddr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000100000b");

  private static final DataWord availableUnfreezeV2SizeAddr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000100000c");

  private static final DataWord unfreezableBalanceV2Addr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000100000d");

  private static final DataWord expireUnfreezeBalanceV2Addr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000100000e");

  private static final DataWord delegatableResourceAddr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000100000f");

  private static final DataWord resourceV2Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000010");

  private static final DataWord checkUnDelegateResourceAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000011");

  private static final DataWord resourceUsageAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000012");

  private static final DataWord totalResourceAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000013");

  private static final DataWord totalDelegatedResourceAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000014");

  private static final DataWord totalAcquiredResourceAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000001000015");

  private static final DataWord ethRipemd160Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000020003");
  private static final DataWord blake2FAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000020009");
  private static final DataWord p256VerifyAddr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000100");

  private static final DataWord kzgPointEvaluationAddr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000002000a");

  // EIP-8052 0x16: FN-DSA / Falcon-512 verify (FIPS-206 draft). Input layout:
  // [msg 32B | sig 666B (headerless salt‖s2 slot, zero-padded; body ends at last
  // non-zero byte) | pk 896B]. Total 1594 B. The slot holds the EIP-8052 headerless
  // signature (no 0x39 byte); the precompile re-inserts the header before verifying.
  private static final DataWord verifyFnDsa512Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000016");

  // 0x17: batch independent Falcon-512 verify — bitmap of (sig, pk, addr)
  // matches; mixed-algorithm contracts call 0x0A and 0x18 separately and OR
  // the bitmaps client-side.
  private static final DataWord batchValidateFnDsa512Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000017");

  // 0x18: ML-DSA-44 single verify (FIPS 204 / Dilithium-2).
  private static final DataWord verifyMlDsa44Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000018");

  // 0x19: batch independent ML-DSA-44 verify — bitmap output, same shape as 0x18.
  private static final DataWord batchValidateMlDsa44Addr = new DataWord(
      "0000000000000000000000000000000000000000000000000000000000000019");

  // 0x1a: algorithm-agnostic Permission multi-sign — accepts ECDSA and any
  // registered PQ scheme (Falcon-512, ML-DSA-44, ...) against the same
  // Permission.keys[] in one call, dispatched by an explicit per-entry scheme
  // tag. Replaces the earlier Falcon-only 0x17 and Dilithium-only draft, which
  // were never activated.
  private static final DataWord validateMultiPqSigAddr = new DataWord(
      "000000000000000000000000000000000000000000000000000000000000001a");

  public static PrecompiledContract getOptimizedContractForConstant(PrecompiledContract contract) {
    try {
      Constructor<?> constructor = contract.getClass().getDeclaredConstructor();
      return (PrecompiledContracts.PrecompiledContract) constructor.newInstance();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static PrecompiledContract getContractForAddress(DataWord address) {

    if (address == null) {
      return identity;
    }
    if (address.equals(ecRecoverAddr)) {
      return ecRecover;
    }
    if (address.equals(sha256Addr)) {
      return sha256;
    }
    if (address.equals(ripempd160Addr)) {
      return ripempd160;
    }
    if (address.equals(identityAddr)) {
      return identity;
    }
    // Byzantium precompiles
    if (address.equals(modExpAddr)) {
      return modExp;
    }
    if (address.equals(altBN128AddAddr)) {
      return altBN128Add;
    }
    if (address.equals(altBN128MulAddr)) {
      return altBN128Mul;
    }
    if (address.equals(altBN128PairingAddr)) {
      return altBN128Pairing;
    }
    if (VMConfig.allowTvmSolidity059() && address.equals(batchValidateSignAddr)) {
      return batchValidateSign;
    }
    if (VMConfig.allowTvmSolidity059() && address.equals(validateMultiSignAddr)) {
      return validateMultiSign;
    }
    if (VMConfig.allowShieldedTRC20Transaction() && address.equals(verifyMintProofAddr)) {
      return verifyMintProof;
    }
    if (VMConfig.allowShieldedTRC20Transaction() && address.equals(verifyTransferProofAddr)) {
      return verifyTransferProof;
    }
    if (VMConfig.allowShieldedTRC20Transaction() && address.equals(verifyBurnProofAddr)) {
      return verifyBurnProof;
    }
    if (VMConfig.allowShieldedTRC20Transaction() && address.equals(merkleHashAddr)) {
      return merkleHash;
    }
    if (VMConfig.allowTvmVote() && address.equals(rewardBalanceAddr)) {
      return rewardBalance;
    }
    if (VMConfig.allowTvmVote() && address.equals(isSrCandidateAddr)) {
      return isSrCandidate;
    }
    if (VMConfig.allowTvmVote() && address.equals(voteCountAddr)) {
      return voteCount;
    }
    if (VMConfig.allowTvmVote() && address.equals(usedVoteCountAddr)) {
      return usedVoteCount;
    }
    if (VMConfig.allowTvmVote() && address.equals(receivedVoteCountAddr)) {
      return receivedVoteCount;
    }
    if (VMConfig.allowTvmVote() && address.equals(totalVoteCountAddr)) {
      return totalVoteCount;
    }
    if (VMConfig.allowTvmCompatibleEvm() && address.equals(ethRipemd160Addr)) {
      return ethRipemd160;
    }
    if (VMConfig.allowTvmCompatibleEvm() && address.equals(blake2FAddr)) {
      return blake2F;
    }
    if (VMConfig.allowTvmBlob() && address.equals(kzgPointEvaluationAddr)) {
      return kzgPointEvaluation;
    }
    if (VMConfig.allowTvmOsaka() && address.equals(p256VerifyAddr)) {
      return p256Verify;
    }

    // 0x1a ValidateMultiPQSig is algorithm-agnostic and dispatches per entry,
    // so it is available whenever ANY registered PQ scheme is active. Per-entry
    // runtime checks inside the precompile still reject scheme tags whose
    // proposal hasn't passed.
    if (VMConfig.allowFnDsa512() || VMConfig.allowMlDsa44()) {
      if (address.equals(validateMultiPqSigAddr)) {
        return validateMultiPqSig;
      }
    }

    // FN-DSA-512 (Falcon): single verify and batch verify are gated by their
    // own proposal flag.
    if (VMConfig.allowFnDsa512()) {
      if (address.equals(verifyFnDsa512Addr)) {
        return verifyFnDsa512;
      }
      if (address.equals(batchValidateFnDsa512Addr)) {
        return batchValidateFnDsa512;
      }
    }

    // ML-DSA-44 (FIPS 204 / Dilithium-2): single verify and batch verify are
    // gated by their own proposal flag.
    if (VMConfig.allowMlDsa44()) {
      if (address.equals(verifyMlDsa44Addr)) {
        return verifyMlDsa44;
      }
      if (address.equals(batchValidateMlDsa44Addr)) {
        return batchValidateMlDsa44;
      }
    }

    if (VMConfig.allowTvmFreezeV2()) {
      if (address.equals(getChainParameterAddr)) {
        return getChainParameter;
      }
      if (address.equals(availableUnfreezeV2SizeAddr)) {
        return availableUnfreezeV2Size;
      }
      if (address.equals(unfreezableBalanceV2Addr)) {
        return unfreezableBalanceV2;
      }
      if (address.equals(expireUnfreezeBalanceV2Addr)) {
        return expireUnfreezeBalanceV2;
      }
      if (address.equals(delegatableResourceAddr)) {
        return delegatableResource;
      }
      if (address.equals(resourceV2Addr)) {
        return resourceV2;
      }
      if (address.equals(checkUnDelegateResourceAddr)) {
        return checkUnDelegateResource;
      }
      if (address.equals(resourceUsageAddr)) {
        return resourceUsage;
      }
      if (address.equals(totalResourceAddr)) {
        return totalResource;
      }
      if (address.equals(totalDelegatedResourceAddr)) {
        return totalDelegatedResource;
      }
      if (address.equals(totalAcquiredResourceAddr)) {
        return totalAcquiredResource;
      }
    }

    return null;
  }

  private static byte[] encodeRes(byte[] w1, byte[] w2) {

    byte[] res = new byte[64];

    w1 = stripLeadingZeroes(w1);
    w2 = stripLeadingZeroes(w2);

    System.arraycopy(w1, 0, res, 32 - w1.length, w1.length);
    System.arraycopy(w2, 0, res, 64 - w2.length, w2.length);

    return res;
  }

  private static byte[] encodeMultiRes(byte[]... words) {
    if (words == null) {
      return null;
    }
    if (words.length == 1) {
      return words[0];
    }

    byte[] res = new byte[words.length * 32];

    for (int i = 0; i < words.length; i++) {
      byte[] word = stripLeadingZeroes(words[i]);

      System.arraycopy(word, 0, res, 32 * (i + 1) - word.length, word.length);
    }

    return res;
  }

  private static byte[] recoverAddrBySign(byte[] sign, byte[] hash) {
    byte[] out = null;
    if (ArrayUtils.isEmpty(sign) || sign.length < 65) {
      return new byte[0];
    }
    try {
      Rsv rsv = Rsv.fromSignature(sign);
      SignatureInterface signature = SignUtils.fromComponents(rsv.getR(), rsv.getS(), rsv.getV(),
          CommonParameter.getInstance().isECKeyCryptoEngine());
      if (signature.validateComponents()) {
        out = SignUtils.signatureToAddress(hash, signature,
            CommonParameter.getInstance().isECKeyCryptoEngine());
      }
    } catch (Throwable any) {
      logger.info("ECRecover error", any.getMessage());
    }
    return out;
  }

  private static byte[][] extractBytes32Array(DataWord[] words, int offset) {
    int len = words[offset].intValueSafe();
    byte[][] bytes32Array = new byte[len][];
    for (int i = 0; i < len; i++) {
      bytes32Array[i] = words[offset + i + 1].getData();
    }
    return bytes32Array;
  }

  private static byte[][] extractBytesArray(DataWord[] words, int offset, byte[] data) {
    if (offset > words.length - 1) {
      return new byte[0][];
    }
    int len = words[offset].intValueSafe();
    byte[][] bytesArray = new byte[len][];
    for (int i = 0; i < len; i++) {
      int bytesOffset = words[offset + i + 1].intValueSafe() / WORD_SIZE;
      int bytesLen = words[offset + bytesOffset + 1].intValueSafe();
      bytesArray[i] = extractBytes(data, (bytesOffset + offset + 2) * WORD_SIZE,
          bytesLen);
    }
    return bytesArray;
  }

  private static byte[][] extractBytesArrayChecked(DataWord[] words, int offset, byte[] data) {
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
      bytesArray[i] = extractBytes(data, (int) fromL, bytesLen);
    }
    return bytesArray;
  }

  private static byte[][] extractSigArray(DataWord[] words, int offset, byte[] data) {
    if (offset > words.length - 1) {
      return new byte[0][];
    }
    int len = words[offset].intValueSafe();
    byte[][] bytesArray = new byte[len][];
    for (int i = 0; i < len; i++) {
      int bytesOffset = words[offset + i + 1].intValueSafe() / WORD_SIZE;
      bytesArray[i] = extractBytes(data, (bytesOffset + offset + 2) * WORD_SIZE,
          SIG_LENGTH);
    }
    return bytesArray;
  }

  private static byte[] extractBytes(byte[] data, int offset, int len) {
    return Arrays.copyOfRange(data, offset, offset + len);
  }

  private static boolean isValidAbiEncoding(byte[] data, int headerWords, int itemWords) {
    if (data == null || data.length % WORD_SIZE != 0) {
      return false;
    }
    long tail = subtractExact(data.length, multiplyExact(headerWords, WORD_SIZE));
    return tail > 0 && tail % multiplyExact(itemWords, WORD_SIZE) == 0;
  }

  /**
   * Structural pre-check for ABI head: word-aligned length and room for the
   * fixed head. The PQ precompiles cannot reuse {@link #isValidAbiEncoding}
   * because their {@code bytes[]} entries (PQ signatures, 1..752 bytes) are
   * variable-length, so the trailing divisibility check does not apply.
   */
  private static boolean isValidAbiHead(byte[] data, int headWords) {
    return data != null
        && data.length % WORD_SIZE == 0
        && data.length >= multiplyExact(headWords, WORD_SIZE);
  }

  /**
   * Verifies that the array offset stored at {@code words[offsetWordIndex]} is
   * word-aligned, falls inside the dynamic data region (≥ head), and points to
   * a length word that still fits inside {@code words}. Sister check to
   * {@link #isValidAbiEncoding} for ABIs whose items are not uniform width.
   */
  private static boolean isValidArrayOffset(DataWord[] words, int offsetWordIndex, int headWords) {
    long offsetBytes = words[offsetWordIndex].longValueSafe();
    if (offsetBytes < (long) headWords * WORD_SIZE || offsetBytes % WORD_SIZE != 0) {
      return false;
    }
    long lengthWordIdx = offsetBytes / WORD_SIZE;
    return lengthWordIdx < words.length;
  }

  /**
   * Best-effort cancellation of all submitted batch-verify tasks. Tasks that
   * have not yet started execution are removed from the worker queue; tasks
   * already running receive an interrupt but BouncyCastle's PQ verify routines
   * do not poll the interrupt flag and will run to completion.
   */
  private static void cancelAll(List<? extends Future<?>> futures) {
    for (Future<?> f : futures) {
      f.cancel(true);
    }
  }

  /**
   * Returns the logical Falcon-512 signature length packed at the start of a
   * fixed slot {@code data[from..to)}: the offset of the last non-zero byte
   * (exclusive). Canonical Falcon encodings always end in a non-zero byte
   * ({@code compressed_s2}'s unary terminator), so anything beyond is zero
   * padding. Returns 0 if the slot is all zero. Shared by 0x16, 0x18, and 0x1a
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
   * Shared by 0x16, 0x18, and 0x1a.
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

  public abstract static class PrecompiledContract {

    protected static final byte[] DATA_FALSE = new byte[WORD_SIZE];
    private byte[] callerAddress;
    private Repository deposit;
    private ProgramResult result;
    @Setter
    @Getter
    private boolean isConstantCall;
    @Getter
    @Setter
    private long vmShouldEndInUs;

    public abstract long getEnergyForData(byte[] data);

    public abstract Pair<Boolean, byte[]> execute(byte[] data);

    public void setRepository(Repository deposit) {
      this.deposit = deposit;
    }

    public byte[] getCallerAddress() {
      return callerAddress.clone();
    }

    public void setCallerAddress(byte[] callerAddress) {
      this.callerAddress = callerAddress.clone();
    }

    public Repository getDeposit() {
      return deposit;
    }

    public ProgramResult getResult() {
      return result;
    }

    public void setResult(ProgramResult result) {
      this.result = result;
    }

    protected long getCPUTimeLeftInNanoSecond() {
      long left = getVmShouldEndInUs() * VMConstant.ONE_THOUSAND - System.nanoTime();
      if (left <= 0) {
        throw Program.Exception.notEnoughTime("call");
      } else {
        return left;
      }
    }

    protected byte[] dataOne() {
      byte[] ret = new byte[WORD_SIZE];
      ret[31] = 1;
      return ret;
    }

    protected byte[] dataBoolean(boolean result) {
      if (result) {
        return DataWord.ONE().getData();
      }
      return DataWord.ZERO().getData();
    }
  }

  public static class Identity extends PrecompiledContract {

    public Identity() {
    }

    @Override
    public long getEnergyForData(byte[] data) {

      // energy charge for the execution:
      // minimum 1 and additional 1 for each 32 bytes word (round  up)
      if (data == null) {
        return 15;
      }
      return 15L + (data.length + 31) / 32 * 3;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      return Pair.of(true, data);
    }
  }

  public static class Sha256 extends PrecompiledContract {


    @Override
    public long getEnergyForData(byte[] data) {

      // energy charge for the execution:
      // minimum 50 and additional 50 for each 32 bytes word (round  up)
      if (data == null) {
        return 60;
      }
      return 60L + (data.length + 31) / 32 * 12;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {

      if (data == null) {
        return Pair.of(true, Sha256Hash.hash(CommonParameter
            .getInstance().isECKeyCryptoEngine(), EMPTY_BYTE_ARRAY));
      }
      return Pair.of(true, Sha256Hash.hash(CommonParameter
          .getInstance().isECKeyCryptoEngine(), data));
    }
  }

  public static class Ripempd160 extends PrecompiledContract {


    @Override
    public long getEnergyForData(byte[] data) {

      // TODO #POC9 Replace magic numbers with constants
      // energy charge for the execution:
      // minimum 50 and additional 50 for each 32 bytes word (round  up)
      if (data == null) {
        return 600;
      }
      return 600L + (data.length + 31) / 32 * 120;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      byte[] target = new byte[20];
      if (data == null) {
        data = EMPTY_BYTE_ARRAY;
      }

      byte[] orig = Sha256Hash.hash(CommonParameter.getInstance()
          .isECKeyCryptoEngine(), data);
      System.arraycopy(orig, 0, target, 0, 20);
      return Pair.of(true, Sha256Hash.hash(CommonParameter.getInstance()
          .isECKeyCryptoEngine(), target));
    }
  }

  public static class ECRecover extends PrecompiledContract {

    private static boolean validateV(byte[] v) {
      for (int i = 0; i < v.length - 1; i++) {
        if (v[i] != 0) {
          return false;
        }
      }
      return true;
    }

    @Override
    public long getEnergyForData(byte[] data) {
      return 3000;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {

      byte[] h = new byte[32];
      byte[] v = new byte[32];
      byte[] r = new byte[32];
      byte[] s = new byte[32];

      DataWord out = null;

      try {
        System.arraycopy(data, 0, h, 0, 32);
        System.arraycopy(data, 32, v, 0, 32);
        System.arraycopy(data, 64, r, 0, 32);

        int sLength = data.length < 128 ? data.length - 96 : 32;
        System.arraycopy(data, 96, s, 0, sLength);

        SignatureInterface signature = SignUtils.fromComponents(r, s, v[31]
            , CommonParameter.getInstance().isECKeyCryptoEngine());
        if (validateV(v) && signature.validateComponents()) {
          out = new DataWord(SignUtils.signatureToAddress(h, signature
              , CommonParameter.getInstance().isECKeyCryptoEngine()));
        }
      } catch (Throwable any) {
      }

      if (out == null) {
        return Pair.of(true, EMPTY_BYTE_ARRAY);
      } else {
        return Pair.of(true, out.getData());
      }
    }
  }

  /**
   * Computes modular exponentiation on big numbers
   * <p>
   * format of data[] array: [length_of_BASE] [length_of_EXPONENT] [length_of_MODULUS] [BASE]
   * [EXPONENT] [MODULUS] where every length is a 32-byte left-padded integer representing the
   * number of bytes. Call data is assumed to be infinitely right-padded with zero bytes.
   * <p>
   * Returns an output as a byte array with the same length as the modulus
   */
  public static class ModExp extends PrecompiledContract {

    private static final BigInteger GQUAD_DIVISOR = BigInteger.valueOf(20);

    private static final int ARGS_OFFSET = 32 * 3; // addresses length part

    private static final int UPPER_BOUND = 1024;

    private static final long MIN_ENERGY_TIP7883 = 500L;

    private static final BigInteger MIN_ENERGY_TIP7883_BI =
        BigInteger.valueOf(MIN_ENERGY_TIP7883);

    @Override
    public long getEnergyForData(byte[] data) {

      if (data == null) {
        data = EMPTY_BYTE_ARRAY;
      }

      int baseLen = parseLen(data, 0);
      int expLen = parseLen(data, 1);
      int modLen = parseLen(data, 2);

      byte[] expHighBytes = parseBytes(data, addSafely(ARGS_OFFSET, baseLen), min(expLen, 32,
          VMConfig.disableJavaLangMath()));

      if (VMConfig.allowTvmOsaka()) {
        return getEnergyTIP7883(baseLen, modLen, expHighBytes, expLen);
      }

      long multComplexity = getMultComplexity(max(baseLen, modLen, VMConfig.disableJavaLangMath()));
      long adjExpLen = getAdjustedExponentLength(expHighBytes, expLen);

      // use big numbers to stay safe in case of overflow
      BigInteger energy = BigInteger.valueOf(multComplexity)
          .multiply(BigInteger.valueOf(max(adjExpLen, 1, VMConfig.disableJavaLangMath())))
          .divide(GQUAD_DIVISOR);

      return isLessThan(energy, BigInteger.valueOf(Long.MAX_VALUE)) ? energy.longValueExact()
          : Long.MAX_VALUE;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {

      if (data == null) {
        return Pair.of(true, EMPTY_BYTE_ARRAY);
      }

      int baseLen = parseLen(data, 0);
      int expLen = parseLen(data, 1);
      int modLen = parseLen(data, 2);

      if (VMConfig.allowTvmOsaka()
          && (baseLen > UPPER_BOUND || expLen > UPPER_BOUND || modLen > UPPER_BOUND)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      if (baseLen == 0 && modLen == 0 && expLen > UPPER_BOUND) {
        MUtil.checkCPUTimeForModExp();
      }

      BigInteger base = parseArg(data, ARGS_OFFSET, baseLen);
      BigInteger exp = parseArg(data, addSafely(ARGS_OFFSET, baseLen), expLen);
      BigInteger mod = parseArg(data, addSafely(addSafely(ARGS_OFFSET, baseLen), expLen), modLen);

      // check if modulus is zero
      if (isZero(mod)) {
        if (VMConfig.allowTvmOsaka()) {
          return Pair.of(true, new byte[modLen]);
        }
        return Pair.of(true, EMPTY_BYTE_ARRAY);
      }

      byte[] res = stripLeadingZeroes(base.modPow(exp, mod).toByteArray());

      // adjust result to the same length as the modulus has
      if (res.length < modLen) {

        byte[] adjRes = new byte[modLen];
        System.arraycopy(res, 0, adjRes, modLen - res.length, res.length);

        return Pair.of(true, adjRes);

      } else {
        return Pair.of(true, res);
      }
    }

    private long getMultComplexity(long x) {

      long x2 = x * x;

      if (x <= 64) {
        return x2;
      }
      if (x <= 1024) {
        return x2 / 4 + 96 * x - 3072;
      }

      return x2 / 16 + 480 * x - 199680;
    }

    private long getAdjustedExponentLength(byte[] expHighBytes, long expLen) {

      int leadingZeros = numberOfLeadingZeros(expHighBytes);
      int highestBit = 8 * expHighBytes.length - leadingZeros;

      // set index basement to zero
      if (highestBit > 0) {
        highestBit--;
      }

      if (expLen <= 32) {
        return highestBit;
      } else {
        return 8 * (expLen - 32) + highestBit;
      }
    }

    /**
     * TIP-7883: ModExp gas cost increase.
     * New pricing formula with higher minimum cost and no divisor.
     */
    private long getEnergyTIP7883(int baseLen, int modLen, byte[] expHighBytes, int expLen) {
      long multComplexity = getMultComplexityTIP7883(baseLen, modLen);
      long iterCount = getIterationCountTIP7883(expHighBytes, expLen);

      // use big numbers to stay safe in case of overflow
      BigInteger energy = BigInteger.valueOf(multComplexity)
          .multiply(BigInteger.valueOf(iterCount));

      if (isLessThan(energy, MIN_ENERGY_TIP7883_BI)) {
        return MIN_ENERGY_TIP7883;
      }

      return isLessThan(energy, BigInteger.valueOf(Long.MAX_VALUE)) ? energy.longValueExact()
          : Long.MAX_VALUE;
    }

    /**
     * TIP-7883: New multiplication complexity formula.
     * Minimal complexity of 16; doubled complexity for base/modulus > 32 bytes.
     */
    private long getMultComplexityTIP7883(int baseLen, int modLen) {
      long maxLength = StrictMathWrapper.max(baseLen, modLen);
      if (maxLength <= 32) {
        return 16;
      }
      // ceil(maxLength / 8)
      long words = StrictMathWrapper.floorDiv(StrictMathWrapper.addExact(maxLength, 7L), 8L);
      return StrictMathWrapper.multiplyExact(2L, StrictMathWrapper.multiplyExact(words, words));
    }

    /**
     * TIP-7883: New iteration count formula.
     * Multiplier for exponents > 32 bytes increased from 8 to 16.
     */
    private long getIterationCountTIP7883(byte[] expHighBytes, long expLen) {
      int leadingZeros = numberOfLeadingZeros(expHighBytes);
      long highestBit = StrictMathWrapper.subtractExact(
          StrictMathWrapper.multiplyExact(8L, expHighBytes.length), leadingZeros);

      if (highestBit > 0) {
        highestBit = StrictMathWrapper.subtractExact(highestBit, 1L);
      }

      long iterCount;
      if (expLen <= 32) {
        iterCount = highestBit;
      } else {
        iterCount = StrictMathWrapper.addExact(
            StrictMathWrapper.multiplyExact(16L, StrictMathWrapper.subtractExact(expLen, 32L)),
            highestBit);
      }

      return StrictMathWrapper.max(iterCount, 1L);
    }

    private int parseLen(byte[] data, int idx) {
      byte[] bytes = parseBytes(data, 32 * idx, 32);
      return new DataWord(bytes).intValueSafe();
    }

    private BigInteger parseArg(byte[] data, int offset, int len) {
      byte[] bytes = parseBytes(data, offset, len);
      return bytesToBigInteger(bytes);
    }
  }

  /**
   * Computes point addition on Barreto–Naehrig curve. See {@link BN128Fp} for details<br/> <br/>
   * <p>
   * input data[]:<br/> two points encoded as (x, y), where x and y are 32-byte left-padded
   * integers,<br/> if input is shorter than expected, it's assumed to be right-padded with zero
   * bytes<br/> <br/>
   * <p>
   * output:<br/> resulting point (x', y'), where x and y encoded as 32-byte left-padded
   * integers<br/>
   */
  public static class BN128Addition extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      if (VMConfig.allowTvmIstanbul()) {
        return getEnergyForDataIstanbul(data);
      }
      return 500;
    }

    private long getEnergyForDataIstanbul(byte[] data) {
      return 150;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {

      if (data == null) {
        data = EMPTY_BYTE_ARRAY;
      }

      byte[] x1 = parseWord(data, 0);
      byte[] y1 = parseWord(data, 1);

      byte[] x2 = parseWord(data, 2);
      byte[] y2 = parseWord(data, 3);

      BN128<Fp> p1 = BN128Fp.create(x1, y1);
      if (p1 == null) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      BN128<Fp> p2 = BN128Fp.create(x2, y2);
      if (p2 == null) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      BN128<Fp> res = p1.add(p2).toEthNotation();

      return Pair.of(true, encodeRes(res.x().bytes(), res.y().bytes()));
    }
  }

  /**
   * Computes multiplication of scalar value on a point belonging to Barreto–Naehrig curve. See
   * {@link BN128Fp} for details<br/> <br/>
   * <p>
   * input data[]:<br/> point encoded as (x, y) is followed by scalar s, where x, y and s are
   * 32-byte left-padded integers,<br/> if input is shorter than expected, it's assumed to be
   * right-padded with zero bytes<br/> <br/>
   * <p>
   * output:<br/> resulting point (x', y'), where x and y encoded as 32-byte left-padded
   * integers<br/>
   */
  public static class BN128Multiplication extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      if (VMConfig.allowTvmIstanbul()) {
        return getEnergyForDataIstanbul(data);
      }
      return 40000;
    }

    private long getEnergyForDataIstanbul(byte[] data) {
      return 6000;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {

      if (data == null) {
        data = EMPTY_BYTE_ARRAY;
      }

      byte[] x = parseWord(data, 0);
      byte[] y = parseWord(data, 1);

      byte[] s = parseWord(data, 2);

      BN128<Fp> p = BN128Fp.create(x, y);
      if (p == null) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      BN128<Fp> res = p.mul(BIUtil.toBI(s)).toEthNotation();

      return Pair.of(true, encodeRes(res.x().bytes(), res.y().bytes()));
    }
  }

  /**
   * Computes pairing check. <br/> See {@link PairingCheck} for details.<br/> <br/>
   * <p>
   * Input data[]: <br/> an array of points (a1, b1, ... , ak, bk), <br/> where "ai" is a point of
   * {@link BN128Fp} curve and encoded as two 32-byte left-padded integers (x; y) <br/> "bi" is a
   * point of {@link BN128G2} curve and encoded as four 32-byte left-padded integers {@code (ai + b;
   * ci + d)}, each coordinate of the point is a big-endian {@link } number, so {@code b} precedes
   * {@code a} in the encoding: {@code (b, a; d, c)} <br/> thus each pair (ai, bi) has 192 bytes
   * length, if 192 is not a multiple of {@code data.length} then execution fails <br/> the number
   * of pairs is derived from input length by dividing it by 192 (the length of a pair) <br/> <br/>
   * <p>
   * output: <br/> pairing product which is either 0 or 1, encoded as 32-byte left-padded integer
   * <br/>
   */
  public static class BN128Pairing extends PrecompiledContract {

    private static final int PAIR_SIZE = 192;

    @Override
    public long getEnergyForData(byte[] data) {
      if (VMConfig.allowTvmIstanbul()) {
        return getEnergyForDataIstanbul(data);
      }
      if (data == null) {
        return 100000;
      }
      return 80000L * (data.length / PAIR_SIZE) + 100000;
    }

    private long getEnergyForDataIstanbul(byte[] data) {
      if (data == null) {
        return 45000;
      }
      return 34000L * (data.length / PAIR_SIZE) + 45000;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {

      if (data == null) {
        data = EMPTY_BYTE_ARRAY;
      }

      // fail if input len is not a multiple of PAIR_SIZE
      if (data.length % PAIR_SIZE > 0) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }

      PairingCheck check = PairingCheck.create();

      // iterating over all pairs
      for (int offset = 0; offset < data.length; offset += PAIR_SIZE) {

        Pair<BN128G1, BN128G2> pair = decodePair(data, offset);

        // fail if decoding has failed
        if (pair == null) {
          return Pair.of(false, EMPTY_BYTE_ARRAY);
        }

        check.addPair(pair.getLeft(), pair.getRight());
      }

      check.run();
      int result = check.result();

      return Pair.of(true, new DataWord(result).getData());
    }

    private Pair<BN128G1, BN128G2> decodePair(byte[] in, int offset) {

      byte[] x = parseWord(in, offset, 0);
      byte[] y = parseWord(in, offset, 1);

      BN128G1 p1 = BN128G1.create(x, y);

      // fail if point is invalid
      if (p1 == null) {
        return null;
      }

      // (b, a)
      byte[] b = parseWord(in, offset, 2);
      byte[] a = parseWord(in, offset, 3);

      // (d, c)
      byte[] d = parseWord(in, offset, 4);
      byte[] c = parseWord(in, offset, 5);

      BN128G2 p2 = BN128G2.create(a, b, c, d);

      // fail if point is invalid
      if (p2 == null) {
        return null;
      }

      return Pair.of(p1, p2);
    }
  }

  public static class ValidateMultiSign extends PrecompiledContract {

    private static final int ENGERYPERSIGN = 1500;
    private static final int MAX_SIZE = 5;
    private static final int ABI_HEADER_WORDS = 5;
    private static final int ABI_ITEM_WORDS = 5;


    @Override
    public long getEnergyForData(byte[] data) {
      long cnt = (data.length / WORD_SIZE - 5) / 5;
      // one sign 1500, half of ecrecover
      return cnt * ENGERYPERSIGN;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] rawData) {
      if (VMConfig.allowTvmOsaka()
          && !isValidAbiEncoding(rawData, ABI_HEADER_WORDS, ABI_ITEM_WORDS)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      DataWord[] words = DataWord.parseArray(rawData);
      byte[] address = words[0].toTronAddress();
      int permissionId = words[1].intValueSafe();
      byte[] data = words[2].getData();

      byte[] combine = ByteUtil.merge(address, ByteArray.fromInt(permissionId), data);
      byte[] hash = Sha256Hash.hash(CommonParameter
          .getInstance().isECKeyCryptoEngine(), combine);

      if (VMConfig.allowTvmSelfdestructRestriction()) {
        int sigArraySize = words[words[3].intValueSafe() / WORD_SIZE].intValueSafe();
        if (sigArraySize > MAX_SIZE) {
          return Pair.of(true, DATA_FALSE);
        }
      }
      byte[][] signatures = VMConfig.allowTvmSelfdestructRestriction() ?
          extractSigArray(words, words[3].intValueSafe() / WORD_SIZE, rawData) :
          extractBytesArray(words, words[3].intValueSafe() / WORD_SIZE, rawData);

      if (signatures.length == 0 || signatures.length > MAX_SIZE) {
        return Pair.of(true, DATA_FALSE);
      }

      AccountCapsule account = this.getDeposit().getAccount(address);
      if (account != null) {
        try {
          Permission permission = account.getPermissionById(permissionId);
          if (permission != null) {
            //calculate weight
            long totalWeight = 0L;
            List<byte[]> executedSignList = new ArrayList<>();
            for (byte[] sign : signatures) {
              byte[] recoveredAddr = recoverAddrBySign(sign, hash);

              sign = merge(recoveredAddr, sign);
              if (ByteArray.matrixContains(executedSignList, recoveredAddr)) {
                if (ByteArray.matrixContains(executedSignList, sign)) {
                  continue;
                }
                MUtil.checkCPUTime();
              }
              long weight = TransactionCapsule.getWeight(permission, recoveredAddr);
              if (weight == 0) {
                //incorrect sign
                return Pair.of(true, DATA_FALSE);
              }
              totalWeight += weight;
              executedSignList.add(sign);
              executedSignList.add(recoveredAddr);
            }

            if (totalWeight >= permission.getThreshold()) {
              return Pair.of(true, dataOne());
            }
          }
        } catch (Throwable t) {
          if (t instanceof OutOfTimeException) {
            throw t;
          }
          logger.info("ValidateMultiSign error:{}", t.getMessage());
        }
      }
      return Pair.of(true, DATA_FALSE);
    }
  }

  public static class BatchValidateSign extends PrecompiledContract {

    private static final ExecutorService workers;
    private static final String workersName = "validate-sign-contract";
    private static final int ENGERYPERSIGN = 1500;
    private static final int MAX_SIZE = 16;
    private static final int ABI_HEADER_WORDS = 5;
    private static final int ABI_ITEM_WORDS = 6;

    static {
      workers = ExecutorServiceManager.newFixedThreadPool(workersName,
          Runtime.getRuntime().availableProcessors() / 2 + 1);
    }

    @Override
    public long getEnergyForData(byte[] data) {
      long cnt = (data.length / WORD_SIZE - 5) / 6;
      // one sign 1500, half of ecrecover
      return cnt * ENGERYPERSIGN;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      try {
        return doExecute(data);
      } catch (Throwable t) {
        if (t instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        return Pair.of(true, new byte[WORD_SIZE]);
      }
    }

    private Pair<Boolean, byte[]> doExecute(byte[] data)
        throws InterruptedException, ExecutionException {
      if (VMConfig.allowTvmOsaka()
          && !isValidAbiEncoding(data, ABI_HEADER_WORDS, ABI_ITEM_WORDS)) {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
      DataWord[] words = DataWord.parseArray(data);
      byte[] hash = words[0].getData();

      if (VMConfig.allowTvmSelfdestructRestriction()) {
        int sigArraySize = words[words[1].intValueSafe() / WORD_SIZE].intValueSafe();
        int addrArraySize = words[words[2].intValueSafe() / WORD_SIZE].intValueSafe();
        if (sigArraySize > MAX_SIZE || addrArraySize > MAX_SIZE) {
          return Pair.of(true, DATA_FALSE);
        }
      }

      byte[][] signatures = VMConfig.allowTvmSelfdestructRestriction() ?
          extractSigArray(words, words[1].intValueSafe() / WORD_SIZE, data) :
          extractBytesArray(words, words[1].intValueSafe() / WORD_SIZE, data);
      byte[][] addresses = extractBytes32Array(
          words, words[2].intValueSafe() / WORD_SIZE);
      int cnt = signatures.length;
      if (cnt == 0 || cnt > MAX_SIZE || signatures.length != addresses.length) {
        return Pair.of(true, DATA_FALSE);
      }
      byte[] res = new byte[WORD_SIZE];
      if (isConstantCall()) {
        //for constant call not use thread pool to avoid potential effect
        for (int i = 0; i < cnt; i++) {
          if (DataWord
              .equalAddressByteArray(addresses[i], recoverAddrBySign(signatures[i], hash))) {
            res[i] = 1;
          }
        }
      } else {
        // add check
        CountDownLatch countDownLatch = new CountDownLatch(cnt);
        List<Future<RecoverAddrResult>> futures = new ArrayList<>(cnt);

        for (int i = 0; i < cnt; i++) {
          Future<RecoverAddrResult> future = workers
              .submit(new RecoverAddrTask(countDownLatch, hash, signatures[i], i));
          futures.add(future);
        }
        boolean withNoTimeout = countDownLatch
            .await(getCPUTimeLeftInNanoSecond(), TimeUnit.NANOSECONDS);

        if (!withNoTimeout) {
          logger.info("BatchValidateSign timeout");
          throw Program.Exception.notEnoughTime("call BatchValidateSign precompile method");
        }

        for (Future<RecoverAddrResult> future : futures) {
          RecoverAddrResult result = future.get();
          int index = result.nonce;
          if (DataWord.equalAddressByteArray(result.addr, addresses[index])) {
            res[index] = 1;
          }
        }
      }
      return Pair.of(true, res);
    }

    @AllArgsConstructor
    private static class RecoverAddrTask implements Callable<RecoverAddrResult> {

      private CountDownLatch countDownLatch;
      private byte[] hash;
      private byte[] signature;
      private int nonce;

      @Override
      public RecoverAddrResult call() {
        try {
          return new RecoverAddrResult(recoverAddrBySign(this.signature, this.hash), nonce);
        } finally {
          countDownLatch.countDown();
        }
      }
    }

    @AllArgsConstructor
    private static class RecoverAddrResult {

      private byte[] addr;
      private int nonce;
    }
  }

  public abstract static class VerifyProof extends PrecompiledContract {

    protected static final long TREE_WIDTH = 1L << 32;
    protected static final byte[][] UNCOMMITTED = new byte[32][32];

    static {
      UNCOMMITTED[0] = ByteArray.fromHexString(
          "0100000000000000000000000000000000000000000000000000000000000000");
      try {
        for (int i = 0; i < 31; i++) {
          JLibrustzcash.librustzcashMerkleHash(
              new LibrustzcashParam.MerkleHashParams(
                  i, UNCOMMITTED[i], UNCOMMITTED[i], UNCOMMITTED[i + 1]));
        }
      } catch (Throwable any) {
        logger.info("Initialize UNCOMMITTED array failed:{}", any.getMessage());
      }
    }

    protected long parseLong(byte[] data, int idx) {
      byte[] bytes = parseBytes(data, idx, 32);
      return new DataWord(bytes).longValueSafe();
    }

    protected int parseInt(byte[] data, int idx) {
      byte[] bytes = parseBytes(data, idx, 32);
      return new DataWord(bytes).intValueSafe();
    }

    private int getFrontierSlot(long leafIndex) {
      int slot = 0;
      if (leafIndex % 2 != 0) {
        int exp1 = 1;
        long pow1 = 2;
        long pow2 = pow1 << 1;
        while (slot == 0) {
          if ((leafIndex + 1 - pow1) % pow2 == 0) {
            slot = exp1;
          } else {
            pow1 = pow2;
            pow2 = pow2 << 1;
            exp1++;
          }
        }
      }
      return slot;
    }

    protected Pair<Boolean, byte[]> insertLeaves(
        byte[][] frontier, long leafCount, byte[][] leafValue) {
      long nodeIndex = 0;
      boolean success = true;
      byte[] leftInput;
      byte[] rightInput;
      byte[] hash = new byte[32];
      byte[] nodeValue = new byte[32];
      int cmCount = leafValue.length;
      int[] slot = new int[cmCount];
      for (int i = 0; i < cmCount; i++) {
        slot[i] = getFrontierSlot(leafCount + i);
      }
      int resultArrayLength = 32;
      for (int i = 0; i < cmCount; i++) {
        resultArrayLength += (slot[i] + 1) * 32;
      }

      byte[] result = new byte[resultArrayLength];
      try {
        int offset = 0;
        for (int i = 0; i < cmCount; i++) {
          byte[] slotArray = DataWord.of((byte) (slot[i] & 0xFF)).getData();
          System.arraycopy(slotArray, 0, result, offset, 32);
          offset += 32;
          nodeIndex = i + leafCount + TREE_WIDTH - 1;
          System.arraycopy(leafValue[i], 0, nodeValue, 0, 32);
          if (slot[i] == 0) {
            System.arraycopy(nodeValue, 0, frontier[0], 0, 32);
            continue;
          }
          for (int level = 1; level <= slot[i]; level++) {
            if (nodeIndex % 2 == 0) {
              leftInput = frontier[level - 1];
              rightInput = nodeValue;
              nodeIndex = (nodeIndex - 1) / 2;
            } else {
              leftInput = nodeValue;
              rightInput = UNCOMMITTED[level - 1];
              nodeIndex = nodeIndex / 2;
            }
            JLibrustzcash.librustzcashMerkleHash(new LibrustzcashParam.MerkleHashParams(
                level - 1, leftInput, rightInput, hash));
            System.arraycopy(hash, 0, nodeValue, 0, 32);
            System.arraycopy(hash, 0, result, offset, 32);
            offset += 32;
          }
          System.arraycopy(nodeValue, 0, frontier[slot[i]], 0, 32);
        }

        for (int level = slot[cmCount - 1] + 1; level <= 32; level++) {
          if (nodeIndex % 2 == 0) {
            leftInput = frontier[level - 1];
            rightInput = nodeValue;
            nodeIndex = (nodeIndex - 1) / 2;
          } else {
            leftInput = nodeValue;
            rightInput = UNCOMMITTED[level - 1];
            nodeIndex = nodeIndex / 2;
          }
          JLibrustzcash.librustzcashMerkleHash(new LibrustzcashParam.MerkleHashParams(
              level - 1, leftInput, rightInput, hash));
          System.arraycopy(hash, 0, nodeValue, 0, 32);
        }
        System.arraycopy(nodeValue, 0, result, offset, 32);
      } catch (Throwable any) {
        success = false;
        String errorMsg = any.getMessage();
        if (errorMsg == null && any.getCause() != null) {
          errorMsg = any.getCause().getMessage();
        }
        logger.info("Insert leaves failed: " + errorMsg);
      }
      if (success) {
        return Pair.of(true, merge(DataWord.ONE().getData(), result));
      } else {
        return Pair.of(true, DataWord.ZERO().getData());
      }
    }
  }

  public static class VerifyMintProof extends VerifyProof {

    private static final int SIZE = 1504;

    @Override
    public long getEnergyForData(byte[] data) {
      return 150000;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      if (data.length != SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      boolean result;
      long ctx = JLibrustzcash.librustzcashSaplingVerificationCtxInit();
      try {
        byte[] cm = new byte[32];
        byte[] cv = new byte[32];
        byte[] epk = new byte[32];
        byte[] proof = new byte[192];
        byte[] bindingSig = new byte[64];
        byte[] signHash = new byte[32];
        byte[][] frontier = new byte[33][32];

        System.arraycopy(data, 0, cm, 0, 32);
        System.arraycopy(data, 32, cv, 0, 32);
        System.arraycopy(data, 64, epk, 0, 32);
        System.arraycopy(data, 96, proof, 0, 192);
        System.arraycopy(data, 288, bindingSig, 0, 64);
        long value = parseLong(data, 352);
        System.arraycopy(data, 384, signHash, 0, 32);
        for (int i = 0; i < 33; i++) {
          System.arraycopy(data, i * 32 + 416, frontier[i], 0, 32);
        }
        long leafCount = parseLong(data, 1472);
        if (leafCount >= TREE_WIDTH) {
          return Pair.of(true, DataWord.ZERO().getData());
        }

        result = JLibrustzcash.librustzcashSaplingCheckOutput(
            new LibrustzcashParam.CheckOutputParams(ctx, cv, cm, epk, proof));
        long valueBalance = -value;
        result = result && JLibrustzcash.librustzcashSaplingFinalCheck(
            new LibrustzcashParam.FinalCheckParams(ctx, valueBalance, bindingSig, signHash));

        if (result) {
          byte[][] leafValue = new byte[1][32];
          System.arraycopy(cm, 0, leafValue[0], 0, 32);
          return insertLeaves(frontier, leafCount, leafValue);
        } else {
          return Pair.of(true, DataWord.ZERO().getData());
        }
      } catch (Throwable any) {
        String errorMsg = any.getMessage();
        if (errorMsg == null && any.getCause() != null) {
          errorMsg = any.getCause().getMessage();
        }
        logger.info("VerifyMintProof exception " + errorMsg);
      } finally {
        JLibrustzcash.librustzcashSaplingVerificationCtxFree(ctx);
      }
      return Pair.of(true, DataWord.ZERO().getData());
    }
  }

  public static class VerifyTransferProof extends VerifyProof {

    private static final Integer[] SIZE = {2080, 2368, 2464, 2752};
    private static final ExecutorService workersInConstantCall;
    private static final ExecutorService workersInNonConstantCall;
    private static final String constantCallName = "verify-transfer-constant-call";
    private static final String nonConstantCallName = "verify-transfer-non-constant-call";

    static {
      workersInConstantCall = ExecutorServiceManager.newFixedThreadPool(constantCallName, 5);
      workersInNonConstantCall = ExecutorServiceManager.newFixedThreadPool(nonConstantCallName, 5);
    }

    @Override
    public long getEnergyForData(byte[] data) {
      return 200000;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      if (!Arrays.asList(SIZE).contains(data.length)) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      try {
        byte[] bindingSig = new byte[64];
        byte[] signHash = new byte[32];
        byte[][] frontier = new byte[33][32];
        //parse unfixed field offset
        int spendOffset = parseInt(data, 0);
        int spendAuthSigOffset = parseInt(data, 32);
        int receiveOffset = parseInt(data, 64);
        System.arraycopy(data, 96, bindingSig, 0, 64);
        System.arraycopy(data, 160, signHash, 0, 32);
        //parse value
        long value = parseLong(data, 192);
        for (int i = 0; i < 33; i++) {
          System.arraycopy(data, i * 32 + 224, frontier[i], 0, 32);
        }
        long leafCount = parseLong(data, 1280);
        if (leafCount >= TREE_WIDTH - 1) {
          return Pair.of(true, DataWord.ZERO().getData());
        }

        int spendCount = parseInt(data, spendOffset);
        int spendAuthSigCount = parseInt(data, spendAuthSigOffset);
        int receiveCount = parseInt(data, receiveOffset);

        if (spendCount != spendAuthSigCount || spendCount < 1
            || spendCount > 2 || receiveCount < 1 || receiveCount > 2) {
          return Pair.of(true, DataWord.ZERO().getData());
        }
        byte[][] anchor = new byte[spendCount][32];
        byte[][] nullifier = new byte[spendCount][32];
        byte[][] spendCv = new byte[spendCount][32];
        byte[][] rk = new byte[spendCount][32];
        byte[][] spendProof = new byte[spendCount][192];
        byte[][] spendAuthSig = new byte[spendCount][64];
        byte[][] receiveCm = new byte[receiveCount][32];
        byte[][] receiveCv = new byte[receiveCount][32];
        byte[][] receiveEpk = new byte[receiveCount][32];
        byte[][] receiveProof = new byte[receiveCount][192];

        //spend
        spendOffset += 32;
        for (int i = 0; i < spendCount; i++) {
          System.arraycopy(data, spendOffset + 320 * i, nullifier[i], 0, 32);
          System.arraycopy(data, spendOffset + 320 * i + 32, anchor[i], 0, 32);
          System.arraycopy(data, spendOffset + 320 * i + 64, spendCv[i], 0, 32);
          System.arraycopy(data, spendOffset + 320 * i + 96, rk[i], 0, 32);
          System.arraycopy(data, spendOffset + 320 * i + 128, spendProof[i], 0, 192);
        }
        spendAuthSigOffset += 32;
        for (int i = 0; i < spendCount; i++) {
          System.arraycopy(data, spendAuthSigOffset + 64 * i, spendAuthSig[i], 0, 64);
        }
        //output
        receiveOffset += 32;
        for (int i = 0; i < receiveCount; i++) {
          System.arraycopy(data, receiveOffset + 288 * i, receiveCm[i], 0, 32);
          System.arraycopy(data, receiveOffset + 288 * i + 32, receiveCv[i], 0, 32);
          System.arraycopy(data, receiveOffset + 288 * i + 64, receiveEpk[i], 0, 32);
          System.arraycopy(data, receiveOffset + 288 * i + 96, receiveProof[i], 0, 192);
        }

        //copy each spendCv(receiveCv) into spendCvs(receiveCvs)
        byte[] spendCvs = new byte[spendCount * 32];
        byte[] receiveCvs = new byte[receiveCount * 32];
        for (int i = 0; i < spendCount; i++) {
          System.arraycopy(spendCv[i], 0, spendCvs, 32 * i, 32);
        }
        for (int i = 0; i < receiveCount; i++) {
          System.arraycopy(receiveCv[i], 0, receiveCvs, 32 * i, 32);
        }
        //check duplicate nullifiers
        HashSet<String> nfSet = new HashSet<>();
        for (byte[] nf : nullifier) {
          if (nfSet.contains(ByteArray.toHexString(nf))) {
            return Pair.of(true, DataWord.ZERO().getData());
          }
          nfSet.add(ByteArray.toHexString(nf));
        }
        //check duplicate output note
        HashSet<String> cmSet = new HashSet<>();
        for (byte[] cm : receiveCm) {
          if (cmSet.contains(ByteArray.toHexString(cm))) {
            return Pair.of(true, DataWord.ZERO().getData());
          }
          cmSet.add(ByteArray.toHexString(cm));
        }

        int threadCount = spendCount + receiveCount + 1;
        CountDownLatch countDownLatch = new CountDownLatch(threadCount);
        List<Future<Boolean>> futures = new ArrayList<>(threadCount);
        ExecutorService workers;
        if (isConstantCall()) {
          workers = workersInConstantCall;
        } else {
          workers = workersInNonConstantCall;
        }

        // submit check spend task
        for (int i = 0; i < spendCount; i++) {
          Future<Boolean> futureCheckSpend = workers
              .submit(new SaplingCheckSpendTask(countDownLatch, spendCv[i], anchor[i],
                  nullifier[i], rk[i], spendProof[i], spendAuthSig[i], signHash));
          futures.add(futureCheckSpend);
        }
        //submit check output task
        for (int i = 0; i < receiveCount; i++) {
          Future<Boolean> futureCheckOutput = workers
              .submit(new SaplingCheckOutputTask(countDownLatch, receiveCv[i], receiveCm[i],
                  receiveEpk[i], receiveProof[i]));
          futures.add(futureCheckOutput);
        }
        // submit check binding signature
        Future<Boolean> futureCheckBindingSig = workers
            .submit(new SaplingCheckBingdingSig(countDownLatch, value, bindingSig,
                signHash, spendCvs, spendCount * 32, receiveCvs, receiveCount * 32));
        futures.add(futureCheckBindingSig);

        boolean withNoTimeout = countDownLatch.await(getCPUTimeLeftInNanoSecond(),
            TimeUnit.NANOSECONDS);
        boolean checkResult = true;
        for (Future<Boolean> future : futures) {
          boolean eachTaskResult = future.get();
          checkResult = checkResult && eachTaskResult;
        }
        if (checkResult) {
          return insertLeaves(frontier, leafCount, receiveCm);
        } else {
          return Pair.of(true, DataWord.ZERO().getData());
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        logger.info("VerifyTransferProof exception: " + e.getMessage());
      } catch (Throwable any) {
        String errorMsg = any.getMessage();
        if (errorMsg == null && any.getCause() != null) {
          errorMsg = any.getCause().getMessage();
        }
        logger.info("VerifyTransferProof exception: " + errorMsg);
      }
      return Pair.of(true, DataWord.ZERO().getData());
    }

    private static class SaplingCheckSpendTask implements Callable<Boolean> {

      private byte[] cv;
      private byte[] anchor;
      private byte[] nullifier;
      private byte[] rk;
      private byte[] zkproof;
      private byte[] spendAuthSig;
      private byte[] signHash;

      private CountDownLatch countDownLatch;

      SaplingCheckSpendTask(CountDownLatch countDownLatch,
          byte[] cv, byte[] anchor, byte[] nullifier, byte[] rk,
          byte[] zkproof, byte[] spendAuthSig, byte[] signHash) {
        this.cv = cv;
        this.anchor = anchor;
        this.nullifier = nullifier;
        this.rk = rk;
        this.zkproof = zkproof;
        this.spendAuthSig = spendAuthSig;
        this.signHash = signHash;
        this.countDownLatch = countDownLatch;
      }

      @Override
      public Boolean call() throws ZksnarkException {
        boolean result;
        try {
          result = JLibrustzcash.librustzcashSaplingCheckSpendNew(
              new LibrustzcashParam.CheckSpendNewParams(this.cv, this.anchor, this.nullifier,
                  this.rk, this.zkproof, this.spendAuthSig, this.signHash));
        } catch (ZksnarkException e) {
          throw e;
        } finally {
          countDownLatch.countDown();
        }
        return result;
      }
    }

    private static class SaplingCheckOutputTask implements Callable<Boolean> {

      private byte[] cv;
      private byte[] cm;
      private byte[] ephemeralKey;
      private byte[] zkproof;

      private CountDownLatch countDownLatch;

      SaplingCheckOutputTask(CountDownLatch countDownLatch, byte[] cv, byte[] cm,
          byte[] ephemeralKey, byte[] zkproof) {
        this.cv = cv;
        this.cm = cm;
        this.ephemeralKey = ephemeralKey;
        this.zkproof = zkproof;
        this.countDownLatch = countDownLatch;
      }

      @Override
      public Boolean call() throws ZksnarkException {
        boolean result;
        try {
          result = JLibrustzcash.librustzcashSaplingCheckOutputNew(
              new LibrustzcashParam.CheckOutputNewParams(this.cv, this.cm,
                  this.ephemeralKey, this.zkproof));
        } catch (ZksnarkException e) {
          throw e;
        } finally {
          countDownLatch.countDown();
        }
        return result;
      }
    }

    private static class SaplingCheckBingdingSig implements Callable<Boolean> {

      private long valueBalance;
      private int spendCvLen;
      private int receiveCvLen;
      private byte[] bindingSig;
      private byte[] signHash;
      private byte[] spendCvs;
      private byte[] receiveCvs;

      private CountDownLatch countDownLatch;

      SaplingCheckBingdingSig(CountDownLatch countDownLatch, long valueBalance, byte[] bindingSig,
          byte[] signHash, byte[] spendCvs, int spendCvLen,
          byte[] receiveCvs, int receiveCvLen) {
        this.valueBalance = valueBalance;
        this.bindingSig = bindingSig;
        this.signHash = signHash;
        this.spendCvs = spendCvs;
        this.spendCvLen = spendCvLen;
        this.receiveCvs = receiveCvs;
        this.receiveCvLen = receiveCvLen;
        this.countDownLatch = countDownLatch;
      }

      @Override
      public Boolean call() throws ZksnarkException {
        boolean result;
        try {
          result = JLibrustzcash.librustzcashSaplingFinalCheckNew(
              new LibrustzcashParam.FinalCheckNewParams(this.valueBalance, this.bindingSig,
                  this.signHash, this.spendCvs, this.spendCvLen,
                  this.receiveCvs, this.receiveCvLen));
        } catch (ZksnarkException e) {
          throw e;
        } finally {
          countDownLatch.countDown();
        }
        return result;
      }
    }
  }

  public static class VerifyBurnProof extends VerifyProof {

    private static final int SIZE = 512;

    @Override
    public long getEnergyForData(byte[] data) {
      return 150000;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      if (data.length != SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      boolean result;
      long ctx = JLibrustzcash.librustzcashSaplingVerificationCtxInit();
      try {
        byte[] nullifier = new byte[32];
        byte[] anchor = new byte[32];
        byte[] cv = new byte[32];
        byte[] rk = new byte[32];
        byte[] proof = new byte[192];
        byte[] spendAuthSig = new byte[64];
        byte[] bindingSig = new byte[64];
        byte[] signHash = new byte[32];
        //spend
        System.arraycopy(data, 0, nullifier, 0, 32);
        System.arraycopy(data, 32, anchor, 0, 32);
        System.arraycopy(data, 64, cv, 0, 32);
        System.arraycopy(data, 96, rk, 0, 32);
        System.arraycopy(data, 128, proof, 0, 192);
        System.arraycopy(data, 320, spendAuthSig, 0, 64);
        long value = parseLong(data, 384);
        System.arraycopy(data, 416, bindingSig, 0, 64);
        System.arraycopy(data, 480, signHash, 0, 32);

        result = JLibrustzcash.librustzcashSaplingCheckSpend(
            new LibrustzcashParam.CheckSpendParams(
                ctx, cv, anchor, nullifier, rk, proof, spendAuthSig, signHash));
        result = result && JLibrustzcash.librustzcashSaplingFinalCheck(
            new LibrustzcashParam.FinalCheckParams(ctx, value, bindingSig, signHash));
      } catch (Throwable any) {
        result = false;
        String errorMsg = any.getMessage();
        if (errorMsg == null && any.getCause() != null) {
          errorMsg = any.getCause().getMessage();
        }
        logger.info("VerifyBurnProof exception " + errorMsg);
      } finally {
        JLibrustzcash.librustzcashSaplingVerificationCtxFree(ctx);
      }
      return Pair.of(true, dataBoolean(result));
    }
  }

  // compute Merkle Hash
  public static class MerkleHash extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 500;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      byte[] left = new byte[32];
      byte[] right = new byte[32];
      byte[] hash = new byte[32];
      boolean res = true;
      try {
        int level = parseInt(data);
        System.arraycopy(data, 32, left, 0, 32);
        System.arraycopy(data, 64, right, 0, 32);
        JLibrustzcash.librustzcashMerkleHash(
            new LibrustzcashParam.MerkleHashParams(level, left, right, hash));
      } catch (Throwable any) {
        res = false;
        logger.info("Compute MerkleHash failed:{}", any.getMessage());
      }
      if (res) {
        return Pair.of(true, hash);
      } else {
        return Pair.of(false, EMPTY_BYTE_ARRAY);
      }
    }

    private int parseInt(byte[] data) {
      byte[] bytes = parseBytes(data, 0, 32);
      return new DataWord(bytes).intValueSafe();
    }
  }

  public static class RewardBalance extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 500;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {

      long rewardBalance = VoteRewardUtil.queryReward(
          TransactionTrace.convertToTronAddress(getCallerAddress()), getDeposit());
      return Pair.of(true, longTo32Bytes(rewardBalance));
    }
  }

  public static class IsSrCandidate extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 20;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != WORD_SIZE) {
        return Pair.of(true, dataBoolean(false));
      }

      byte[] address = new DataWord(data).toTronAddress();
      WitnessCapsule witnessCapsule = this.getDeposit().getWitness(address);
      if (witnessCapsule != null) {
        return Pair.of(true, dataBoolean(true));
      } else {
        return Pair.of(true, dataBoolean(false));
      }
    }
  }

  public static class VoteCount extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 500;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, longTo32Bytes(0L));
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      AccountCapsule accountCapsule = this.getDeposit().getAccount(address);

      long voteCount = 0;
      if (accountCapsule != null && !accountCapsule.getVotesList().isEmpty()) {
        ByteString witness = ByteString.copyFrom(words[1].toTronAddress());
        for (Protocol.Vote vote : accountCapsule.getVotesList()) {
          if (witness.equals(vote.getVoteAddress())) {
            voteCount += vote.getVoteCount();
          }
        }
      }

      return Pair.of(true, longTo32Bytes(voteCount));
    }
  }

  public static class UsedVoteCount extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 20;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != WORD_SIZE) {
        return Pair.of(true, longTo32Bytes(0L));
      }

      byte[] address = new DataWord(data).toTronAddress();
      AccountCapsule accountCapsule = this.getDeposit().getAccount(address);

      long usedVoteCount = 0;
      if (accountCapsule != null && !accountCapsule.getVotesList().isEmpty()) {
        for (Protocol.Vote vote : accountCapsule.getVotesList()) {
          usedVoteCount += vote.getVoteCount();
        }
      }

      return Pair.of(true, longTo32Bytes(usedVoteCount));
    }
  }

  public static class ReceivedVoteCount extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 20;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != WORD_SIZE) {
        return Pair.of(true, longTo32Bytes(0L));
      }

      byte[] address = new DataWord(data).toTronAddress();
      WitnessCapsule witnessCapsule = this.getDeposit().getWitness(address);

      long voteCount = witnessCapsule != null ? witnessCapsule.getVoteCount() : 0;
      return Pair.of(true, longTo32Bytes(voteCount));
    }
  }

  public static class TotalVoteCount extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 20;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != WORD_SIZE) {
        return Pair.of(true, longTo32Bytes(0L));
      }

      byte[] address = new DataWord(data).toTronAddress();
      AccountCapsule accountCapsule = this.getDeposit().getAccount(address);

      long tronPower;
      if (accountCapsule == null) {
        tronPower = 0;
      } else {
        if (getDeposit().getDynamicPropertiesStore().supportUnfreezeDelay()
            && getDeposit().getDynamicPropertiesStore().supportAllowNewResourceModel()) {
          tronPower = accountCapsule.getAllTronPower();
        } else {
          tronPower = accountCapsule.getTronPower();
        }
      }
      return Pair.of(true, longTo32Bytes(tronPower / TRX_PRECISION));
    }
  }

  public static class EthRipemd160 extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      if (data == null) {
        return 600;
      }
      return 600L + (data.length + 31) / 32 * 120L;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      byte[] result;
      if (data == null) {
        result = Hash.ripemd160(EMPTY_BYTE_ARRAY);
      } else {
        result = Hash.ripemd160(data);
      }
      return Pair.of(true, new DataWord(result).getData());
    }
  }

  public static class Blake2F extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      if (data.length != 213 || (data[212] & 0xFE) != 0) {
        return 0;
      }
      final byte[] roundsBytes = copyOfRange(data, 0, 4);
      final BigInteger rounds = new BigInteger(1, roundsBytes);
      return rounds.longValue();
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data.length != 213) {
        logger.warn("Incorrect input length.  Expected {} and got {}", 213, data.length);
        return Pair.of(false, DataWord.ZERO().getData());
      }
      if ((data[212] & 0xFE) != 0) {
        logger.warn("Incorrect finalization flag, expected 0 or 1 and got {}", data[212]);
        return Pair.of(false, DataWord.ZERO().getData());
      }
      final MessageDigest digest = new Blake2bfMessageDigest();
      byte[] result;
      try {
        digest.update(data);
        result = digest.digest();
      } catch (Exception e) {
        return Pair.of(true, EMPTY_BYTE_ARRAY);
      }
      return Pair.of(true, result);
    }
  }

  public static class GetChainParameter extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
      long code = new DataWord(data).longValueSafe();

      long res = ChainParameterEnum.fromCode(code).getAction().apply(
          getDeposit());

      return Pair.of(true, longTo32Bytes(res));
    }
  }

  public static class AvailableUnfreezeV2Size extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      byte[] address = new DataWord(data).toTronAddress();

      long result = FreezeV2Util.queryAvailableUnfreezeV2Size(address, getDeposit());
      return Pair.of(true, longTo32Bytes(result));
    }
  }

  public static class UnfreezableBalanceV2 extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      long type = words[1].longValueSafe();

      long balance = FreezeV2Util.queryUnfreezableBalanceV2(address, type, getDeposit());
      return Pair.of(true, longTo32Bytes(balance));
    }
  }

  public static class ExpireUnfreezeBalanceV2 extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      long time = words[1].longValueSafe();

      if (time < 0) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      if (time >= Long.MAX_VALUE / 1_000) {
        time = Long.MAX_VALUE;
      } else {
        time = time * 1_000;
      }

      long balance = FreezeV2Util.queryExpireUnfreezeBalanceV2(address, time, getDeposit());
      return Pair.of(true, longTo32Bytes(balance));
    }
  }

  public static class DelegatableResource extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      long type = words[1].longValueSafe();

      long result = FreezeV2Util.queryDelegatableResource(address, type, getDeposit());
      return Pair.of(true, longTo32Bytes(result));
    }
  }

  public static class ResourceV2 extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 3 * WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] target = words[0].toTronAddress();
      byte[] from = words[1].toTronAddress();
      long type = words[2].longValueSafe();

      long balance;
      if (Arrays.equals(from, target)) {
        balance = FreezeV2Util.queryUnfreezableBalanceV2(from, type, getDeposit());
      } else {
        balance = FreezeV2Util.queryResourceV2(from, target, type, getDeposit());
      }
      return Pair.of(true, longTo32Bytes(balance));
    }
  }

  public static class CheckUnDelegateResource extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 3 * WORD_SIZE) {
        return Pair.of(true, encodeMultiRes(
            DataWord.ZERO().getData(), DataWord.ZERO().getData(), DataWord.ZERO().getData()));
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] target = words[0].toTronAddress();
      long amount = words[1].longValueSafe();
      long type = words[2].longValueSafe();

      Triple<Long, Long, Long> values =
          FreezeV2Util.checkUndelegateResource(target, amount, type, getDeposit());
      if (values == null || values.getLeft() == null
          || values.getMiddle() == null || values.getRight() == null) {
        return Pair.of(true, encodeMultiRes(
            DataWord.ZERO().getData(), DataWord.ZERO().getData(), DataWord.ZERO().getData()));
      }

      return Pair.of(true, encodeMultiRes(longTo32Bytes(values.getLeft()),
          longTo32Bytes(values.getMiddle()), longTo32Bytes(values.getRight())));
    }
  }

  public static class ResourceUsage extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, encodeRes(DataWord.ZERO().getData(), DataWord.ZERO().getData()));
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      long type = words[1].longValueSafe();

      Pair<Long, Long> values = FreezeV2Util.queryFrozenBalanceUsage(address, type, getDeposit());
      if (values == null || values.getLeft() == null || values.getRight() == null) {
        return Pair.of(true, encodeRes(DataWord.ZERO().getData(), DataWord.ZERO().getData()));
      }

      return Pair.of(true, encodeRes(
          longTo32Bytes(values.getLeft()), longTo32Bytes(values.getRight())));
    }
  }

  public static class TotalResource extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      long type = words[1].longValueSafe();

      AccountCapsule accountCapsule = getDeposit().getAccount(address);
      if (accountCapsule == null) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      long totalResource = 0;
      if (type == 0) {
        totalResource = accountCapsule.getAllFrozenBalanceForBandwidth();
      } else if (type == 1) {
        totalResource = accountCapsule.getAllFrozenBalanceForEnergy();
      }

      return Pair.of(true, longTo32Bytes(totalResource));
    }
  }

  public static class TotalDelegatedResource extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      long type = words[1].longValueSafe();

      AccountCapsule accountCapsule = getDeposit().getAccount(address);
      if (accountCapsule == null) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      long delegatedResource = 0;
      if (type == 0) {
        delegatedResource = accountCapsule.getTotalDelegatedFrozenBalanceForBandwidth();
      } else if (type == 1) {
        delegatedResource = accountCapsule.getTotalDelegatedFrozenBalanceForEnergy();
      }

      return Pair.of(true, longTo32Bytes(delegatedResource));
    }
  }

  public static class TotalAcquiredResource extends PrecompiledContract {

    @Override
    public long getEnergyForData(byte[] data) {
      return 50;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != 2 * WORD_SIZE) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      DataWord[] words = DataWord.parseArray(data);
      byte[] address = words[0].toTronAddress();
      long type = words[1].longValueSafe();

      AccountCapsule accountCapsule = getDeposit().getAccount(address);
      if (accountCapsule == null) {
        return Pair.of(true, DataWord.ZERO().getData());
      }

      long acquiredResource = 0;
      if (type == 0) {
        acquiredResource = accountCapsule.getTotalAcquiredDelegatedFrozenBalanceForBandwidth();
      } else if (type == 1) {
        acquiredResource = accountCapsule.getTotalAcquiredDelegatedFrozenBalanceForEnergy();
      }

      return Pair.of(true, longTo32Bytes(acquiredResource));
    }
  }

  public static class KZGPointEvaluation extends PrecompiledContract {

    private static final int BLOB_VERIFY_INPUT_LENGTH = 192;
    private static final byte BLOB_COMMITMENT_VERSION_KZG = 0x01;
    private static final byte[] BLOB_PRECOMPILED_RETURN_VALUE =
        ByteUtil.merge(ByteUtil.longTo32Bytes(FIELD_ELEMENTS_PER_BLOB),
            ByteUtil.bigIntegerToBytes(BLS_MODULUS, 32));

    @Override
    public long getEnergyForData(byte[] data) {
      return 50000;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != BLOB_VERIFY_INPUT_LENGTH) {
        return Pair.of(false, DataWord.ZERO().getData());
      }

      byte[] versionedHash = parseBytes(data, 0, 32);
      byte[] z = parseBytes(data, 32, 32);
      byte[] y = parseBytes(data, 64, 32);
      byte[] commitment = parseBytes(data, 96, 48);
      byte[] proof = parseBytes(data, 144, 48);

      byte[] hash = Sha256Hash.hash(
          CommonParameter.getInstance().isECKeyCryptoEngine(), commitment);
      hash[0] = BLOB_COMMITMENT_VERSION_KZG;
      if (!Arrays.equals(versionedHash, hash)) {
        return Pair.of(false, DataWord.ZERO().getData());
      }

      try {
        if (CKZG4844JNI.verifyKzgProof(commitment, z, y, proof)) {
          return Pair.of(true, BLOB_PRECOMPILED_RETURN_VALUE);
        } else {
          return Pair.of(false, DataWord.ZERO().getData());
        }
      } catch (RuntimeException e) {
        logger.warn("KZG point evaluation precompile contract failed {}", e.getMessage());
        return Pair.of(false, DataWord.ZERO().getData());
      }
    }
  }


  public static class P256Verify extends PrecompiledContract {

    private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256r1");
    private static final ECDomainParameters DOMAIN = new ECDomainParameters(
        CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH());
    private static final BigInteger N = CURVE.getN();
    private static final BigInteger P = CURVE.getCurve().getField().getCharacteristic();
    private static final int INPUT_LEN = 160;
    private static final long ENERGY = 6900L;

    @Override
    public long getEnergyForData(byte[] data) {
      return ENERGY;
    }

    @Override
    public Pair<Boolean, byte[]> execute(byte[] data) {
      if (data == null || data.length != INPUT_LEN) {
        return Pair.of(true, EMPTY_BYTE_ARRAY);
      }
      try {
        byte[] hash = copyOfRange(data, 0, 32);
        BigInteger r = bytesToBigInteger(copyOfRange(data, 32, 64));
        BigInteger s = bytesToBigInteger(copyOfRange(data, 64, 96));
        BigInteger qx = bytesToBigInteger(copyOfRange(data, 96, 128));
        BigInteger qy = bytesToBigInteger(copyOfRange(data, 128, 160));

        if (r.signum() <= 0 || r.compareTo(N) >= 0
            || s.signum() <= 0 || s.compareTo(N) >= 0) {
          return Pair.of(true, EMPTY_BYTE_ARRAY);
        }
        if (qx.signum() < 0 || qx.compareTo(P) >= 0
            || qy.signum() < 0 || qy.compareTo(P) >= 0) {
          return Pair.of(true, EMPTY_BYTE_ARRAY);
        }
        if (qx.signum() == 0 && qy.signum() == 0) {
          return Pair.of(true, EMPTY_BYTE_ARRAY);
        }

        ECPoint point = CURVE.getCurve().createPoint(qx, qy);
        DOMAIN.validatePublicPoint(point);

        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(point, DOMAIN));
        boolean ok = verifier.verifySignature(hash, r, s);
        return Pair.of(true, ok ? dataOne() : EMPTY_BYTE_ARRAY);
      } catch (Exception e) {
        // Off-curve point: createPoint / validatePublicPoint throw IllegalArgumentException.
        // Crafted signature: BouncyCastle has a known NPE bug inside verifySignature.
        // EIP-7951 mandates the precompile never reverts; map any failure to (true, empty).
        return Pair.of(true, EMPTY_BYTE_ARRAY);
      }
    }
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
  public static class VerifyFnDsa512 extends PrecompiledContract {

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
   * 0x17 BatchValidateFnDsa512 — independent per-element Falcon-512 verify.
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
   * <p>Falcon sigs are pinned to the 666-byte slot from {@code VerifyFnDsa512} (0x16)
   * for cross-precompile consistency; {@link #falconSlotToHeaderedSig} recovers the
   * headerless body and re-inserts the {@code 0x39} header before BC verification.
   *
   * <p>Reuses the {@code BatchValidateSign.workers} pool when not in a constant
   * call and enforces {@code getCPUTimeLeftInNanoSecond()} timeout. {@code MAX_SIZE = 16}.
   * Energy is {@code cnt × 220}.
   */
  public static class BatchValidateFnDsa512 extends PrecompiledContract {

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
        return (long) cnt * ENERGY_PER_SIGN;
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
        return Pair.of(true, new byte[WORD_SIZE]);
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
        return Pair.of(true, DATA_FALSE);
      }

      byte[][] signatures = extractBytesArrayChecked(words, sigArrayWord, data);
      byte[][] publicKeys = extractBytesArrayChecked(words, pkArrayWord, data);
      byte[][] addresses = extractBytes32Array(words, addrArrayWord);

      int cnt = signatures.length;
      if (cnt == 0 || publicKeys.length != cnt || addresses.length != cnt) {
        return Pair.of(true, DATA_FALSE);
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
          Future<PqVerifyResult> future = BatchValidateSign.workers.submit(
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

    private static boolean verifyOne(byte[] sig, byte[] pk, byte[] hash, byte[] expectedAddr) {
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
          return new PqVerifyResult(verifyOne(signature, publicKey, hash, expectedAddr), nonce);
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
   * cost so 1312 B Dilithium-2 keys work unchanged. The EIP-8051 expanded-pk
   * variant is implemented separately at 0x12 — 0x19 stays as-is.
   */
  public static class VerifyMlDsa44 extends PrecompiledContract {

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
        return Pair.of(true, ok ? DataWord.ONE().getData() : DataWord.ZERO().getData());
      } catch (Throwable t) {
        return Pair.of(true, DataWord.ZERO().getData());
      }
    }
  }

  /**
   * 0x1a ValidateMultiPQSig — algorithm-agnostic Permission multi-sign. Accepts
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
   * (matches 0x16/0x18): the slot holds {@code salt ‖ s2_compressed} with no
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
   * {@code allowFnDsa512()} is false even though 0x1a itself is registered as
   * long as one PQ proposal is active. Same for ML-DSA-44.
   */
  public static class ValidateMultiPQSig extends PrecompiledContract {

    private static final int ECDSA_ENERGY_PER_SIGN = 1500;
    private static final int FN_DSA_512_ENERGY = 220;
    private static final int ML_DSA_44_ENERGY = 470;
    private static final int WORST_PQ_ENERGY = ML_DSA_44_ENERGY;
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
        long energy = (long) ecdsaCnt * ECDSA_ENERGY_PER_SIGN;
        for (int i = 0; i < pqCnt; i++) {
          int tag = words[schemeOff + 1 + i].intValueSafe();
          PQScheme s = PQScheme.forNumber(tag);
          Integer cost = s == null ? null : PQ_ENERGY.get(s);
          // Unknown / unregistered tag → charge worst case so a caller can't
          // encode a junk tag to underpay before execute() rejects it.
          energy += cost == null ? WORST_PQ_ENERGY : cost;
        }
        return energy;
      } catch (Throwable t) {
        return (long) MAX_SIZE * WORST_PQ_ENERGY;
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
        byte[] data = words[2].getData();

        byte[] combine = ByteUtil.merge(address, ByteArray.fromInt(permissionId), data);
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

        // Per-variable bounds first to defeat int overflow in the sum below
        // (e.g. Integer.MAX_VALUE + 1 wraps to Integer.MIN_VALUE and slips past
        // a naive `> MAX_SIZE` check).
        if (ecdsaCnt < 0 || schemeCnt < 0
            || ecdsaCnt > MAX_SIZE || schemeCnt > MAX_SIZE
            || schemeCnt != pqSigCnt || schemeCnt != pqPkCnt
            || ecdsaCnt + schemeCnt == 0
            || ecdsaCnt + schemeCnt > MAX_SIZE) {
          return Pair.of(true, DATA_FALSE);
        }

        byte[][] ecdsaSigs = extractSigArray(words, ecdsaArrayWord, rawData);
        byte[][] pqSigs = extractBytesArrayChecked(words, pqSigArrayWord, rawData);
        byte[][] pqPks = extractBytesArrayChecked(words, pqPkArrayWord, rawData);
        if (pqSigs.length != schemeCnt || pqPks.length != schemeCnt) {
          return Pair.of(true, DATA_FALSE);
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
          byte[] recoveredAddr = recoverAddrBySign(sign, hash);
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
            return Pair.of(true, DATA_FALSE);
          }
          // Per-entry runtime gate: the scheme's proposal must be active even
          // though 0x1a was registered under (allowFnDsa512 || allowMlDsa44).
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
            // Slot lengths are exact here (Falcon = 666, Dilithium = 2420) —
            // a Falcon sig mislabelled as Dilithium fails this check.
            return Pair.of(true, DATA_FALSE);
          }
          if (scheme == PQScheme.FN_DSA_512) {
            // The Falcon slot is the EIP-8052 headerless body; rebuild the
            // BC-headered sig (re-inserts 0x39) before verification.
            sig = falconSlotToHeaderedSig(sig, 0, sig.length);
            if (sig == null) {
              return Pair.of(true, DATA_FALSE);
            }
          }
          byte[] derivedAddr;
          try {
            derivedAddr = PQSchemeRegistry.computeAddress(scheme, pk);
          } catch (Throwable t) {
            return Pair.of(true, DATA_FALSE);
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
      }
      return Pair.of(true, DATA_FALSE);
    }
  }

  /**
   * 0x19 BatchValidateMlDsa44 — independent per-element ML-DSA-44 verify.
   * Returns a 256-bit bitmap where bit {@code i} is set iff
   * {@code derive(pk_i) == expectedAddr_i} AND {@code MLDSA44.verify(pk_i, hash, sig_i)}.
   * Same ABI shape as 0x17, with sigs 2420 B and pks 1312 B.
   * {@code MAX_SIZE = 16}; energy is {@code cnt × 470}.
   */
  public static class BatchValidateMlDsa44 extends PrecompiledContract {

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
        return (long) cnt * ENERGY_PER_SIGN;
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
        return Pair.of(true, new byte[WORD_SIZE]);
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
        return Pair.of(true, DATA_FALSE);
      }

      byte[][] signatures = extractBytesArrayChecked(words, sigArrayWord, data);
      byte[][] publicKeys = extractBytesArrayChecked(words, pkArrayWord, data);
      byte[][] addresses = extractBytes32Array(words, addrArrayWord);

      int cnt = signatures.length;
      if (cnt == 0 || publicKeys.length != cnt || addresses.length != cnt) {
        return Pair.of(true, DATA_FALSE);
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
          Future<PqVerifyResult> future = BatchValidateSign.workers.submit(
              new PqVerifyTask(countDownLatch, hash, signatures[i],
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
          return new PqVerifyResult(verifyOne(signature, publicKey, hash, expectedAddr), nonce);
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

}
