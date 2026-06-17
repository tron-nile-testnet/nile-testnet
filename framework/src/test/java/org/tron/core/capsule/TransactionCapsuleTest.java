package org.tron.core.capsule;

import static org.tron.protos.Protocol.Transaction.Result.contractResult.BAD_JUMP_DESTINATION;
import static org.tron.protos.Protocol.Transaction.Result.contractResult.PRECOMPILED_CONTRACT;
import static org.tron.protos.Protocol.Transaction.Result.contractResult.SUCCESS;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.LoggerFactory;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.utils.StringUtil;
import org.tron.core.Wallet;
import org.tron.core.config.args.Args;
import org.tron.core.exception.ValidateSignatureException;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.Protocol.Transaction.Result;
import org.tron.protos.Protocol.Transaction.Result.contractResult;
import org.tron.protos.Protocol.Transaction.raw;
import org.tron.protos.contract.BalanceContract.TransferContract;
import org.tron.protos.contract.SmartContractOuterClass.TriggerSmartContract;

@Slf4j
public class TransactionCapsuleTest extends BaseTest {

  private static String OWNER_ADDRESS;

  @BeforeClass
  public static void init() {
    Args.setParam(new String[]{"-d", dbPath()}, TestConstants.TEST_CONF);
    OWNER_ADDRESS = Wallet.getAddressPreFixString() + "03702350064AD5C1A8AA6B4D74B051199CFF8EA7";
  }

  /**
   * create temp Capsule test need.
   */
  @Before
  public void createAccountCapsule() {
    AccountCapsule ownerCapsule = new AccountCapsule(ByteString.copyFromUtf8("owner"),
        StringUtil.hexString2ByteString(OWNER_ADDRESS), AccountType.Normal, 10_000_000_000L);
    dbManager.getAccountStore().put(ownerCapsule.createDbKey(), ownerCapsule);
  }

  @Test
  public void trxCapsuleClearTest() {
    Transaction tx = Transaction.newBuilder()
        .addRet(Result.newBuilder().setContractRet(contractResult.OUT_OF_TIME).build()).build();
    TransactionCapsule trxCap = new TransactionCapsule(tx);
    Result.contractResult contractResult = trxCap.getContractResult();
    trxCap.resetResult();
    Assert.assertEquals(trxCap.getInstance().getRetCount(), 0);
    trxCap.setResultCode(contractResult);
    Assert.assertEquals(trxCap.getInstance()
        .getRet(0).getContractRet(), Result.contractResult.OUT_OF_TIME);
  }

  @Test
  public void testRemoveRedundantRet() {
    Transaction.Builder transaction = Transaction.newBuilder().setRawData(raw.newBuilder()
        .addContract(Transaction.Contract.newBuilder().setType(ContractType.TriggerSmartContract))
        .setFeeLimit(1000000000)).build().toBuilder();
    transaction.addRet(Result.newBuilder().setContractRet(SUCCESS).build());
    transaction.addRet(Result.newBuilder().setContractRet(PRECOMPILED_CONTRACT).build());
    transaction.addRet(Result.newBuilder().setContractRet(BAD_JUMP_DESTINATION).build());
    TransactionCapsule transactionCapsule = new TransactionCapsule(transaction.build());
    transactionCapsule.removeRedundantRet();
    Assert.assertEquals(1, transactionCapsule.getInstance().getRetCount());
    Assert.assertEquals(SUCCESS, transactionCapsule.getInstance().getRet(0).getContractRet());
  }

  @Test
  public void slowVerify() {
    Logger capsuleLogger = (Logger) LoggerFactory.getLogger("capsule");
    Level originalLevel = capsuleLogger.getLevel();
    capsuleLogger.setLevel(Level.INFO);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    capsuleLogger.addAppender(appender);
    try {
      TransactionCapsule cap = new TransactionCapsule(Transaction.newBuilder().build());
      long startNs = System.nanoTime() - TimeUnit.MILLISECONDS.toNanos(51);
      cap.logSlowSigVerify(startNs);

      List<ILoggingEvent> warns = appender.list.stream()
          .filter(e -> e.getLevel() == Level.WARN)
          .collect(Collectors.toList());
      Assert.assertEquals("expected one WARN for a slow verify", 1, warns.size());
      String rendered = warns.get(0).getFormattedMessage();
      Assert.assertTrue("WARN should mention slow verify: " + rendered,
          rendered.contains("slow verify"));
      Assert.assertTrue("WARN should echo the txId: " + rendered,
          rendered.contains(cap.getTransactionId().toString()));
      Assert.assertTrue("WARN should include sigCount: " + rendered,
          rendered.contains("sigCount="));
      Assert.assertTrue("WARN should include cost in ms: " + rendered,
          rendered.contains("cost="));
      Assert.assertTrue("WARN should render ms suffix: " + rendered,
          rendered.contains(" ms"));
    } finally {
      appender.stop();
      capsuleLogger.detachAppender(appender);
      capsuleLogger.setLevel(originalLevel);
    }
  }

  // --------------------- FN-DSA pq_auth_sig verification (V2) ---------------------

  private static final String PQ_OWNER_HEX = "41abd4b9367799eaa3197fecb144eb71de1e049abc";
  private static final String PQ_TO_HEX = "41548794500882809695a8a687866e76d4271a1abc";

  private Transaction buildTransferTx(String ownerHex, int permissionId) {
    TransferContract transfer = TransferContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(ownerHex)))
        .setToAddress(ByteString.copyFrom(ByteArray.fromHexString(PQ_TO_HEX)))
        .setAmount(1L)
        .build();
    Transaction.Contract c = Transaction.Contract.newBuilder()
        .setType(ContractType.TransferContract)
        .setParameter(Any.pack(transfer))
        .setPermissionId(permissionId)
        .build();
    raw rawData = raw.newBuilder().addContract(c).build();
    return Transaction.newBuilder().setRawData(rawData).build();
  }

  /**
   * V2: bind the PQ public key to the permission via address-as-fingerprint.
   * The signer address is derived from the public key by the scheme's
   * fingerprint hash (see {@link PQSchemeRegistry#computeAddress}).
   */
  private void putAccountWithPQPermission(String ownerHex, byte[] pqPublicKey, PQScheme scheme) {
    byte[] addr = ByteArray.fromHexString(ownerHex);
    byte[] signerAddr = PQSchemeRegistry.computeAddress(scheme, pqPublicKey);
    Key pqKey = Key.newBuilder()
        .setAddress(ByteString.copyFrom(signerAddr))
        .setWeight(1L)
        .build();
    Permission owner = Permission.newBuilder()
        .setType(PermissionType.Owner)
        .setPermissionName("owner")
        .setThreshold(1)
        .addKeys(pqKey)
        .build();
    AccountCapsule acc = new AccountCapsule(ByteString.copyFrom(addr),
        ByteString.copyFromUtf8("pqowner"), AccountType.Normal);
    acc.updatePermissions(owner, null, java.util.Collections.emptyList());
    dbManager.getAccountStore().put(addr, acc);
  }

  @Test
  public void pqAuthSigBeforeActivationRejected() {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0).toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(new byte[FNDSA512.PUBLIC_KEY_LENGTH]))
            .setSignature(ByteString.copyFrom(new byte[FNDSA512.SIGNATURE_MAX_LENGTH]))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(tx);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("should reject pq_auth_sig before activation");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("no post-quantum scheme is activated"));
    }
  }

  @Test
  public void fastVerify() {
    Logger capsuleLogger = (Logger) LoggerFactory.getLogger("capsule");
    Level originalLevel = capsuleLogger.getLevel();
    capsuleLogger.setLevel(Level.INFO);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    capsuleLogger.addAppender(appender);
    try {
      TransactionCapsule cap = new TransactionCapsule(Transaction.newBuilder().build());
      cap.logSlowSigVerify(System.nanoTime());
      long warnCount = appender.list.stream()
          .filter(e -> e.getLevel() == Level.WARN)
          .count();
      Assert.assertEquals("no WARN should fire below the threshold", 0, warnCount);
    } finally {
      appender.stop();
      capsuleLogger.detachAppender(appender);
      capsuleLogger.setLevel(originalLevel);
    }
  }

  private static byte[] txId(Transaction tx) {
    return Sha256Hash.of(Args.getInstance().isECKeyCryptoEngine(),
        tx.getRawData().toByteArray()).getBytes();
  }

  @Test
  public void validPQAuthSigAccepted() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 kp = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, kp.getPublicKey(), PQScheme.FN_DSA_512);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = txId(tx);

    byte[] sig = FNDSA512.sign(kp.getPrivateKey(), txid);

    Transaction signed = tx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    Assert.assertTrue(cap.validatePubSignature(dbManager.getAccountStore(),
        dbManager.getDynamicPropertiesStore()));
  }

  @Test
  public void duplicateSignerRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 kp = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, kp.getPublicKey(), PQScheme.FN_DSA_512);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = txId(tx);
    
    byte[] sig = FNDSA512.sign(kp.getPrivateKey(), txid);
    PQAuthSig w = PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
        .setSignature(ByteString.copyFrom(sig))
        .build();
    Transaction signed = tx.toBuilder().addPqAuthSig(w).addPqAuthSig(w).build();

    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("duplicate signer should be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("has signed twice"));
    }
  }

  @Test
  public void tamperedPQAuthSigRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 kp = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, kp.getPublicKey(), PQScheme.FN_DSA_512);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = txId(tx);
    
    byte[] sig = FNDSA512.sign(kp.getPrivateKey(), txid);
    sig[0] ^= 0x01;

    Transaction signed = tx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("tampered signature should be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("pq sig invalid"));
    }
  }

  @Test
  public void signerNotInPermissionRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 known = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, known.getPublicKey(), PQScheme.FN_DSA_512);

    // Sign with a *different* keypair → derived address is not in the permission.
    FNDSA512 stranger = new FNDSA512();
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = txId(tx);
    
    byte[] sig = FNDSA512.sign(stranger.getPrivateKey(), txid);

    Transaction signed = tx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(stranger.getPublicKey()))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("signer outside permission should be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("not contained of permission"));
    }
  }

  /**
   * TRC20 transfer(address,uint256) call data: 4-byte selector + 32-byte address + 32-byte amount.
   */
  private Transaction buildTrc20TransferTx(String ownerHex, int permissionId) {
    byte[] selector = ByteArray.fromHexString("a9059cbb");
    byte[] toAddrPadded = new byte[32];
    byte[] toRaw = ByteArray.fromHexString(PQ_TO_HEX.substring(2)); // strip "41"
    System.arraycopy(toRaw, 0, toAddrPadded, 12, 20);
    byte[] amountPadded = new byte[32];
    amountPadded[31] = (byte) 100; // 100 tokens
    byte[] callData = new byte[selector.length + toAddrPadded.length + amountPadded.length];
    System.arraycopy(selector, 0, callData, 0, 4);
    System.arraycopy(toAddrPadded, 0, callData, 4, 32);
    System.arraycopy(amountPadded, 0, callData, 36, 32);

    byte[] contractAddr = ByteArray.fromHexString("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
    TriggerSmartContract trigger = TriggerSmartContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(ownerHex)))
        .setContractAddress(ByteString.copyFrom(contractAddr))
        .setData(ByteString.copyFrom(callData))
        .build();
    Transaction.Contract c = Transaction.Contract.newBuilder()
        .setType(ContractType.TriggerSmartContract)
        .setParameter(Any.pack(trigger))
        .setPermissionId(permissionId)
        .build();
    raw rawData = raw.newBuilder().addContract(c).setFeeLimit(150_000_000L).build();
    return Transaction.newBuilder().setRawData(rawData).build();
  }

  /**
   * Returns [serializedSize, packSize, maxTxPerBlock] rows ordered by signature size:
   * ECKey, FN-DSA-512, ML-DSA-44.
   */
  private long[][] measureSizes(Transaction baseTx) {
    final long blockLimit = 2_000_000L;

    // ECKey (ECDSA): 65-byte signature in `signature` field
    ECKey ecKey = new ECKey();
    TransactionCapsule ecCap = new TransactionCapsule(baseTx);
    ecCap.sign(ecKey.getPrivKeyBytes());
    long ecSerial = ecCap.getInstance().toByteArray().length;
    long ecPack = ecCap.computeTrxSizeForBlockMessage();

    byte[] txid = txId(baseTx);

    // FN-DSA-512: variable-length signature (<= 752 bytes) + 897-byte public key
    FNDSA512 kpFn = new FNDSA512();
    byte[] sigFn = FNDSA512.sign(kpFn.getPrivateKey(), txid);
    Transaction txFn = baseTx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(kpFn.getPublicKey()))
            .setSignature(ByteString.copyFrom(sigFn))
            .build())
        .build();
    TransactionCapsule capFn = new TransactionCapsule(txFn);
    long dFnSerial = txFn.toByteArray().length;
    long dFnPack = capFn.computeTrxSizeForBlockMessage();

    // ML-DSA-44: fixed 2420-byte signature + 1312-byte public key
    MLDSA44 kpMl = new MLDSA44();
    byte[] sigMl = MLDSA44.sign(kpMl.getPrivateKey(), txid);
    Transaction txMl = baseTx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.ML_DSA_44)
            .setPublicKey(ByteString.copyFrom(kpMl.getPublicKey()))
            .setSignature(ByteString.copyFrom(sigMl))
            .build())
        .build();
    TransactionCapsule capMl = new TransactionCapsule(txMl);
    long dMlSerial = txMl.toByteArray().length;
    long dMlPack = capMl.computeTrxSizeForBlockMessage();

    return new long[][]{
        {ecSerial,  ecPack,  blockLimit / ecPack},
        {dFnSerial, dFnPack, blockLimit / dFnPack},
        {dMlSerial, dMlPack, blockLimit / dMlPack},
    };
  }

  @Test
  public void transactionSizeComparisonByScheme() {
    long[][] trx   = measureSizes(buildTransferTx(PQ_OWNER_HEX, 0));
    long[][] trc20 = measureSizes(buildTrc20TransferTx(PQ_OWNER_HEX, 0));

    String[] labels = {"ECKey (ECDSA)", "FN-DSA-512", "ML-DSA-44"};
    System.out.println("=== TRX transfer ===");
    for (int i = 0; i < labels.length; i++) {
      System.out.printf("  %s: serial=%d B  pack=%d B  maxTx/block=%d%n",
          labels[i], trx[i][0], trx[i][1], trx[i][2]);
    }
    System.out.println("=== TRC20 transfer ===");
    for (int i = 0; i < labels.length; i++) {
      System.out.printf("  %s: serial=%d B  pack=%d B  maxTx/block=%d%n",
          labels[i], trc20[i][0], trc20[i][1], trc20[i][2]);
    }

    // Both PQ envelopes are larger than ECKey, so they fit fewer txs per block.
    // ML-DSA-44 (2420 B sig + 1312 B pk) is the heaviest, FN-DSA-512 sits between.
    Assert.assertTrue(trx[1][0] > trx[0][0]);
    Assert.assertTrue(trc20[1][0] > trc20[0][0]);
    Assert.assertTrue(trx[1][2] < trx[0][2]);
    Assert.assertTrue(trc20[1][2] < trc20[0][2]);

    Assert.assertTrue(trx[2][0] > trx[1][0]);
    Assert.assertTrue(trc20[2][0] > trc20[1][0]);
    Assert.assertTrue(trx[2][2] < trx[1][2]);
    Assert.assertTrue(trc20[2][2] < trc20[1][2]);
  }

  @Test
  public void pqAuthSigWrongPublicKeyLengthRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 kp = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, kp.getPublicKey(), PQScheme.FN_DSA_512);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = txId(tx);
    byte[] sig = FNDSA512.sign(kp.getPrivateKey(), txid);

    // Truncate public key by one byte to force the length-mismatch branch.
    byte[] shortPub = new byte[FNDSA512.PUBLIC_KEY_LENGTH - 1];
    System.arraycopy(kp.getPublicKey(), 0, shortPub, 0, shortPub.length);

    Transaction signed = tx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(shortPub))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("wrong public key length must be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("public key or signature length mismatch"));
    }
  }

  @Test
  public void pqAuthSigWrongSignatureLengthRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 kp = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, kp.getPublicKey(), PQScheme.FN_DSA_512);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);

    // Empty signature is not a valid FN-DSA-512 length, hits the same branch.
    Transaction signed = tx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
            .setSignature(ByteString.EMPTY)
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("wrong signature length must be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("public key or signature length mismatch"));
    }
  }

  @Test
  public void pqAuthSigUnsupportedSchemeRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 kp = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, kp.getPublicKey(), PQScheme.FN_DSA_512);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = txId(tx);
    byte[] sig = FNDSA512.sign(kp.getPrivateKey(), txid);

    // setSchemeValue(99) sets an unknown numeric tag; reading back yields
    // PQScheme.UNRECOGNIZED, which PQSchemeRegistry.contains() rejects.
    Transaction signed = tx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setSchemeValue(99)
            .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("unsupported scheme must be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("unsupported pq scheme"));
    }
  }

  @Test
  public void validatePubSignatureRejectsMissingSig() {
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    TransactionCapsule cap = new TransactionCapsule(tx);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("transaction with no signatures must be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("miss sig"));
    }
  }

  @Test
  public void validatePubSignatureRejectsMissingContract() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    FNDSA512 kp = new FNDSA512();
    byte[] sig = FNDSA512.sign(kp.getPrivateKey(), new byte[32]);

    // No contracts in raw_data, but a pq_auth_sig is attached so the signature
    // count is non-zero; the missing-contract branch must still reject it.
    Transaction tx = Transaction.newBuilder()
        .setRawData(raw.newBuilder().build())
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(tx);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("transaction with no contracts must be rejected");
    } catch (ValidateSignatureException e) {
      Assert.assertTrue(e.getMessage().contains("miss sig or contract"));
    }
  }

  @Test
  public void validatePubSignatureRejectsTooManySignatures() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    int original = dbManager.getDynamicPropertiesStore().getTotalSignNum();
    try {
      dbManager.getDynamicPropertiesStore().saveTotalSignNum(1);
      FNDSA512 a = new FNDSA512();
      FNDSA512 b = new FNDSA512();
      putAccountWithPQPermission(PQ_OWNER_HEX, a.getPublicKey(), PQScheme.FN_DSA_512);

      Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
      byte[] txid = txId(tx);
      byte[] sigA = FNDSA512.sign(a.getPrivateKey(), txid);
      byte[] sigB = FNDSA512.sign(b.getPrivateKey(), txid);

      Transaction signed = tx.toBuilder()
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setScheme(PQScheme.FN_DSA_512)
              .setPublicKey(ByteString.copyFrom(a.getPublicKey()))
              .setSignature(ByteString.copyFrom(sigA))
              .build())
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setScheme(PQScheme.FN_DSA_512)
              .setPublicKey(ByteString.copyFrom(b.getPublicKey()))
              .setSignature(ByteString.copyFrom(sigB))
              .build())
          .build();
      TransactionCapsule cap = new TransactionCapsule(signed);
      try {
        cap.validatePubSignature(dbManager.getAccountStore(),
            dbManager.getDynamicPropertiesStore());
        Assert.fail("more sigs than totalSignNum must be rejected");
      } catch (ValidateSignatureException e) {
        Assert.assertTrue(e.getMessage().contains("too many signatures"));
      }
    } finally {
      dbManager.getDynamicPropertiesStore().saveTotalSignNum(original);
    }
  }

  @Test
  public void fnDsaPQAuthSigRejectedWhenNotActivated() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
    FNDSA512 kp = new FNDSA512();
    putAccountWithPQPermission(PQ_OWNER_HEX, kp.getPublicKey(), PQScheme.FN_DSA_512);

    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    byte[] txid = txId(tx);
    
    byte[] sig = FNDSA512.sign(kp.getPrivateKey(), txid);

    Transaction signed = tx.toBuilder()
        .addPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
            .setSignature(ByteString.copyFrom(sig))
            .build())
        .build();
    TransactionCapsule cap = new TransactionCapsule(signed);
    try {
      cap.validatePubSignature(dbManager.getAccountStore(), dbManager.getDynamicPropertiesStore());
      Assert.fail("FN-DSA must be rejected when ALLOW_FN_DSA_512 is 0");
    } catch (ValidateSignatureException expected) {
      Assert.assertTrue(expected.getMessage().contains("no post-quantum scheme is activated"));
    }
  }

  @Test
  public void toStringRendersSignedTransferContract() {
    // A signed transfer tx exercises the contract-list rendering path of
    // toString(), including the per-contract type/address lines, the
    // TransferContract amount branch, and the legacy `sign=` rendering.
    Transaction tx = buildTransferTx(PQ_OWNER_HEX, 0);
    ECKey key = new ECKey();
    byte[] sig = key.sign(txId(tx)).toByteArray();
    Transaction signed = tx.toBuilder().addSignature(ByteString.copyFrom(sig)).build();

    String rendered = new TransactionCapsule(signed).toString();
    Assert.assertTrue(rendered.contains("contract list:{"));
    Assert.assertTrue(rendered.contains("TransferContract"));
    Assert.assertTrue(rendered.contains("transfer amount=1"));
    Assert.assertTrue(rendered.contains("sign="));
  }

  @Test
  public void toStringRendersEmptyContractList() {
    Transaction empty = Transaction.newBuilder().setRawData(raw.newBuilder().build()).build();
    String rendered = new TransactionCapsule(empty).toString();
    Assert.assertTrue(rendered.contains("contract list is empty"));
  }
}
