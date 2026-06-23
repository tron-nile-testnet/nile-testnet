package org.tron.core.services.jsonrpc;

import com.google.protobuf.ByteString;
import javax.annotation.Resource;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.utils.ByteArray;
import org.tron.core.Wallet;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.services.jsonrpc.types.TransactionResult;
import org.tron.protos.Protocol;
import org.tron.protos.contract.SmartContractOuterClass;

public class TransactionResultTest extends BaseTest {

  @Resource
  private Wallet wallet;

  private static final String OWNER_ADDRESS = "41548794500882809695a8a687866e76d4271a1abc";
  private static final String CONTRACT_ADDRESS = "A0B4750E2CD76E19DCA331BF5D089B71C3C2798548";

  // QUANTITY pattern from ethereum/execution-apis base-types schema (uint).
  private static final String QUANTITY_PATTERN = "^0x(0|[1-9a-f][0-9a-f]*)$";

  static {
    Args.setParam(new String[] {"-d", dbPath()}, TestConstants.TEST_CONF);
  }

  private static void assertQuantity(String value) {
    Assert.assertNotNull(value);
    Assert.assertTrue("not a valid QUANTITY: " + value, value.matches(QUANTITY_PATTERN));
  }

  @Test
  public void testBuildTransactionResultWithBlock() {
    SmartContractOuterClass.TriggerSmartContract.Builder builder2 =
        SmartContractOuterClass.TriggerSmartContract.newBuilder()
            .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(OWNER_ADDRESS)))
            .setContractAddress(ByteString.copyFrom(ByteArray.fromHexString(CONTRACT_ADDRESS)));
    TransactionCapsule transactionCapsule = new TransactionCapsule(builder2.build(),
        Protocol.Transaction.Contract.ContractType.TriggerSmartContract);
    Protocol.Transaction transaction = transactionCapsule.getInstance();
    BlockCapsule blockCapsule = new BlockCapsule(Protocol.Block.newBuilder().setBlockHeader(
        Protocol.BlockHeader.newBuilder().setRawData(Protocol.BlockHeader.raw.newBuilder()
            .setParentHash(ByteString.copyFrom(ByteArray.fromHexString(
                "0304f784e4e7bae517bcab94c3e0c9214fb4ac7ff9d7d5a937d1f40031f87b82")))
            .setNumber(9))).addTransactions(transaction).build());

    TransactionResult transactionResult = new TransactionResult(blockCapsule, 0, transaction,
        100, 1, wallet);
    Assert.assertEquals(transactionResult.getBlockNumber(), "0x9");
    Assert.assertEquals("0x5691531881bc44adbc722060d85fdf29265823db8e884b0d104fcfbba253cf11",
        transactionResult.getHash());
    Assert.assertEquals(transactionResult.getGasPrice(), "0x1");
    Assert.assertEquals(transactionResult.getGas(), "0x64");
    Assert.assertEquals("0x0", transactionResult.getNonce());
    assertQuantity(transactionResult.getNonce());
  }

  @Test
  public void testBuildTransactionResult() {
    SmartContractOuterClass.TriggerSmartContract.Builder builder2 =
        SmartContractOuterClass.TriggerSmartContract.newBuilder()
            .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(OWNER_ADDRESS)))
            .setContractAddress(ByteString.copyFrom(ByteArray.fromHexString(CONTRACT_ADDRESS)));
    TransactionCapsule transactionCapsule = new TransactionCapsule(builder2.build(),
        Protocol.Transaction.Contract.ContractType.TriggerSmartContract);

    TransactionResult transactionResult =
        new TransactionResult(transactionCapsule.getInstance(), wallet);
    Assert.assertEquals("0x5691531881bc44adbc722060d85fdf29265823db8e884b0d104fcfbba253cf11",
        transactionResult.getHash());
    Assert.assertEquals(transactionResult.getGasPrice(), "0x");
    Assert.assertEquals("0x0", transactionResult.getNonce());
    assertQuantity(transactionResult.getNonce());
  }

  private Protocol.Transaction buildBaseTransaction() {
    SmartContractOuterClass.TriggerSmartContract.Builder builder =
        SmartContractOuterClass.TriggerSmartContract.newBuilder()
            .setOwnerAddress(ByteString.copyFrom(ByteArray.fromHexString(OWNER_ADDRESS)))
            .setContractAddress(ByteString.copyFrom(ByteArray.fromHexString(CONTRACT_ADDRESS)));
    return new TransactionCapsule(builder.build(),
        Protocol.Transaction.Contract.ContractType.TriggerSmartContract).getInstance();
  }

  // r[0..32] + s[32..64] + v[64], v stored as revId 0 so parseSignature normalizes it to 27.
  private byte[] buildSignature() {
    byte[] sign = new byte[65];
    for (int i = 0; i < 32; i++) {
      sign[i] = (byte) (i + 1); // r
    }
    for (int i = 32; i < 64; i++) {
      sign[i] = (byte) (i + 1); // s
    }
    sign[64] = 0;
    return sign;
  }

  private Protocol.PQAuthSig buildPqAuthSig() {
    return Protocol.PQAuthSig.newBuilder()
        .setScheme(Protocol.PQScheme.ML_DSA_44)
        .setPublicKey(ByteString.copyFrom(new byte[] {1, 2, 3}))
        .setSignature(ByteString.copyFrom(new byte[] {4, 5, 6}))
        .build();
  }

  @Test
  public void testParseSignatureWithNoSignature() {
    TransactionResult transactionResult =
        new TransactionResult(buildBaseTransaction(), wallet);
    // No ECDSA signature and no PQ signature: v/r/s fall back to zero padding.
    Assert.assertEquals(ByteArray.toJsonHex(new byte[1]), transactionResult.getV());
    Assert.assertEquals(ByteArray.toJsonHex(new byte[32]), transactionResult.getR());
    Assert.assertEquals(ByteArray.toJsonHex(new byte[32]), transactionResult.getS());
    Assert.assertNull(transactionResult.getPqAuthSigList());
  }

  @Test
  public void testParseSignatureWithEcdsaSignatureOnly() {
    byte[] sign = buildSignature();
    Protocol.Transaction transaction = buildBaseTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(sign))
        .build();

    TransactionResult transactionResult = new TransactionResult(transaction, wallet);
    Assert.assertEquals(ByteArray.toJsonHex(java.util.Arrays.copyOfRange(sign, 0, 32)),
        transactionResult.getR());
    Assert.assertEquals(ByteArray.toJsonHex(java.util.Arrays.copyOfRange(sign, 32, 64)),
        transactionResult.getS());
    // revId 0 is normalized to 27 (0x1b).
    Assert.assertEquals(ByteArray.toJsonHex(new byte[] {27}), transactionResult.getV());
    Assert.assertNull(transactionResult.getPqAuthSigList());
  }

  @Test
  public void testParseSignatureWithPqAuthSigOnly() {
    Protocol.PQAuthSig pqAuthSig = buildPqAuthSig();
    Protocol.Transaction transaction = buildBaseTransaction().toBuilder()
        .addPqAuthSig(pqAuthSig)
        .build();

    TransactionResult transactionResult = new TransactionResult(transaction, wallet);
    // No ECDSA signature: v/r/s fall back to zero padding.
    Assert.assertEquals(ByteArray.toJsonHex(new byte[1]), transactionResult.getV());
    Assert.assertEquals(ByteArray.toJsonHex(new byte[32]), transactionResult.getR());
    Assert.assertEquals(ByteArray.toJsonHex(new byte[32]), transactionResult.getS());
    Assert.assertNotNull(transactionResult.getPqAuthSigList());
    Assert.assertEquals(1, transactionResult.getPqAuthSigList().size());
    TransactionResult.PQAuthSigResult result = transactionResult.getPqAuthSigList().get(0);
    Assert.assertEquals(pqAuthSig.getScheme().name(), result.getScheme());
    Assert.assertEquals(ByteArray.toJsonHex(pqAuthSig.getPublicKey().toByteArray()),
        result.getPublicKey());
    Assert.assertEquals(ByteArray.toJsonHex(pqAuthSig.getSignature().toByteArray()),
        result.getSignature());
  }

  @Test
  public void testParseSignatureWithEcdsaAndPqAuthSig() {
    byte[] sign = buildSignature();
    Protocol.PQAuthSig pqAuthSig = buildPqAuthSig();
    Protocol.Transaction transaction = buildBaseTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(sign))
        .addPqAuthSig(pqAuthSig)
        .build();

    TransactionResult transactionResult = new TransactionResult(transaction, wallet);
    Assert.assertEquals(ByteArray.toJsonHex(java.util.Arrays.copyOfRange(sign, 0, 32)),
        transactionResult.getR());
    Assert.assertEquals(ByteArray.toJsonHex(java.util.Arrays.copyOfRange(sign, 32, 64)),
        transactionResult.getS());
    Assert.assertEquals(ByteArray.toJsonHex(new byte[] {27}), transactionResult.getV());
    Assert.assertNotNull(transactionResult.getPqAuthSigList());
    Assert.assertEquals(1, transactionResult.getPqAuthSigList().size());
    Assert.assertEquals(pqAuthSig, transactionResult.getPqAuthSigList().get(0));
  }

}
