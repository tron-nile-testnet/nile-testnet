package org.tron.example.pqc;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import org.tron.api.GrpcAPI.EmptyMessage;
import org.tron.api.GrpcAPI.Return;
import org.tron.api.WalletGrpc;
import org.tron.api.WalletGrpc.WalletBlockingStub;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.math.StrictMathWrapper;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.ByteArray;
import org.tron.common.crypto.Hash;
import org.tron.common.utils.Commons;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.BalanceContract.TransferContract;
import org.tron.protos.contract.SmartContractOuterClass.TriggerSmartContract;

/**
 * Demo client that connects to {@link PQWitnessNode} and continuously broadcasts transfer
 * and TRC20 transactions signed by every registered PQ scheme (FN-DSA-512 and ML-DSA-44)
 * in parallel, plus a parallel ECDSA stream. The witness node activates both PQ schemes
 * and gives the demo user account an owner permission with one signer key per scheme, so
 * either signature satisfies the threshold-1 owner permission.
 * <p>
 * PQ keypairs are derived from the same fixed seeds used by PQWitnessNode, so no
 * out-of-band key exchange is needed. ECDSA transactions use -Decdsa.private.key.
 * <p>
 * Run from the repository root:
 *   ./gradlew :example:pqc-example:run -PmainClass=org.tron.example.pqc.PQTxSender
 *
 * Optional JVM args:
 *   -Dpqc.host=localhost
 *   -Dpqc.port=50051
 *   -Dpqc.fn-dsa-512.transfer.tps=5  (per-scheme transfer rate; 0 disables that stream)
 *   -Dpqc.fn-dsa-512.trc20.tps=0
 *   -Dpqc.ml-dsa-44.transfer.tps=5
 *   -Dpqc.ml-dsa-44.trc20.tps=0
 *   -Decdsa.private.key=1234567890123456789012345678901234567890123456789012345678901234
 *   -Decdsa.transfer.tps=5
 *   -Decdsa.trc20.tps=0
 */
public class PQTxSender {

  private static final String HOST = System.getProperty("pqc.host", "localhost");
  private static final int PORT = Integer.parseInt(System.getProperty("pqc.port", "50051"));

  /**
   * Recipient of the demo transfer.
   */
  private static final byte[] TO_ADDR =
      Commons.decodeFromBase58Check("TKmyxLsRR2FWMVEHaQA2pZh1xB7oXPXzG1");

  /**
   * TRC20 contract address (USDT on TRON).
   */
  private static final byte[] TRC20_CONTRACT_ADDR =
      Commons.decodeFromBase58Check("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");

  /**
   * Demo TRC20 amount in base units (6 decimals = 1 token).
   */
  private static final long TRC20_AMOUNT = 1L;

  /**
   * Upper bound for TRC20 execution fee.
   */
  private static final long TRC20_FEE_LIMIT = 1000_000_000L;

  /**
   * Default demo ECDSA private key. Override it with -Decdsa.private.key for a funded account.
   */
  private static final String DEFAULT_ECDSA_PRIVATE_KEY =
      "1234567890123456789012345678901234567890123456789012345678901234";

  /**
   * Per-scheme default send rates. Split so each PQ algorithm can be tuned
   * independently from the others (Falcon-512 signing is ~2× slower than
   * ML-DSA-44, so operators often run Falcon at a lower default rate).
   */
  private static final Map<PQScheme, Double> DEFAULT_PQ_TRANSFER_TPS;
  private static final Map<PQScheme, Double> DEFAULT_PQ_TRC20_TPS;

  static {
    Map<PQScheme, Double> transfer = new EnumMap<>(PQScheme.class);
    transfer.put(PQScheme.FN_DSA_512, 5.0d);
    transfer.put(PQScheme.ML_DSA_44, 5.0d);
    DEFAULT_PQ_TRANSFER_TPS = transfer;

    Map<PQScheme, Double> trc20 = new EnumMap<>(PQScheme.class);
    trc20.put(PQScheme.FN_DSA_512, 0d);
    trc20.put(PQScheme.ML_DSA_44, 0d);
    DEFAULT_PQ_TRC20_TPS = trc20;
  }

  /** Default send rate for ECDSA transfer transactions. */
  private static final double DEFAULT_ECDSA_TRANSFER_TPS = 5.0d;
  /** Default send rate for ECDSA TRC20 transactions. */
  private static final double DEFAULT_ECDSA_TRC20_TPS = 0d;

  public static void main(String[] args) throws Exception {
    // Force INFO level: logback-test.xml (on the test classpath) sets root=DEBUG
    // which is far too noisy for a demo run.
    ((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
        .getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME))
        .setLevel(ch.qos.logback.classic.Level.INFO);

    // byte[] ownerAddr = Commons.decodeFromBase58Check("TJUfbazhixG4YtqJxUDmv5XisZvvy1wP91");
    byte[] ownerAddr = PQWitnessNode.USER_ADDR;

    // ── 1. Derive a user keypair per registered PQ scheme (same seed as
    //      PQWitnessNode), and parse per-scheme TPS knobs. ─────────────────
    Map<PQScheme, PQSignature> pqKeypairs = new EnumMap<>(PQScheme.class);
    Map<PQScheme, Double> pqTransferTps = new EnumMap<>(PQScheme.class);
    Map<PQScheme, Double> pqTrc20Tps = new EnumMap<>(PQScheme.class);
    for (PQScheme scheme : PQSchemeRegistry.registeredSchemes()) {
      byte[] userSeed = new byte[PQSchemeRegistry.getSeedLength(scheme)];
      Arrays.fill(userSeed, (byte) 0x02);
      pqKeypairs.put(scheme, PQSchemeRegistry.fromSeed(scheme, userSeed));
      pqTransferTps.put(scheme,
          readTps("pqc." + tpsKey(scheme) + ".transfer.tps",
              DEFAULT_PQ_TRANSFER_TPS.get(scheme)));
      pqTrc20Tps.put(scheme,
          readTps("pqc." + tpsKey(scheme) + ".trc20.tps",
              DEFAULT_PQ_TRC20_TPS.get(scheme)));
    }

    ECKey ecdsaKey = ECKey.fromPrivate(
        ByteArray.fromHexString(System.getProperty("ecdsa.private.key",
            DEFAULT_ECDSA_PRIVATE_KEY)));
    byte[] ecdsaOwnerAddr = ecdsaKey.getAddress();
    double ecdsaTransferTps = readTps("ecdsa.transfer.tps", DEFAULT_ECDSA_TRANSFER_TPS);
    double ecdsaTrc20Tps = readTps("ecdsa.trc20.tps", DEFAULT_ECDSA_TRC20_TPS);

    System.out.println("=== PQC/ECDSA Tx Sender ===");
    System.out.println("Connecting to " + HOST + ":" + PORT);
    System.out.println("PQC owner address:    " + ByteArray.toHexString(ownerAddr));
    for (Map.Entry<PQScheme, PQSignature> entry : pqKeypairs.entrySet()) {
      PQScheme scheme = entry.getKey();
      System.out.println("PQC signer (" + scheme + "): "
          + ByteArray.toHexString(entry.getValue().getAddress())
          + "  transfer TPS=" + pqTransferTps.get(scheme)
          + "  trc20 TPS=" + pqTrc20Tps.get(scheme));
    }
    System.out.println("ECDSA owner address:  " + ByteArray.toHexString(ecdsaOwnerAddr));
    System.out.println("ECDSA transfer TPS:   " + ecdsaTransferTps);
    System.out.println("ECDSA TRC20 TPS:      " + ecdsaTrc20Tps);

    // ── 2. Connect via gRPC ───────────────────────────────────────────────
    ManagedChannel channel = ManagedChannelBuilder.forAddress(HOST, PORT).usePlaintext().build();
    WalletBlockingStub stub = WalletGrpc.newBlockingStub(channel);

    try {
      List<Thread> threads = new ArrayList<>();
      for (Map.Entry<PQScheme, PQSignature> entry : pqKeypairs.entrySet()) {
        PQScheme scheme = entry.getKey();
        PQSignature kp = entry.getValue();
        double transferTps = pqTransferTps.get(scheme);
        double trc20Tps = pqTrc20Tps.get(scheme);
        threads.add(new Thread(
            () -> runTransferLoop(stub, ownerAddr, kp, scheme, transferTps),
            "pqc-" + tpsKey(scheme) + "-transfer-sender-grpc"));
        threads.add(new Thread(
            () -> runTrc20Loop(stub, ownerAddr, kp, scheme, trc20Tps),
            "pqc-" + tpsKey(scheme) + "-trc20-sender-grpc"));
      }
      threads.add(new Thread(
          () -> runEcdsaTransferLoop(stub, ecdsaOwnerAddr, ecdsaKey, ecdsaTransferTps),
          "ecdsa-transfer-sender-grpc"));
      threads.add(new Thread(
          () -> runEcdsaTrc20Loop(stub, ecdsaOwnerAddr, ecdsaKey, ecdsaTrc20Tps),
          "ecdsa-trc20-sender-grpc"));

      for (Thread t : threads) {
        t.start();
      }
      for (Thread t : threads) {
        t.join();
      }
    } finally {
      channel.shutdown();
      channel.awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  /** Lowercase, hyphenated form of the scheme name for tag/property keys. */
  private static String tpsKey(PQScheme scheme) {
    return scheme.name().toLowerCase(Locale.ROOT).replace('_', '-');
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static byte[] ecdsaTxId(Transaction tx) {
    return Sha256Hash.hash(CommonParameter.getInstance().isECKeyCryptoEngine(),
        tx.getRawData().toByteArray());
  }

  private static byte[] longToBytes(long value) {
    return ByteBuffer.allocate(8).putLong(value).array();
  }

  private static void runTransferLoop(WalletBlockingStub stub, byte[] ownerAddr,
      PQSignature userKp, PQScheme scheme, double tps) {
    if (tps <= 0) {
      System.out.println("pqc transfer sender disabled for " + scheme);
      return;
    }
    long intervalMs = tpsToIntervalMs(tps);
    long counter = 1L;
    while (!Thread.currentThread().isInterrupted()) {
      long loopStart = System.currentTimeMillis();
      sendTransferTransaction(stub, ownerAddr, userKp, scheme, counter++);
      sleepRemaining(intervalMs, loopStart);
    }
  }

  private static void runTrc20Loop(WalletBlockingStub stub, byte[] ownerAddr,
      PQSignature userKp, PQScheme scheme, double tps) {
    if (tps <= 0) {
      System.out.println("pqc trc20 sender disabled for " + scheme);
      return;
    }
    long intervalMs = tpsToIntervalMs(tps);
    long counter = 1L;
    while (!Thread.currentThread().isInterrupted()) {
      long loopStart = System.currentTimeMillis();
      sendTrc20Transaction(stub, ownerAddr, userKp, scheme, counter++);
      sleepRemaining(intervalMs, loopStart);
    }
  }

  private static void runEcdsaTransferLoop(WalletBlockingStub stub, byte[] ownerAddr,
      ECKey ecdsaKey, double tps) {
    if (tps <= 0) {
      System.out.println("ecdsa transfer sender disabled");
      return;
    }
    long intervalMs = tpsToIntervalMs(tps);
    long counter = 1L;
    while (!Thread.currentThread().isInterrupted()) {
      long loopStart = System.currentTimeMillis();
      sendEcdsaTransferTransaction(stub, ownerAddr, ecdsaKey, counter++);
      sleepRemaining(intervalMs, loopStart);
    }
  }

  private static void runEcdsaTrc20Loop(WalletBlockingStub stub, byte[] ownerAddr,
      ECKey ecdsaKey, double tps) {
    if (tps <= 0) {
      System.out.println("ecdsa trc20 sender disabled");
      return;
    }
    long intervalMs = tpsToIntervalMs(tps);
    long counter = 1L;
    while (!Thread.currentThread().isInterrupted()) {
      long loopStart = System.currentTimeMillis();
      sendEcdsaTrc20Transaction(stub, ownerAddr, ecdsaKey, counter++);
      sleepRemaining(intervalMs, loopStart);
    }
  }

  private static void sendTransferTransaction(WalletBlockingStub stub, byte[] ownerAddr,
      PQSignature userKp, PQScheme scheme, long seq) {
    String tag = "pqc-" + tpsKey(scheme) + "-transfer-" + seq;
    try {
      WalletBlockingStub timedStub = stub.withDeadlineAfter(10, TimeUnit.SECONDS);

      // Fetch the latest block for TaPoS before every send so the demo stays valid
      // even if the node advances quickly.
      Block head = timedStub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long refNum = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = sha256(headerRaw);

      Transaction tx = buildTransferTransaction(ownerAddr, blockHash, refNum);
      byte[] txId = sha256(tx.getRawData().toByteArray());
      byte[] sig = userKp.sign(txId);
      Transaction signedTx = tx.toBuilder()
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setScheme(scheme)
              .setPublicKey(ByteString.copyFrom(userKp.getPublicKey()))
              .setSignature(ByteString.copyFrom(sig)))
          .build();

      Return result = timedStub.broadcastTransaction(signedTx);
      System.out.println("[" + tag + "] ref=#" + refNum
          + " tx=" + ByteArray.toHexString(txId)
          + " result=" + result.getCode());
    } catch (Exception e) {
      System.err.println("[" + tag + "] send failed: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private static void sendTrc20Transaction(WalletBlockingStub stub, byte[] ownerAddr,
      PQSignature userKp, PQScheme scheme, long seq) {
    String tag = "pqc-" + tpsKey(scheme) + "-trc20-" + seq;
    try {
      WalletBlockingStub timedStub = stub.withDeadlineAfter(10, TimeUnit.SECONDS);

      // Fetch the latest block for TaPoS before every send so the demo stays valid
      // even if the node advances quickly.
      Block head = timedStub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long refNum = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = sha256(headerRaw);

      Transaction tx = buildTrc20Transaction(ownerAddr, blockHash, refNum);
      Transaction.raw.Builder rawBuilder = tx.getRawData().toBuilder();
      rawBuilder.setFeeLimit(TRC20_FEE_LIMIT);
      tx = tx.toBuilder().setRawData(rawBuilder).build();

      byte[] txId = sha256(tx.getRawData().toByteArray());
      byte[] sig = userKp.sign(txId);
      Transaction signedTx = tx.toBuilder()
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setScheme(scheme)
              .setPublicKey(ByteString.copyFrom(userKp.getPublicKey()))
              .setSignature(ByteString.copyFrom(sig)))
          .build();

      Return result = timedStub.broadcastTransaction(signedTx);
      System.out.println("[" + tag + "] ref=#" + refNum
          + " tx=" + ByteArray.toHexString(txId)
          + " result=" + result.getCode());
    } catch (Exception e) {
      System.err.println("[" + tag + "] send failed: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private static void sendEcdsaTransferTransaction(WalletBlockingStub stub, byte[] ownerAddr,
      ECKey ecdsaKey, long seq) {
    try {
      WalletBlockingStub timedStub = stub.withDeadlineAfter(10, TimeUnit.SECONDS);

      Block head = timedStub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long refNum = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = sha256(headerRaw);

      Transaction tx = buildTransferTransaction(ownerAddr, blockHash, refNum);
      byte[] txId = ecdsaTxId(tx);
      Transaction signedTx = signWithEcdsa(tx, ecdsaKey, txId);

      Return result = timedStub.broadcastTransaction(signedTx);
      System.out.println("[ecdsa-transfer-" + seq + "] ref=#" + refNum
          + " tx=" + ByteArray.toHexString(txId)
          + " result=" + result.getCode());
    } catch (Exception e) {
      System.err.println("[ecdsa-transfer-" + seq + "] send failed: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private static void sendEcdsaTrc20Transaction(WalletBlockingStub stub, byte[] ownerAddr,
      ECKey ecdsaKey, long seq) {
    try {
      WalletBlockingStub timedStub = stub.withDeadlineAfter(10, TimeUnit.SECONDS);

      Block head = timedStub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long refNum = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = sha256(headerRaw);

      Transaction tx = buildTrc20Transaction(ownerAddr, blockHash, refNum);
      Transaction.raw.Builder rawBuilder = tx.getRawData().toBuilder();
      rawBuilder.setFeeLimit(TRC20_FEE_LIMIT);
      tx = tx.toBuilder().setRawData(rawBuilder).build();

      byte[] txId = ecdsaTxId(tx);
      Transaction signedTx = signWithEcdsa(tx, ecdsaKey, txId);

      Return result = timedStub.broadcastTransaction(signedTx);
      System.out.println("[ecdsa-trc20-" + seq + "] ref=#" + refNum
          + " tx=" + ByteArray.toHexString(txId)
          + " result=" + result.getCode());
    } catch (Exception e) {
      System.err.println("[ecdsa-trc20-" + seq + "] send failed: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private static Transaction signWithEcdsa(Transaction tx, ECKey ecdsaKey, byte[] txId) {
    ECDSASignature signature = ecdsaKey.sign(txId);
    return tx.toBuilder().addSignature(ByteString.copyFrom(signature.toByteArray())).build();
  }

  private static Transaction buildTransferTransaction(byte[] ownerAddr, byte[] blockHash,
      long refNum) {
    Transaction.raw rawData = Transaction.raw.newBuilder()
        .addContract(Transaction.Contract.newBuilder()
            .setType(ContractType.TransferContract)
            .setParameter(Any.pack(TransferContract.newBuilder()
                .setOwnerAddress(ByteString.copyFrom(ownerAddr))
                .setToAddress(ByteString.copyFrom(TO_ADDR))
                .setAmount(1L)
                .build()))
            .setPermissionId(0))
        .setRefBlockHash(ByteString.copyFrom(Arrays.copyOfRange(blockHash, 8, 16)))
        .setRefBlockBytes(ByteString.copyFrom(longToBytes(refNum), 6, 2))
        .setExpiration(randomExpiration())
        .build();
    return Transaction.newBuilder().setRawData(rawData).build();
  }

  private static Transaction buildTrc20Transaction(byte[] ownerAddr, byte[] blockHash,
      long refNum) {
    TriggerSmartContract trigger = TriggerSmartContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(ownerAddr))
        .setContractAddress(ByteString.copyFrom(TRC20_CONTRACT_ADDR))
        .setData(ByteString.copyFrom(encodeTransferCall(TO_ADDR, TRC20_AMOUNT)))
        .setCallValue(0L)
        .build();
    TransactionCapsule trxCap = new TransactionCapsule(trigger, ContractType.TriggerSmartContract);
    Transaction tx = trxCap.getInstance();
    Transaction.raw.Builder rawBuilder = tx.getRawData().toBuilder();
    rawBuilder.setRefBlockHash(ByteString.copyFrom(Arrays.copyOfRange(blockHash, 8, 16)));
    rawBuilder.setRefBlockBytes(ByteString.copyFrom(longToBytes(refNum), 6, 2));
    rawBuilder.setExpiration(randomExpiration());
    return tx.toBuilder().setRawData(rawBuilder).build();
  }

  /**
   * ABI-encode a ERC20/TRC20 transfer(address,uint256) call.
   * Layout: 4-byte selector | 32-byte address (left-padded) | 32-byte amount (big-endian).
   * TRON addresses are 21 bytes (0x41 prefix); strip the prefix to get the 20-byte EVM address.
   */
  private static byte[] encodeTransferCall(byte[] tronAddr, long amount) {
    // selector = keccak256("transfer(address,uint256)")[0:4]
    byte[] selector = Arrays.copyOf(
        Hash.sha3(("transfer(address,uint256)").getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        4);
    // address word: 12 zero bytes + 20-byte EVM address (TRON addr minus 0x41 prefix)
    byte[] addrWord = new byte[32];
    System.arraycopy(tronAddr, 1, addrWord, 12, 20);
    // amount word: big-endian uint256
    byte[] amountWord = new byte[32];
    ByteBuffer.wrap(amountWord, 24, 8).putLong(amount);
    byte[] result = new byte[4 + 32 + 32];
    System.arraycopy(selector, 0, result, 0, 4);
    System.arraycopy(addrWord, 0, result, 4, 32);
    System.arraycopy(amountWord, 0, result, 36, 32);
    return result;
  }

  /**
   * Random expiration in [now + 60_000ms, now + 80_000_000ms]. tx_id =
   * sha256(rawData) and the signature is not part of the digest, so two threads
   * that share an owner address and emit byte-identical rawData would collide and
   * trip DUP_TRANSACTION_ERROR. Spreading expiration across an ~80M ms window
   * gives ~8e7 entropy per send — at 30 TPS, the per-3s-refBlock-window collision
   * chance is ~5.6e-6, more than enough for a long-running demo. The upper bound
   * stays well below the 24h server-side cap (Manager.validateCommon →
   * MAXIMUM_TIME_UNTIL_EXPIRATION = 86_400_000ms).
   */
  private static long randomExpiration() {
    long now = System.currentTimeMillis();
    return now + ThreadLocalRandom.current().nextLong(60_000L, 80_000_001L);
  }

  private static double readTps(String key, double defaultValue) {
    return Double.parseDouble(System.getProperty(key, Double.toString(defaultValue)));
  }

  private static long tpsToIntervalMs(double tps) {
    return StrictMathWrapper.max(1L, StrictMathWrapper.round(1000.0d / tps));
  }

  private static void sleepRemaining(long intervalMs, long loopStartMs) {
    long sleepMs = intervalMs - (System.currentTimeMillis() - loopStartMs);
    if (sleepMs > 0) {
      try {
        Thread.sleep(sleepMs);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }
}
