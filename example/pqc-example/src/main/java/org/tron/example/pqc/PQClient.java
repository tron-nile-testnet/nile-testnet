package org.tron.example.pqc;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import org.tron.api.GrpcAPI.EmptyMessage;
import org.tron.api.GrpcAPI.Return;
import org.tron.api.WalletGrpc;
import org.tron.api.WalletGrpc.WalletBlockingStub;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.BalanceContract.TransferContract;

/**
 * Demo client that connects to {@link PQWitnessNode} and broadcasts a
 * PQ-signed transfer transaction. Scheme is selected via {@code -Dpqc.scheme}
 * (FN_DSA_512 or ML_DSA_44, default FN_DSA_512) and must match the witness node.
 *
 * The keypair is derived from the same fixed seed used by PQWitnessNode, so no
 * out-of-band key exchange is needed.
 *
 * Usage:
 *   Terminal 1 — start the witness node first:
 *     ./gradlew :example:pqc-example:run -PmainClass=org.tron.example.pqc.PQWitnessNode
 *   Terminal 2 — broadcast a PQC transaction:
 *     ./gradlew :example:pqc-example:run -PmainClass=org.tron.example.pqc.PQClient
 *
 * Optional JVM args:
 *   -Dpqc.scheme=FN_DSA_512  (default; or ML_DSA_44)
 *   -Dpqc.host=localhost     (default: localhost)
 *   -Dpqc.port=50051         (default: 50051)
 */
public class PQClient {

  private static final PQScheme PQ_SCHEME = PQScheme.valueOf(
      System.getProperty("pqc.scheme", PQWitnessNode.PQ_SCHEME.name()));
  private static final String HOST = System.getProperty("pqc.host", "localhost");
  private static final int PORT = Integer.parseInt(System.getProperty("pqc.port", "50051"));

  /** Recipient of the demo transfer. */
  private static final byte[] TO_ADDR =
      ByteArray.fromHexString("41f522cc20ca18b636bdd93b4fb15ea84cc2b4e001");

  public static void main(String[] args) throws Exception {
    // Force INFO level: logback-test.xml (on the test classpath) sets root=DEBUG
    // which is far too noisy for a demo run.
    ((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
        .getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME))
        .setLevel(ch.qos.logback.classic.Level.INFO);

    // ── 1. Derive user keypair from same fixed seed as PQWitnessNode ─────
    byte[] userSeed = new byte[PQSchemeRegistry.getSeedLength(PQ_SCHEME)];
    Arrays.fill(userSeed, (byte) 0x02);
    PQSignature userKp = PQSchemeRegistry.fromSeed(PQ_SCHEME, userSeed);

    byte[] userPub    = userKp.getPublicKey();
    byte[] signerAddr = userKp.getAddress();
    byte[] ownerAddr  = PQWitnessNode.USER_ADDR;

    System.out.println("=== PQC Client ===");
    System.out.println("Scheme:         " + PQ_SCHEME);
    System.out.println("Connecting to " + HOST + ":" + PORT);
    System.out.println("Owner address:  " + ByteArray.toHexString(ownerAddr));
    System.out.println("Signer address: " + ByteArray.toHexString(signerAddr));

    // ── 2. Connect via gRPC ───────────────────────────────────────────────
    ManagedChannel channel = ManagedChannelBuilder.forAddress(HOST, PORT).usePlaintext().build();
    WalletBlockingStub stub = WalletGrpc.newBlockingStub(channel)
        .withDeadlineAfter(10, TimeUnit.SECONDS);

    try {
      // ── 3. Fetch reference block for TaPoS ───────────────────────────
      Block head = stub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long   refNum    = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = Sha256Hash.of(
          CommonParameter.getInstance().isECKeyCryptoEngine(), headerRaw).getBytes();

      System.out.println("Reference block: #" + refNum
          + " hash=" + ByteArray.toHexString(Arrays.copyOfRange(blockHash, 0, 8)) + "...");

      // ── 4. Build the transfer transaction ─────────────────────────────
      Transaction.raw rawData = Transaction.raw.newBuilder()
          .addContract(Transaction.Contract.newBuilder()
              .setType(ContractType.TransferContract)
              .setParameter(Any.pack(TransferContract.newBuilder()
                  .setOwnerAddress(ByteString.copyFrom(ownerAddr))
                  .setToAddress(ByteString.copyFrom(TO_ADDR))
                  .setAmount(1_000_000L)  // 1 TRX
                  .build()))
              .setPermissionId(0))
          // TaPoS fields
          .setRefBlockHash(ByteString.copyFrom(Arrays.copyOfRange(blockHash, 8, 16)))
          .setRefBlockBytes(ByteString.copyFrom(longToBytes(refNum), 6, 2))
          .setExpiration(System.currentTimeMillis() + 60_000L)
          .build();

      Transaction tx = Transaction.newBuilder().setRawData(rawData).build();

      // ── 5. Sign with selected PQ scheme ─────────────────────────────────
      byte[] txId   = Sha256Hash.of(
          CommonParameter.getInstance().isECKeyCryptoEngine(),
          rawData.toByteArray()).getBytes();
      byte[] sig    = userKp.sign(txId);

      // Producers must set the scheme tag explicitly; scheme=0
      // (UNKNOWN_PQ_SCHEME) is rejected by the verifier as unregistered.
      Transaction signedTx = tx.toBuilder()
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setScheme(PQ_SCHEME)
              .setPublicKey(ByteString.copyFrom(userPub))
              .setSignature(ByteString.copyFrom(sig)))
          .build();

      System.out.println("TX id: " + ByteArray.toHexString(txId));

      // ── 6. Broadcast ──────────────────────────────────────────────────
      Return result = stub.broadcastTransaction(signedTx);
      System.out.println("Broadcast result: " + result.getCode()
          + " — " + result.getMessage().toStringUtf8());

      if (result.getResult()) {
        System.out.println("SUCCESS: PQC-signed transaction accepted by the node.");
      } else {
        System.out.println("REJECTED: " + result.getCode());
      }

    } finally {
      channel.shutdown();
      channel.awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  private static byte[] longToBytes(long value) {
    return ByteBuffer.allocate(8).putLong(value).array();
  }
}
