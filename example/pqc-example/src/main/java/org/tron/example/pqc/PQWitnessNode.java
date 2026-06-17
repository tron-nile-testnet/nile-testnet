package org.tron.example.pqc;

import com.google.protobuf.ByteString;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.application.Application;
import org.tron.common.application.ApplicationFactory;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.utils.ByteArray;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.consensus.ConsensusService;
import org.tron.core.db.Manager;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;

/**
 * Demo witness node with PQ block production. Scheme is selected via
 * {@code -Dpqc.scheme} (FN_DSA_512 or ML_DSA_44, default FN_DSA_512) and must
 * match what {@link PQClient} / {@link PQFullNode} use.
 *
 * Starts an in-process TRON node configured with a PQC witness keypair and
 * a user account that holds a PQ owner permission — ready to receive
 * transactions from {@link PQClient}.
 *
 * Keypairs are derived from fixed seeds so PQClient can derive matching keys
 * without any out-of-band coordination.
 *
 * Usage:
 *   Terminal 1 — start this node:
 *     ./gradlew :example:pqc-example:run -PmainClass=org.tron.example.pqc.PQWitnessNode
 *   Terminal 2 — broadcast a PQC transaction:
 *     ./gradlew :example:pqc-example:run -PmainClass=org.tron.example.pqc.PQClient
 */
public class PQWitnessNode {

  /**
   * Active PQ scheme used for block production (witness signs blocks with this
   * scheme). Selectable via {@code -Dpqc.scheme}. The on-chain user account
   * carries owner-permission keys for ALL registered PQ schemes, so PQTxSender
   * can broadcast transactions signed by either scheme regardless of which one
   * the witness uses to sign blocks.
   */
  static final PQScheme PQ_SCHEME = PQScheme.valueOf(
      System.getProperty("pqc.scheme", PQScheme.ML_DSA_44.name()));

  /** Per-scheme fixed seed for the PQ witness keypair (shared with PQClient). */
  static final Map<PQScheme, byte[]> WITNESS_SEEDS = filledSeeds((byte) 0x01);
  /** Per-scheme fixed seed for the PQ user keypair (shared with PQClient). */
  static final Map<PQScheme, byte[]> USER_SEEDS = filledSeeds((byte) 0x02);

  /** Active-scheme witness seed (kept for callers that don't iterate schemes). */
  static final byte[] WITNESS_SEED = WITNESS_SEEDS.get(PQ_SCHEME);
  /** Active-scheme user seed (kept for callers that don't iterate schemes). */
  static final byte[] USER_SEED = USER_SEEDS.get(PQ_SCHEME);

  /** gRPC port the node listens on. */
  static final int GRPC_PORT = 50051;

  /** Full-node HTTP port. */
  static final int HTTP_PORT = 8090;

  /** P2P listen port (shared with PQFullNode so it can dial in as a seed peer). */
  static final int P2P_PORT = 18888;

  private static final String DEFAULT_ECDSA_PRIVATE_KEY =
      "1234567890123456789012345678901234567890123456789012345678901234";

  /** Fixed on-chain address for the demo user account. */
  static final byte[] USER_ADDR =  ECKey.fromPrivate(
      ByteArray.fromHexString(DEFAULT_ECDSA_PRIVATE_KEY)).getAddress();

  public static void main(String[] args) throws Exception {
    // Force INFO level: logback-test.xml (on the test classpath) sets root=DEBUG
    // which is far too noisy for a demo run.
    ((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
        .getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME))
        .setLevel(ch.qos.logback.classic.Level.INFO);

    // ── 1. Derive deterministic keypairs ──────────────────────────────────
    // Active-scheme keypair drives block production; per-scheme user keypairs
    // populate the multi-key owner permission so transactions signed under any
    // registered PQ scheme verify against the same on-chain account.
    PQSignature witnessKp = PQSchemeRegistry.fromSeed(PQ_SCHEME, WITNESS_SEED);
    Map<PQScheme, PQSignature> userKps = new EnumMap<>(PQScheme.class);
    for (PQScheme scheme : PQSchemeRegistry.registeredSchemes()) {
      userKps.put(scheme, PQSchemeRegistry.fromSeed(scheme, USER_SEEDS.get(scheme)));
    }
    PQSignature userKp = userKps.get(PQ_SCHEME);

    byte[] witnessPub  = witnessKp.getPublicKey();
    byte[] witnessAddr = witnessKp.getAddress();
    byte[] userPub     = userKp.getPublicKey();
    byte[] signerAddr  = userKp.getAddress();

    System.out.println("=== PQC Witness Node ===");
    System.out.println("Block-producing scheme:       " + PQ_SCHEME);
    System.out.println("Witness address:              " + ByteArray.toHexString(witnessAddr));
    System.out.println("User address:                 " + ByteArray.toHexString(USER_ADDR));
    System.out.println("User signer (ECDSA): " + ByteArray.toHexString(USER_ADDR));
    for (Map.Entry<PQScheme, PQSignature> entry : userKps.entrySet()) {
      System.out.println("User signer (" + entry.getKey() + "): "
          + ByteArray.toHexString(entry.getValue().getAddress()));
    }
    System.out.println("gRPC port:                    " + GRPC_PORT);
    System.out.println("HTTP port:                    " + HTTP_PORT);
    System.out.println("P2P port:                     " + P2P_PORT);

    // ── 2. Configure node ─────────────────────────────────────────────────
    File dbDir = Files.createTempDirectory("pqc-node-").toFile();
    dbDir.deleteOnExit();

    // Inject the witness keypair via a temp JSON key file (derived from
    // WITNESS_SEED, matching what PQClient derives) referenced from a temp HOCON
    // config that includes config-test.conf.
    Path conf = writeWitnessConfig(witnessKp);

    Args.setParam(new String[]{"--output-directory", dbDir.getAbsolutePath(), "-w"},
        conf.toString());
    Args.getInstance().setRpcEnable(true);
    Args.getInstance().setFullNodeHttpEnable(true);
    Args.getInstance().setFullNodeHttpPort(HTTP_PORT);
    Args.getInstance().setRpcPort(GRPC_PORT);
    Args.getInstance().setNodeListenPort(P2P_PORT);
    Args.getInstance().setNeedSyncCheck(false);
    Args.getInstance().setMinEffectiveConnection(0);
    Args.getInstance().genesisBlock.setWitnesses(new ArrayList<>());

    // ── 3. Start Spring context ───────────────────────────────────────────
    TronApplicationContext context = new TronApplicationContext(DefaultConfig.class);
    Application app = ApplicationFactory.create(context);
    Manager db = context.getBean(Manager.class);
    ChainBaseManager chain = context.getBean(ChainBaseManager.class);

    // ── 4. Install PQ genesis pre-state (shared with PQFullNode) ─────────
    Map<PQScheme, byte[]> userPubs = new EnumMap<>(PQScheme.class);
    for (Map.Entry<PQScheme, PQSignature> entry : userKps.entrySet()) {
      userPubs.put(entry.getKey(), entry.getValue().getPublicKey());
    }
    installPQGenesisState(db, chain, witnessPub, userPubs);

    // ── 5. Start consensus (DposTask auto-produces blocks) ───────────────
    context.getBean(ConsensusService.class).start();

    // ── 6. Start gRPC / P2P server ───────────────────────────────────────
    app.startup();

    System.out.println("\nNode is running. Send Ctrl-C to stop.");
    System.out.println("Run PQClient or PQFullNode in another terminal.\n");

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      System.out.println("Shutting down...");
      context.close();
      Args.clearParam();
    }));

    Thread.currentThread().join(); // block until Ctrl-C
  }

  /**
   * Apply the PQ-specific pre-state that must exist on every node participating
   * in the demo network. Both PQWitnessNode and PQFullNode call this so their
   * genesis state matches before the first PQ block is produced / received.
   *
   * <p>{@code userPubs} carries one public key per registered PQ scheme; the
   * owner permission is built as a multi-key permission with threshold 1, so
   * a single signature under any included scheme satisfies it. This lets
   * PQTxSender send transactions signed by either FN-DSA-512 or ML-DSA-44
   * against the same on-chain account.
   */
  static void installPQGenesisState(Manager db, ChainBaseManager chain,
      byte[] witnessPub, Map<PQScheme, byte[]> userPubs) {
    byte[] witnessAddr = PQSchemeRegistry.computeAddress(PQ_SCHEME, witnessPub);
    ByteString witnessAddrBs = ByteString.copyFrom(witnessAddr);

    // Activate every registered PQ scheme so transactions signed under any of
    // them are accepted by the verifier.
    for (PQScheme scheme : PQSchemeRegistry.registeredSchemes()) {
      if (scheme == PQScheme.ML_DSA_44) {
        db.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
      } else if (scheme == PQScheme.FN_DSA_512) {
        db.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
      }
    }
    db.getDynamicPropertiesStore().saveAllowMultiSign(1L);

    // Witness account with PQ witness permission for the block-producing scheme.
    // Address-as-fingerprint binds the public key in-band; no separate pq_key
    // field is stored.
    Permission witnessPerm = Permission.newBuilder()
        .setType(PermissionType.Witness)
        .setId(1).setPermissionName("witness").setThreshold(1)
        .addKeys(Key.newBuilder()
            .setAddress(witnessAddrBs).setWeight(1))
        .build();
    db.getAccountStore().put(witnessAddr, new AccountCapsule(Account.newBuilder()
        .setAddress(witnessAddrBs).setType(AccountType.Normal)
        .setBalance(1_000_000_000L).setIsWitness(true)
        .setWitnessPermission(witnessPerm).build()));

    // The witness must be in the witness store BEFORE consensus starts so that
    // DposService.start() includes it in the active-witness schedule.
    chain.getWitnessStore().put(witnessAddr, new WitnessCapsule(witnessAddrBs));
    chain.getWitnessScheduleStore().saveActiveWitnesses(new ArrayList<>());
    chain.addWitness(witnessAddrBs);

    // User account with one owner-permission key per registered PQ scheme.
    // Threshold 1 ⇒ a single signature under any included scheme passes.
    Permission.Builder userOwnerPerm = Permission.newBuilder()
        .setType(PermissionType.Owner).setPermissionName("owner").setThreshold(1);
    for (Map.Entry<PQScheme, byte[]> entry : userPubs.entrySet()) {
      byte[] signerAddr = PQSchemeRegistry.computeAddress(entry.getKey(), entry.getValue());
      userOwnerPerm.addKeys(Key.newBuilder()
          .setAddress(ByteString.copyFrom(signerAddr)).setWeight(1));
    }
    userOwnerPerm.addKeys(Key.newBuilder().setAddress(ByteString.copyFrom(USER_ADDR)).setWeight(1));
    AccountCapsule userCapsule = new AccountCapsule(
        ByteString.copyFrom(USER_ADDR), ByteString.copyFromUtf8("pquser"), AccountType.Normal);
    userCapsule.setBalance(100_000_000_000_000L); // 100000000 TRX
    userCapsule.updatePermissions(userOwnerPerm.build(), null, Collections.emptyList());
    db.getAccountStore().put(USER_ADDR, userCapsule);
  }

  private static Map<PQScheme, byte[]> filledSeeds(byte value) {
    Map<PQScheme, byte[]> seeds = new EnumMap<>(PQScheme.class);
    for (PQScheme scheme : PQSchemeRegistry.registeredSchemes()) {
      byte[] seed = new byte[PQSchemeRegistry.getSeedLength(scheme)];
      Arrays.fill(seed, value);
      seeds.put(scheme, seed);
    }
    return Collections.unmodifiableMap(seeds);
  }

  private static Path writeWitnessConfig(PQSignature witnessKp) throws java.io.IOException {
    // Write the keypair to a JSON key file, then reference its path from the node
    // config. For schemes whose expanded sk lets BC recover the pk (ML-DSA-44),
    // emit privateKey only; otherwise emit privateKey + publicKey (Falcon-512,
    // since BC has no public path from (f, g) to h — see bcgit/bc-java#2297).
    Path keyFile = Files.createTempFile("pqc-witness-key-", ".json");
    keyFile.toFile().deleteOnExit();
    StringBuilder json = new StringBuilder()
        .append("{\n")
        .append("  \"scheme\": \"").append(PQ_SCHEME.name()).append("\",\n")
        .append("  \"privateKey\": \"").append(Hex.toHexString(witnessKp.getPrivateKey()))
        .append("\"");
    if (!PQSchemeRegistry.canDerivePublicKey(PQ_SCHEME)) {
      json.append(",\n  \"publicKey\": \"")
          .append(Hex.toHexString(witnessKp.getPublicKey())).append("\"");
    }
    json.append("\n}\n");
    Files.write(keyFile, json.toString().getBytes(StandardCharsets.UTF_8));

    Path conf = Files.createTempFile("pqc-witness-", ".conf");
    conf.toFile().deleteOnExit();
    String keyPath = keyFile.toAbsolutePath().toString().replace("\\", "\\\\");
    String body = "include classpath(\"config-test.conf\")\n"
        + "localPqWitness = {\n"
        + "  keys = [\n"
        + "    \"" + keyPath + "\"\n"
        + "  ]\n"
        + "}\n";
    Files.write(conf, body.getBytes(StandardCharsets.UTF_8));
    return conf;
  }
}
