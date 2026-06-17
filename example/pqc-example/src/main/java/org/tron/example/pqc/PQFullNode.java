package org.tron.example.pqc;

import java.io.File;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import org.tron.common.application.Application;
import org.tron.common.application.ApplicationFactory;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.utils.ByteArray;
import org.tron.core.ChainBaseManager;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.db.Manager;
import org.tron.protos.Protocol.PQScheme;

/**
 * Demo fullnode that dials {@link PQWitnessNode} via P2P and syncs PQ-signed blocks.
 * The active scheme follows {@link PQWitnessNode#PQ_SCHEME} (selectable via
 * {@code -Dpqc.scheme}), so both processes derive matching genesis state.
 *
 * Both nodes share the same deterministic PQ genesis pre-state (witness account with a
 * PQ witness permission + demo user account with a PQ owner permission),
 * installed via {@link PQWitnessNode#installPQGenesisState}. Once the witness produces
 * a block it is broadcast over P2P; this node validates {@code BlockHeader.pq_auth_sig}
 * against the same on-chain public key and applies the block.
 *
 * Usage:
 *   Terminal 1 — start the witness node first:
 *     ./gradlew :example:pqc-example:run -PmainClass=org.tron.example.pqc.PQWitnessNode
 *   Terminal 2 — start a fullnode that syncs from it:
 *     ./gradlew :example:pqc-example:run -PmainClass=org.tron.example.pqc.PQFullNode
 *
 * Optional JVM args:
 *   -Dpqc.witness.host=127.0.0.1   (default: 127.0.0.1)
 *   -Dpqc.witness.p2p.port=18888   (default: PQWitnessNode.P2P_PORT)
 */
public class PQFullNode {

  /** gRPC port (different from PQWitnessNode so both can run on one host). */
  static final int GRPC_PORT = 50052;
  /** Full-node HTTP port (different from PQWitnessNode). */
  static final int HTTP_PORT = 8091;
  /** P2P listen port (different from PQWitnessNode). */
  static final int P2P_PORT = 18889;

  private static final String WITNESS_HOST = System.getProperty("pqc.witness.host", "127.0.0.1");
  private static final int WITNESS_P2P_PORT = Integer.parseInt(
      System.getProperty("pqc.witness.p2p.port", String.valueOf(PQWitnessNode.P2P_PORT)));

  public static void main(String[] args) throws Exception {
    // Force INFO level: logback-test.xml (on the test classpath) sets root=DEBUG
    // which is far too noisy for a demo run.
    ((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
        .getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME))
        .setLevel(ch.qos.logback.classic.Level.INFO);

    // ── 1. Derive the same deterministic keys used by PQWitnessNode ──────
    PQSignature witnessKp = PQSchemeRegistry.fromSeed(
        PQWitnessNode.PQ_SCHEME, PQWitnessNode.WITNESS_SEED);
    Map<PQScheme, byte[]> userPubs = new EnumMap<>(PQScheme.class);
    for (PQScheme scheme : PQSchemeRegistry.registeredSchemes()) {
      userPubs.put(scheme,
          PQSchemeRegistry.fromSeed(scheme, PQWitnessNode.USER_SEEDS.get(scheme))
              .getPublicKey());
    }

    byte[] witnessPub = witnessKp.getPublicKey();

    System.out.println("=== PQC Full Node ===");
    System.out.println("Block-producing scheme: " + PQWitnessNode.PQ_SCHEME);
    System.out.println("Peer (witness): " + WITNESS_HOST + ":" + WITNESS_P2P_PORT);
    System.out.println("gRPC port:      " + GRPC_PORT);
    System.out.println("HTTP port:      " + HTTP_PORT);
    System.out.println("P2P port:       " + P2P_PORT);
    System.out.println("Witness address (expected): "
        + ByteArray.toHexString(witnessKp.getAddress()));

    // ── 2. Configure node (no -w: this is a pure fullnode) ────────────────
    File dbDir = Files.createTempDirectory("pqc-fullnode-").toFile();
    dbDir.deleteOnExit();

    Args.setParam(new String[]{"--output-directory", dbDir.getAbsolutePath()}, "config-test.conf");
    Args.getInstance().setRpcEnable(true);
    Args.getInstance().setFullNodeHttpEnable(true);
    Args.getInstance().setFullNodeHttpPort(HTTP_PORT);
    Args.getInstance().setSolidityNodeHttpEnable(false);
    Args.getInstance().setRpcPort(GRPC_PORT);
    Args.getInstance().setNodeListenPort(P2P_PORT);
    Args.getInstance().setNeedSyncCheck(false);
    Args.getInstance().setMinEffectiveConnection(0);
    Args.getInstance().genesisBlock.setWitnesses(new ArrayList<>());

    // Point to the witness node as the only seed peer.
    // Mutable list — startup appends persisted peers to it.
    Args.getInstance().getSeedNode().setAddressList(new ArrayList<>(
        Collections.singletonList(new InetSocketAddress(WITNESS_HOST, WITNESS_P2P_PORT))));

    // ── 3. Start Spring context ───────────────────────────────────────────
    TronApplicationContext context = new TronApplicationContext(DefaultConfig.class);
    Application app = ApplicationFactory.create(context);
    Manager db = context.getBean(Manager.class);
    ChainBaseManager chain = context.getBean(ChainBaseManager.class);

    // ── 4. Install matching PQ genesis pre-state ──────────────────────────
    // Without this the incoming pq_auth_sig would fail to validate because
    // this node wouldn't know the witness's PQ public key.
    PQWitnessNode.installPQGenesisState(db, chain, witnessPub, userPubs);

    // ── 5. Start P2P + gRPC (no ConsensusService.start — we don't produce) ─
    app.startup();

    System.out.println("\nFull node running, syncing from witness. Send Ctrl-C to stop.\n");

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      System.out.println("Shutting down...");
      context.close();
      Args.clearParam();
    }));

    Thread.currentThread().join();
  }
}
