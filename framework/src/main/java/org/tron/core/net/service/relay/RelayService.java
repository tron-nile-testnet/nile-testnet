package org.tron.core.net.service.relay;

import com.google.protobuf.ByteString;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.tron.common.backup.BackupManager;
import org.tron.common.backup.BackupManager.BackupStatusEnum;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.common.es.ExecutorServiceManager;
import org.tron.common.log.layout.DesensitizedConverter;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.LocalWitnesses;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.db.Manager;
import org.tron.core.net.TronNetDelegate;
import org.tron.core.net.TronNetService;
import org.tron.core.net.message.adv.BlockMessage;
import org.tron.core.net.message.handshake.HelloMessage;
import org.tron.core.net.peer.Item;
import org.tron.core.net.peer.PeerConnection;
import org.tron.core.store.WitnessScheduleStore;
import org.tron.p2p.connection.Channel;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.ReasonCode;

@Slf4j(topic = "net")
@Component
public class RelayService {

  private static final int MAX_PEER_COUNT_PER_ADDRESS = 5;

  @Autowired
  private ChainBaseManager chainBaseManager;

  @Autowired
  private TronNetDelegate tronNetDelegate;

  @Autowired
  private ApplicationContext ctx;

  private Manager manager;

  private WitnessScheduleStore witnessScheduleStore;

  private BackupManager backupManager;
  private final String esName = "relay-service";

  private final ScheduledExecutorService executorService = ExecutorServiceManager
      .newSingleThreadScheduledExecutor(esName);

  private final CommonParameter parameter = Args.getInstance();

  private final List<InetSocketAddress> fastForwardNodes = parameter.getFastForwardNodes();

  private final int ecdsaKeySize = Args.getLocalWitnesses().getPrivateKeys().size();

  private final int pqKeySize = Args.getLocalWitnesses().getPqKeypairs().size();

  // A node may carry an ECDSA witness, a PQ witness, or both (mixed multi-SR).
  // Either-or-both must be matched against the active schedule, and
  // fillHelloMessage must announce the address matching the signing path.
  private final ByteString ecdsaWitnessAddress =
      Args.getLocalWitnesses().getWitnessAccountAddress() != null ? ByteString
          .copyFrom(Args.getLocalWitnesses().getWitnessAccountAddress()) : null;

  private final ByteString pqWitnessAddress =
      Args.getLocalWitnesses().getPqWitnessAccountAddress() != null ? ByteString
          .copyFrom(Args.getLocalWitnesses().getPqWitnessAccountAddress()) : null;

  private final int maxFastForwardNum = Args.getInstance().getMaxFastForwardNum();

  public void init() {
    manager = ctx.getBean(Manager.class);
    witnessScheduleStore = ctx.getBean(WitnessScheduleStore.class);
    backupManager = ctx.getBean(BackupManager.class);

    logger.info(
        "Fast forward config, isWitness: {}, ecdsaKeySize: {}, pqKeySize: {}, fastForwardNodes: {}",
        parameter.isWitness(), ecdsaKeySize, pqKeySize, fastForwardNodes.size());

    if (!parameter.isWitness() || (ecdsaKeySize == 0 && pqKeySize == 0) || fastForwardNodes.isEmpty()) {
      return;
    }

    executorService.scheduleWithFixedDelay(() -> {
      try {
        if (isAnyLocalWitnessActive()
            && backupManager.getStatus().equals(BackupStatusEnum.MASTER)) {
          connect();
        } else {
          disconnect();
        }
      } catch (Exception e) {
        logger.info("Execute failed.", e);
      }
    }, 30, 100, TimeUnit.SECONDS);
  }

  public void close() {
    ExecutorServiceManager.shutdownAndAwaitTermination(executorService, esName);
  }

  /**
   * Whether the channel's remote peer is in {@code node.fastForward.nodes}.
   */
  public boolean isFastForwardPeer(Channel channel) {
    if (channel == null || channel.getInetAddress() == null) {
      return false;
    }
    return fastForwardNodes.stream()
        .anyMatch(ff -> channel.getInetAddress().equals(ff.getAddress()));
  }

  public void fillHelloMessage(HelloMessage message, Channel channel) {
    if (!isActiveWitness() || !isFastForwardPeer(channel)) {
      return;
    }
    byte[] digest = Sha256Hash.of(CommonParameter.getInstance()
        .isECKeyCryptoEngine(), ByteArray.fromLong(message.getTimestamp()))
        .getBytes();
    // In a mixed-witness node (ECDSA + PQ), pick the path whose address
    // is currently in the active schedule — otherwise the receiver
    // rejects on the "not a schedule witness" check in checkHelloMessage.
    List<ByteString> active = witnessScheduleStore.getActiveWitnesses();
    boolean useEcdsa = ecdsaKeySize > 0 && ecdsaWitnessAddress != null
        && active.contains(ecdsaWitnessAddress);
    ByteString announceAddress = useEcdsa ? ecdsaWitnessAddress : pqWitnessAddress;
    Protocol.HelloMessage.Builder builder = message.getHelloMessage().toBuilder()
        .setAddress(announceAddress);
    if (useEcdsa) {
      SignInterface cryptoEngine = SignUtils.fromPrivate(
          ByteArray.fromHexString(Args.getLocalWitnesses().getPrivateKey()),
          Args.getInstance().isECKeyCryptoEngine());
      ByteString sig = ByteString.copyFrom(
          cryptoEngine.Base64toBytes(cryptoEngine.signHash(digest)));
      builder.setSignature(sig).clearPqAuthSig();
    } else {
      // isAnyLocalWitnessActive() guarantees at least one of ECDSA/PQ is active;
      // since useEcdsa is false here, the PQ identity must be the active one.
      // Guard the keypair list anyway so a stale/mutated config fails loud
      // instead of with IOOB.
      LocalWitnesses lw = Args.getLocalWitnesses();
      if (lw.getPqKeypairs().isEmpty()) {
        logger.warn("HelloMessage fill skipped: no PQ keypair available");
        return;
      }
      PqKeypair kp = lw.getPqKeypairs().get(0);
      PQScheme scheme = kp.getScheme();
      byte[] privKey = ByteArray.fromHexString(kp.getPrivateKey());
      byte[] pubKey = ByteArray.fromHexString(kp.getPublicKey());
      byte[] sig = PQSchemeRegistry.sign(scheme, privKey, digest);
      builder.setPqAuthSig(PQAuthSig.newBuilder()
          .setScheme(scheme)
          .setPublicKey(ByteString.copyFrom(pubKey))
          .setSignature(ByteString.copyFrom(sig)))
          .clearSignature();
    }
    message.setHelloMessage(builder.build());
  }

  public boolean checkHelloMessage(HelloMessage message, Channel channel) {
    if (!parameter.isFastForward()) {
      return true;
    }

    Protocol.HelloMessage msg = message.getHelloMessage();
    InetAddress remoteAddress = channel.getInetAddress();

    if (msg.getAddress().isEmpty()) {
      logger.info("HelloMessage from {}, address is empty.", remoteAddress);
      return false;
    }

    if (!witnessScheduleStore.getActiveWitnesses().contains(msg.getAddress())) {
      logger.warn("HelloMessage from {}, {} is not a schedule witness.",
          remoteAddress, ByteArray.toHexString(msg.getAddress().toByteArray()));
      return false;
    }

    if (getPeerCountByAddress(msg.getAddress()) > MAX_PEER_COUNT_PER_ADDRESS) {
      logger.warn("HelloMessage from {}, the number of peers of {} exceeds {}.",
          remoteAddress, ByteArray.toHexString(msg.getAddress().toByteArray()),
          MAX_PEER_COUNT_PER_ADDRESS);
      return false;
    }

    boolean hasLegacy = !msg.getSignature().isEmpty();
    boolean hasPq = msg.hasPqAuthSig();
    if (hasLegacy && hasPq) {
      logger.warn("HelloMessage from {}, signature and pq_auth_sig must not be set "
          + "at the same time.", remoteAddress);
      return false;
    }
    if (!hasLegacy && !hasPq) {
      logger.warn("HelloMessage from {}, neither signature nor pq_auth_sig found.", remoteAddress);
      return false;
    }

    if (hasLegacy && !SignUtils.isValidLength(msg.getSignature().size())) {
      logger.warn("HelloMessage from {}, signature size is {}.",
          remoteAddress, msg.getSignature().size());
      return false;
    }

    boolean isVerified;
    try {
      byte[] digest = Sha256Hash.of(CommonParameter.getInstance().isECKeyCryptoEngine(),
          ByteArray.fromLong(msg.getTimestamp())).getBytes();
      if (hasPq) {
        isVerified = verifyPqAuthSig(digest, msg.getPqAuthSig(), msg.getAddress(), remoteAddress);
      } else {
        isVerified =
            verifyEcdsaSignature(digest, msg.getSignature(), msg.getAddress(), remoteAddress);
      }
      if (isVerified) {
        TronNetService.getP2pConfig().getTrustNodes().add(remoteAddress);
        DesensitizedConverter.addSensitive(remoteAddress.toString().substring(1),
            ByteArray.toHexString(msg.getAddress().toByteArray()));
      }
      return isVerified;
    } catch (Exception e) {
      logger.error("Check hello message failed, msg: {}, {}", message, remoteAddress, e);
      return false;
    }
  }

  private boolean verifyEcdsaSignature(byte[] digest, ByteString signature,
      ByteString witnessAddr, InetAddress remoteAddress) throws SignatureException {
    String sig = TransactionCapsule.getBase64FromByteString(signature);
    byte[] sigAddress = SignUtils.signatureToAddress(digest, sig,
        Args.getInstance().isECKeyCryptoEngine());
    byte[] expected = resolveExpectedSignerAddress(witnessAddr, remoteAddress);
    return expected != null && Arrays.equals(sigAddress, expected);
  }

  private boolean verifyPqAuthSig(byte[] digest, PQAuthSig pqAuthSig,
      ByteString witnessAddr, InetAddress remoteAddress) {
    PQScheme scheme = pqAuthSig.getScheme();
    if (!manager.getDynamicPropertiesStore().isPqSchemeAllowed(scheme)) {
      logger.warn("HelloMessage from {}, pq_auth_sig scheme {} is not allowed on chain.",
          remoteAddress, scheme);
      return false;
    }
    byte[] publicKey = pqAuthSig.getPublicKey().toByteArray();
    if (publicKey.length != PQSchemeRegistry.getPublicKeyLength(scheme)) {
      logger.warn("HelloMessage from {}, pq_auth_sig public key length mismatch for {}.",
          remoteAddress, scheme);
      return false;
    }
    byte[] signature = pqAuthSig.getSignature().toByteArray();
    if (!PQSchemeRegistry.isValidSignatureLength(scheme, signature.length)) {
      logger.warn("HelloMessage from {}, pq_auth_sig signature length mismatch for {}.",
          remoteAddress, scheme);
      return false;
    }

    byte[] expected = resolveExpectedSignerAddress(witnessAddr, remoteAddress);
    if (expected == null) {
      return false;
    }
    byte[] derivedAddr = PQSchemeRegistry.computeAddress(scheme, publicKey);
    if (!Arrays.equals(derivedAddr, expected)) {
      logger.warn("HelloMessage from {}, pq_auth_sig public key does not bind witness {}.",
          remoteAddress, ByteArray.toHexString(witnessAddr.toByteArray()));
      return false;
    }
    return PQSchemeRegistry.verify(scheme, publicKey, digest, signature);
  }

  /**
   * Resolve the address the signer must match: the witness address itself, or its
   * configured witness-permission address when multi-sign is enabled. Returns null
   * (and logs) when multi-sign is on but the witness account is missing.
   */
  private byte[] resolveExpectedSignerAddress(ByteString witnessAddr, InetAddress remoteAddress) {
    if (manager.getDynamicPropertiesStore().getAllowMultiSign() != 1) {
      return witnessAddr.toByteArray();
    }
    AccountCapsule account = manager.getAccountStore().get(witnessAddr.toByteArray());
    if (account == null) {
      logger.warn("HelloMessage from {}, witness account {} not found in accountStore.",
          remoteAddress, ByteArray.toHexString(witnessAddr.toByteArray()));
      return null;
    }
    return account.getWitnessPermissionAddress();
  }

  private long getPeerCountByAddress(ByteString address) {
    return tronNetDelegate.getActivePeer().stream()
      .filter(peer -> peer.getAddress() != null && peer.getAddress().equals(address))
      .count();
  }

  private boolean isActiveWitness() {
    return parameter.isWitness()
        && (ecdsaKeySize > 0 || pqKeySize > 0)
        && !fastForwardNodes.isEmpty()
        && isAnyLocalWitnessActive()
        && backupManager.getStatus().equals(BackupStatusEnum.MASTER);
  }

  // True iff either of this node's witness identities is in the active schedule.
  private boolean isAnyLocalWitnessActive() {
    List<ByteString> active = witnessScheduleStore.getActiveWitnesses();
    return (ecdsaWitnessAddress != null && active.contains(ecdsaWitnessAddress))
        || (pqWitnessAddress != null && active.contains(pqWitnessAddress));
  }

  private void connect() {
    for (InetSocketAddress fastForwardNode : fastForwardNodes) {
      if (!TronNetService.getP2pConfig().getActiveNodes().contains(fastForwardNode)) {
        TronNetService.getP2pConfig().getActiveNodes().add(fastForwardNode);
      }
    }
  }

  private void disconnect() {
    fastForwardNodes.forEach(address -> {
      TronNetService.getP2pConfig().getActiveNodes().remove(address);
      TronNetService.getPeers().forEach(peer -> {
        if (peer.getInetAddress().equals(address.getAddress())) {
          peer.disconnect(ReasonCode.NOT_WITNESS);
          peer.getChannel().close();
        }
      });
    });
  }

  private Set<ByteString> getNextWitnesses(ByteString key, Integer count) {
    List<ByteString> list = chainBaseManager.getWitnessScheduleStore().getActiveWitnesses();
    int index = list.indexOf(key);
    if (index < 0) {
      return new HashSet<>(list);
    }
    Set<ByteString> set = new HashSet<>();
    for (; count > 0; count--) {
      set.add(list.get(++index % list.size()));
    }
    return set;
  }

  public void broadcast(BlockMessage msg) {
    Set<ByteString> witnesses = getNextWitnesses(
            msg.getBlockCapsule().getWitnessAddress(), maxFastForwardNum);
    Item item = new Item(msg.getBlockId(), Protocol.Inventory.InventoryType.BLOCK);
    List<PeerConnection> peers = tronNetDelegate.getActivePeer().stream()
            .filter(peer -> !peer.isNeedSyncFromPeer() && !peer.isNeedSyncFromUs())
            .filter(peer -> peer.getAdvInvReceive().getIfPresent(item) == null
                    && peer.getAdvInvSpread().getIfPresent(item) == null)
            .filter(peer -> peer.getAddress() != null && witnesses.contains(peer.getAddress()))
            .collect(Collectors.toList());

    peers.forEach(peer -> {
      peer.sendMessage(msg);
      peer.getAdvInvSpread().put(item, System.currentTimeMillis());
      peer.setFastForwardBlock(msg.getBlockId());
    });
  }
}
