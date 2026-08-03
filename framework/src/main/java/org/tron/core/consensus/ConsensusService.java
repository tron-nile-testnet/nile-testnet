package org.tron.core.consensus;

import static org.tron.common.utils.ByteArray.fromHexString;

import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.common.parameter.CommonParameter;
import org.tron.consensus.Consensus;
import org.tron.consensus.base.Param;
import org.tron.consensus.base.Param.Miner;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.exception.TronError;
import org.tron.core.store.WitnessStore;
import org.tron.protos.Protocol.PQScheme;

@Slf4j(topic = "consensus")
@Component
public class ConsensusService {

  @Autowired
  private Consensus consensus;

  @Autowired
  private WitnessStore witnessStore;

  @Autowired
  private BlockHandleImpl blockHandle;

  @Autowired
  private PbftBaseImpl pbftBaseImpl;

  private CommonParameter parameter = Args.getInstance();

  public void start() {
    Param param = Param.getInstance();
    param.setEnable(parameter.isWitness());
    param.setGenesisBlock(parameter.getGenesisBlock());
    param.setMinParticipationRate(parameter.getMinParticipationRate());
    param.setBlockProduceTimeoutPercent(Args.getInstance().getBlockProducedTimeOut());
    param.setNeedSyncCheck(parameter.isNeedSyncCheck());
    param.setAgreeNodeCount(parameter.getAgreeNodeCount());
    List<Miner> miners = new ArrayList<>();
    List<String> privateKeys = Args.getLocalWitnesses().getPrivateKeys();
    List<PqKeypair> pqKeypairs = Args.getLocalWitnesses().getPqKeypairs();

    if (privateKeys.size() > 1) {
      for (String key : privateKeys) {
        byte[] privateKey = fromHexString(key);
        byte[] privateKeyAddress = SignUtils
            .fromPrivate(privateKey, Args.getInstance().isECKeyCryptoEngine()).getAddress();
        WitnessCapsule witnessCapsule = witnessStore.get(privateKeyAddress);
        if (null == witnessCapsule) {
          logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(privateKeyAddress));
        }
        Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
            ByteString.copyFrom(privateKeyAddress));
        miners.add(miner);
        logger.info("Add witness: {}, size: {}",
            Hex.toHexString(privateKeyAddress), miners.size());
      }
    } else if (privateKeys.size() == 1) {
      byte[] privateKey =
          fromHexString(Args.getLocalWitnesses().getPrivateKey());
      byte[] privateKeyAddress = SignUtils.fromPrivate(privateKey,
          Args.getInstance().isECKeyCryptoEngine()).getAddress();
      byte[] witnessAddress = Args.getLocalWitnesses().getWitnessAccountAddress();
      if (witnessAddress == null || witnessAddress.length == 0) {
        witnessAddress = privateKeyAddress;
      }
      WitnessCapsule witnessCapsule = witnessStore.get(witnessAddress);
      if (null == witnessCapsule) {
        logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
      }
      // In multi-signature mode, the address derived from the private key may differ from
      // witnessAddress.
      Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
          ByteString.copyFrom(witnessAddress));
      miners.add(miner);
    }

    if (pqKeypairs.size() > 1) {
      for (PqKeypair kp : pqKeypairs) {
        Miner miner = buildPQMiner(param, kp, null);
        miners.add(miner);
        logger.info("Add {} witness (from configured keypair): {}, size: {}",
            kp.getScheme(),
            Hex.toHexString(miner.getPq().getWitnessAddress().toByteArray()),
            miners.size());
      }
    } else if (pqKeypairs.size() == 1) {
      Miner miner = buildPQMiner(param, pqKeypairs.get(0),
          Args.getLocalWitnesses().getPqWitnessAccountAddress());
      miners.add(miner);
      logger.info("Add {} witness (from configured keypair): {}",
          miner.getPq().getScheme(),
          Hex.toHexString(miner.getPq().getWitnessAddress().toByteArray()));
    }

    param.setMiners(miners);
    param.setBlockHandle(blockHandle);
    param.setPbftInterface(pbftBaseImpl);
    consensus.start(param);
    logger.info("consensus service start success");
  }

  /**
   * Builds a PQ-only miner from a configured keypair. When {@code witnessAddressOverride}
   * is non-empty (single-witness mode), the override is used as the witness account
   * address while the PQ-derived address fills the key-address slot — letting multi-sig
   * permission setups route signing through a witness account distinct from the key.
   * In multi-witness mode the override does not apply (a single config value cannot
   * address N witnesses), so callers pass {@code null} and the PQ-derived address
   * fills both slots.
   */
  private Miner buildPQMiner(Param param, PqKeypair pqKeypair, byte[] witnessAddressOverride) {
    PQScheme scheme = pqKeypair.getScheme();
    requireSupportedPqScheme(scheme);
    PQSignature keypair = PQSchemeRegistry.fromKeypair(scheme,
        fromHexString(pqKeypair.getPrivateKey()), fromHexString(pqKeypair.getPublicKey()));
    byte[] pqAddress = keypair.getAddress();
    byte[] witnessAddress =
        (witnessAddressOverride != null && witnessAddressOverride.length > 0)
            ? witnessAddressOverride : pqAddress;
    if (witnessStore.get(witnessAddress) == null) {
      logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
    }
    return param.new Miner(scheme,
        keypair.getPrivateKey(), keypair.getPublicKey(),
        ByteString.copyFrom(pqAddress), ByteString.copyFrom(witnessAddress));
  }

  private static void requireSupportedPqScheme(PQScheme scheme) {
    if (!PQSchemeRegistry.contains(scheme)) {
      throw new TronError("unsupported PQ witness scheme: " + scheme,
          TronError.ErrCode.WITNESS_INIT);
    }
  }

  public void stop() {
    logger.info("consensus service closed start.");
    consensus.stop();
    logger.info("consensus service closed successfully.");
  }

}
