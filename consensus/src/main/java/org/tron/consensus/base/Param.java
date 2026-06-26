package org.tron.consensus.base;

import com.google.protobuf.ByteString;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.tron.common.args.GenesisBlock;
import org.tron.protos.Protocol.PQScheme;

public class Param {

  private static volatile Param param = new Param();

  @Getter
  @Setter
  private boolean enable;
  @Getter
  @Setter
  private boolean needSyncCheck;
  @Getter
  @Setter
  private int minParticipationRate;
  @Getter
  @Setter
  private int blockProduceTimeoutPercent;
  @Getter
  @Setter
  private GenesisBlock genesisBlock;
  @Getter
  @Setter
  private List<Miner> miners;
  @Getter
  @Setter
  private BlockHandle blockHandle;
  @Getter
  @Setter
  private int agreeNodeCount;
  @Getter
  @Setter
  private PbftInterface pbftInterface;

  private Param() {

  }

  public static Param getInstance() {
    if (param == null) {
      synchronized (Param.class) {
        if (param == null) {
          param = new Param();
        }
      }
    }
    return param;
  }

  public class Miner {

    @Getter
    @Setter
    private byte[] privateKey;

    @Getter
    @Setter
    private ByteString privateKeyAddress;

    @Getter
    @Setter
    private ByteString witnessAddress;

    /**
     * Post-quantum identity for this miner — non-null iff the miner signs
     * blocks via the PQ path. ECDSA fields above are left null when this is
     * set so the two miner kinds never share a slot.
     */
    @Getter
    private PQMiner pq;

    public Miner(byte[] privateKey, ByteString privateKeyAddress, ByteString witnessAddress) {
      this.privateKey = privateKey;
      this.privateKeyAddress = privateKeyAddress;
      this.witnessAddress = witnessAddress;
    }

    /**
     * PQ-miner constructor. {@code privateKeyAddress} carries the PQ-derived
     * address (the key-slot identity), {@code witnessAddress} carries the
     * on-chain witness identity (often the same, but may differ in multi-sig
     * setups). The ECDSA fields {@link #privateKey} / {@link #privateKeyAddress}
     * / {@link #witnessAddress} are left null on purpose so ECDSA-only code
     * paths cannot accidentally consume a PQ identity.
     */
    public Miner(PQScheme scheme, byte[] privateKey, byte[] publicKey,
        ByteString privateKeyAddress, ByteString witnessAddress) {
      this.pq = new PQMiner(scheme, privateKey, publicKey, privateKeyAddress, witnessAddress);
    }

    /** True iff this miner signs via the PQ path (i.e. has a {@link PQMiner}). */
    public boolean isPq() {
      return pq != null;
    }

    /**
     * Returns the on-chain witness address regardless of signing scheme — PQ
     * miners route to {@link PQMiner#getWitnessAddress()}, ECDSA miners to
     * {@link #witnessAddress}. Use this from scheme-agnostic call sites
     * (block-producer map keys, witness-set filters, generic logging).
     */
    public ByteString getEffectiveWitnessAddress() {
      return pq != null ? pq.getWitnessAddress() : witnessAddress;
    }

    /**
     * Returns the signing-key-derived address regardless of signing scheme —
     * PQ miners route to {@link PQMiner#getPrivateKeyAddress()}, ECDSA miners to
     * {@link #privateKeyAddress}. Use this from scheme-agnostic call sites
     * (e.g. multi-sign permission checks).
     */
    public ByteString getEffectivePrivateKeyAddress() {
      return pq != null ? pq.getPrivateKeyAddress() : privateKeyAddress;
    }

    /**
     * Post-quantum identity bundle: scheme + key material + derived addresses.
     * Fields are {@code final}; the key {@code byte[]} references are held
     * directly (not copied), so callers must not mutate the arrays they pass in
     * or get back.
     */
    public class PQMiner {

      @Getter
      private final PQScheme scheme;

      @Getter
      private final byte[] privateKey;

      @Getter
      private final byte[] publicKey;

      /** Address derived from the PQ public key (key-slot identity). */
      @Getter
      private final ByteString privateKeyAddress;

      /** On-chain witness identity — may differ from {@link #privateKeyAddress}
       *  in multi-sig setups, otherwise equal to it. */
      @Getter
      private final ByteString witnessAddress;

      public PQMiner(PQScheme scheme, byte[] privateKey, byte[] publicKey,
          ByteString privateKeyAddress, ByteString witnessAddress) {
        this.scheme = scheme;
        this.privateKey = privateKey == null ? null : privateKey.clone();
        this.publicKey = publicKey == null ? null : publicKey.clone();
        this.privateKeyAddress = privateKeyAddress;
        this.witnessAddress = witnessAddress;
      }
    }
  }

  public Miner getMiner() {
    return miners.get(0);
  }
}