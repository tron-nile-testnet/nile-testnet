package org.tron.core.capsule;

import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.config.args.Args;
import org.tron.core.exception.ValidateSignatureException;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.BlockHeader;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;

public class BlockCapsulePQTest extends BaseTest {

  private ECKey witnessKey;
  private byte[] witnessAddress;
  private FNDSA512 pqKeypair;
  private byte[] pqAddress;

  @BeforeClass
  public static void init() {
    Args.setParam(new String[] {"-d", dbPath()}, TestConstants.TEST_CONF);
  }

  @Before
  public void setUp() {
    witnessKey = new ECKey();
    witnessAddress = witnessKey.getAddress();
    pqKeypair = new FNDSA512();
    pqAddress = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, pqKeypair.getPublicKey());
  }

  /**
   * Reset every PQ-scheme activation flag. Without this, a test that flips
   * {@code allowFnDsa512} or {@code allowMlDsa44} on leaks the bit into the
   * next test's {@code isAnyPqSchemeAllowed()} check — which is how the
   * legacy-only "before activation" cases became order-dependent.
   */
  @After
  public void resetPqFlags() {
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(0L);
  }

  /**
   * Build a witness account whose witness permission key is bound to the
   * given address. For PQ scenarios, pass {@link #pqAddress}; for legacy ECDSA
   * scenarios, pass {@link #witnessAddress}.
   */
  private AccountCapsule buildWitnessAccount(byte[] keyAddress) {
    Key kb = Key.newBuilder().setAddress(ByteString.copyFrom(keyAddress)).setWeight(1).build();
    Permission witnessPerm = Permission.newBuilder()
        .setType(PermissionType.Witness)
        .setId(1)
        .setPermissionName("witness")
        .setThreshold(1)
        .addKeys(kb)
        .build();
    Account account = Account.newBuilder()
        .setAccountName(ByteString.copyFromUtf8("w"))
        .setAddress(ByteString.copyFrom(witnessAddress))
        .setType(AccountType.Normal)
        .setBalance(1_000_000_000L)
        .setIsWitness(true)
        .setWitnessPermission(witnessPerm)
        .build();
    return new AccountCapsule(account);
  }

  private BlockCapsule buildSignedBlock(byte[] parentHash) {
    BlockCapsule block = new BlockCapsule(
        1L,
        Sha256Hash.wrap(ByteString.copyFrom(parentHash)),
        System.currentTimeMillis(),
        ByteString.copyFrom(witnessAddress));
    block.sign(witnessKey.getPrivKeyBytes());
    return block;
  }

  private BlockCapsule buildUnsignedBlock(byte[] parentHash) {
    return new BlockCapsule(
        1L,
        Sha256Hash.wrap(ByteString.copyFrom(parentHash)),
        System.currentTimeMillis(),
        ByteString.copyFrom(witnessAddress));
  }

  private byte[] signPQ(byte[] message) {
    return FNDSA512.sign(pqKeypair.getPrivateKey(), message);
  }

  private PQAuthSig buildPQAuthSig(byte[] signature) {
    return PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(pqKeypair.getPublicKey()))
        .setSignature(ByteString.copyFrom(signature))
        .build();
  }

  /**
   * {@link BlockCapsule#hasWitnessSignature()} is the apply-vs-pack discriminator
   * in {@code Manager#processTransaction}; a PQ-only block must read as signed so
   * it follows the same apply/trace-check path as ECDSA blocks.
   */
  @Test
  public void hasWitnessSignatureTrueForPqOnlyBlock() {
    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    Assert.assertFalse(block.hasWitnessSignature());

    block.setPqAuthSig(buildPQAuthSig(signPQ(block.getRawHashBytes())));
    Assert.assertTrue(block.hasWitnessSignature());
  }

  @Test
  public void legacyValidateWithoutPQAuthSigAcceptedBeforeActivation() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
    AccountCapsule witness = buildWitnessAccount(witnessAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildSignedBlock(parentHash);
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqAuthSigBeforeActivationRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    // Keep the PQ surface on (mlDsa44=1) so validateSignature enters the PQ
    // branch, but leave fnDsa512=0 — this is the per-scheme activation gate
    // we expect to reject the block at.
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void bothLegacyAndPQAuthSigRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule signed = buildSignedBlock(parentHash);
    byte[] digest = signed.getRawHashBytes();
    // Bypass BlockCapsule#setPqAuthSig (which clears witness_signature) so the
    // resulting block carries BOTH legacy ECDSA + PQ signatures — the wire shape
    // that the mutual-exclusion check in validateSignature must reject.
    BlockHeader dualHeader = signed.getInstance().getBlockHeader().toBuilder()
        .setPqAuthSig(buildPQAuthSig(signPQ(digest)))
        .build();
    Block dual = signed.getInstance().toBuilder().setBlockHeader(dualHeader).build();
    BlockCapsule block = new BlockCapsule(dual);
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test
  public void pqOnlyAccepted() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqAuthSigWithUnknownFieldRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    // Valid scheme/key/signature, but a nested unknown field (#99) is smuggled
    // into the header's pq_auth_sig. The block path must reject it outright,
    // matching the tx consensus path and the ingress gates.
    PQAuthSig withUnknown = buildPQAuthSig(signPQ(digest)).toBuilder()
        .setUnknownFields(UnknownFieldSet.newBuilder()
            .addField(99, UnknownFieldSet.Field.newBuilder()
                .addLengthDelimited(ByteString.copyFrom(new byte[16])).build())
            .build())
        .build();
    block.setPqAuthSig(withUnknown);
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqAuthSigWithDefaultSchemeRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    // Omit setScheme(...) so the field stays at the proto3 default
    // UNKNOWN_PQ_SCHEME. Producers must set the scheme tag explicitly; the
    // verifier rejects scheme=0 as unregistered.
    PQAuthSig defaultScheme = PQAuthSig.newBuilder()
        .setPublicKey(ByteString.copyFrom(pqKeypair.getPublicKey()))
        .setSignature(ByteString.copyFrom(signPQ(digest)))
        .build();
    Assert.assertEquals(PQScheme.UNKNOWN_PQ_SCHEME, defaultScheme.getScheme());
    block.setPqAuthSig(defaultScheme);
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test
  public void tamperedPQAuthSigFails() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    byte[] pqSig = signPQ(digest);
    pqSig[pqSig.length - 1] ^= 0x01;
    block.setPqAuthSig(buildPQAuthSig(pqSig));
    Assert.assertFalse(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void signerNotInWitnessPermissionRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    // Witness permission key bound to a different address (the legacy ECDSA
    // address), so the PQ signer's derived address won't match.
    AccountCapsule witness = buildWitnessAccount(witnessAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  /**
   * Smoke test that the registry-driven block-signing path also accepts ML-DSA-44.
   * The validate path is scheme-agnostic; a happy-path + tampered-sig pair is
   * enough to prove parametric correctness across both registered schemes.
   */
  @Test
  public void pqOnlyAcceptedForMlDsa44() throws Exception {
    MLDSA44 mlKeypair = new MLDSA44();
    byte[] mlAddress = PQSchemeRegistry.computeAddress(
        PQScheme.ML_DSA_44, mlKeypair.getPublicKey());
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    AccountCapsule witness = buildWitnessAccount(mlAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    byte[] sig = MLDSA44.sign(mlKeypair.getPrivateKey(), digest);
    block.setPqAuthSig(PQAuthSig.newBuilder()
        .setScheme(PQScheme.ML_DSA_44)
        .setPublicKey(ByteString.copyFrom(mlKeypair.getPublicKey()))
        .setSignature(ByteString.copyFrom(sig))
        .build());
    Assert.assertTrue(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test
  public void tamperedPQAuthSigFailsForMlDsa44() throws Exception {
    MLDSA44 mlKeypair = new MLDSA44();
    byte[] mlAddress = PQSchemeRegistry.computeAddress(
        PQScheme.ML_DSA_44, mlKeypair.getPublicKey());
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    AccountCapsule witness = buildWitnessAccount(mlAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    byte[] sig = MLDSA44.sign(mlKeypair.getPrivateKey(), digest);
    sig[sig.length - 1] ^= 0x01;
    block.setPqAuthSig(PQAuthSig.newBuilder()
        .setScheme(PQScheme.ML_DSA_44)
        .setPublicKey(ByteString.copyFrom(mlKeypair.getPublicKey()))
        .setSignature(ByteString.copyFrom(sig))
        .build());
    Assert.assertFalse(block.validateSignature(
        dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore()));
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqAuthSigWrongPublicKeyLengthRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    // Truncate the public key so it no longer matches the scheme's fixed length;
    // validation must reject before any address derivation.
    byte[] shortPk = new byte[pqKeypair.getPublicKey().length - 1];
    System.arraycopy(pqKeypair.getPublicKey(), 0, shortPk, 0, shortPk.length);
    block.setPqAuthSig(PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(shortPk))
        .setSignature(ByteString.copyFrom(signPQ(digest)))
        .build());
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqAuthSigWrongSignatureLengthRejected() throws Exception {
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);
    AccountCapsule witness = buildWitnessAccount(pqAddress);
    dbManager.getAccountStore().put(witnessAddress, witness);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    // A one-byte signature is far below the scheme's minimum length, so the
    // length guard rejects it before the cryptographic verify is attempted.
    block.setPqAuthSig(buildPQAuthSig(new byte[] {0x01}));
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }

  @Test(expected = ValidateSignatureException.class)
  public void pqAuthSigWitnessAccountNotFoundRejected() throws Exception {
    // allowMultiSign forces the verifier to resolve the witness account from the
    // store; with no account put there, it must raise "witness account not found".
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    dbManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);

    byte[] parentHash = new byte[32];
    BlockCapsule block = buildUnsignedBlock(parentHash);
    byte[] digest = block.getRawHashBytes();
    block.setPqAuthSig(buildPQAuthSig(signPQ(digest)));
    block.validateSignature(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
  }
}
