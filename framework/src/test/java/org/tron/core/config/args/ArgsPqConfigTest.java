package org.tron.core.config.args;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.tron.common.TestConstants;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.common.utils.LocalWitnesses;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.PQScheme;

/**
 * Covers the {@code localPqWitness.keys} parsing in {@link Args#setParam}:
 * {@code keys} is a list of JSON key-file paths, each file carrying one keypair
 * as {@code scheme} plus either {@code seed} or {@code privateKey} (and, for
 * FN_DSA_512, {@code publicKey}). Exercises the per-scheme rules — ML_DSA_44
 * takes {@code privateKey} only (derives the public key), FN_DSA_512 requires
 * both halves — and the seed/key exclusivity and length guards.
 */
public class ArgsPqConfigTest {

  @Rule
  public TemporaryFolder tmp = new TemporaryFolder();

  @After
  public void tearDown() {
    Args.clearParam();
  }

  @Test
  public void mlDsa44SeedDerivesKeypair() throws IOException {
    byte[] seed = filled(MLDSA44.SEED_LENGTH, (byte) 0x07);
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\", \"seed\": \"" + Hex.toHexString(seed) + "\" }"));

    Args.setParam(new String[]{"--witness"}, conf.toString());

    LocalWitnesses lw = Args.getLocalWitnesses();
    assertEquals(1, lw.getPqKeypairs().size());
    PqKeypair kp = lw.getPqKeypairs().get(0);
    assertEquals(PQScheme.ML_DSA_44, kp.getScheme());

    PQSignature expected = PQSchemeRegistry.fromSeed(PQScheme.ML_DSA_44, seed);
    assertEquals(Hex.toHexString(expected.getPrivateKey()), kp.getPrivateKey());
    assertEquals(Hex.toHexString(expected.getPublicKey()), kp.getPublicKey());
  }

  @Test
  public void mlDsa44SeedAcceptsZeroXPrefix() throws IOException {
    byte[] seed = filled(MLDSA44.SEED_LENGTH, (byte) 0x09);
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\", \"seed\": \"0x" + Hex.toHexString(seed) + "\" }"));
    Args.setParam(new String[]{"--witness"}, conf.toString());
    assertEquals(1, Args.getLocalWitnesses().getPqKeypairs().size());
  }

  @Test
  public void mlDsa44PrivateKeyDerivesPublicKey() throws IOException {
    MLDSA44 ml = new MLDSA44(filled(MLDSA44.SEED_LENGTH, (byte) 0x0C));
    byte[] priv = ml.getPrivateKey();
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\", \"privateKey\": \"" + Hex.toHexString(priv) + "\" }"));

    Args.setParam(new String[]{"--witness"}, conf.toString());

    LocalWitnesses lw = Args.getLocalWitnesses();
    assertEquals(1, lw.getPqKeypairs().size());
    PqKeypair kp = lw.getPqKeypairs().get(0);
    assertEquals(Hex.toHexString(priv), kp.getPrivateKey());
    assertEquals(Hex.toHexString(ml.getPublicKey()), kp.getPublicKey());
  }

  @Test
  public void fnDsa512PrivateKeyAndPublicKeyAccepted() throws IOException {
    FNDSA512 fn = new FNDSA512(filled(FNDSA512.SEED_LENGTH, (byte) 0x11));
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"FN_DSA_512\","
            + " \"privateKey\": \"" + Hex.toHexString(fn.getPrivateKey()) + "\","
            + " \"publicKey\": \"" + Hex.toHexString(fn.getPublicKey()) + "\" }"));

    Args.setParam(new String[]{"--witness"}, conf.toString());

    LocalWitnesses lw = Args.getLocalWitnesses();
    assertEquals(1, lw.getPqKeypairs().size());
    PqKeypair kp = lw.getPqKeypairs().get(0);
    assertEquals(PQScheme.FN_DSA_512, kp.getScheme());
    assertEquals(Hex.toHexString(fn.getPrivateKey()), kp.getPrivateKey());
    assertEquals(Hex.toHexString(fn.getPublicKey()), kp.getPublicKey());
  }

  @Test
  public void multipleKeyFilesAccepted() throws IOException {
    String mlFile = writeKeyFile("{ \"scheme\": \"ML_DSA_44\", \"privateKey\": \""
        + Hex.toHexString(new MLDSA44(filled(MLDSA44.SEED_LENGTH, (byte) 0x21)).getPrivateKey())
        + "\" }");
    FNDSA512 fn = new FNDSA512(filled(FNDSA512.SEED_LENGTH, (byte) 0x22));
    String fnFile = writeKeyFile("{ \"scheme\": \"FN_DSA_512\", \"privateKey\": \""
        + Hex.toHexString(fn.getPrivateKey()) + "\", \"publicKey\": \""
        + Hex.toHexString(fn.getPublicKey()) + "\" }");

    Args.setParam(new String[]{"--witness"}, writeConf(mlFile, fnFile).toString());
    assertEquals(2, Args.getLocalWitnesses().getPqKeypairs().size());
  }

  @Test
  public void keyAndSeedBothSetUsesPrivateKey() throws IOException {
    // When both seed and privateKey are present (--all mode), privateKey takes priority.
    byte[] seedBytes = filled(MLDSA44.SEED_LENGTH, (byte) 0x05);
    MLDSA44 ml = new MLDSA44(seedBytes);
    String seedHex = Hex.toHexString(seedBytes);
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\","
            + " \"seed\": \"" + seedHex + "\","
            + " \"privateKey\": \"" + Hex.toHexString(ml.getPrivateKey()) + "\" }"));

    Args.setParam(new String[]{"--witness"}, conf.toString());
    LocalWitnesses lw = Args.getLocalWitnesses();
    PqKeypair kp = lw.getPqKeypairs().get(0);
    // privateKey takes priority: loaded keypair must match the explicit key, not the seed
    assertEquals(Hex.toHexString(ml.getPrivateKey()), kp.getPrivateKey());
  }

  @Test
  public void neitherKeyNorSeedRejected() throws IOException {
    Path conf = writeConf(writeKeyFile("{ \"scheme\": \"ML_DSA_44\" }"));

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("at least one of `seed` or `privateKey`"));
  }

  @Test
  public void mlDsa44SeedWrongLengthRejected() throws IOException {
    String shortSeed = Hex.toHexString(filled(MLDSA44.SEED_LENGTH - 1, (byte) 0x02));
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\", \"seed\": \"" + shortSeed + "\" }"));

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("seed must be"));
  }

  @Test
  public void mlDsa44PrivateKeyWrongLengthRejected() throws IOException {
    String shortKey = Hex.toHexString(filled(MLDSA44.PRIVATE_KEY_LENGTH - 1, (byte) 0x0D));
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\", \"privateKey\": \"" + shortKey + "\" }"));

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("privateKey must be"));
  }

  @Test
  public void mlDsa44PublicKeyMatchingAccepted() throws IOException {
    // ML-DSA-44 publicKey is optional; when present and matching the derived key it is accepted.
    MLDSA44 ml = new MLDSA44(filled(MLDSA44.SEED_LENGTH, (byte) 0x0B));
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\","
            + " \"privateKey\": \"" + Hex.toHexString(ml.getPrivateKey()) + "\","
            + " \"publicKey\": \"" + Hex.toHexString(ml.getPublicKey()) + "\" }"));

    Args.setParam(new String[]{"--witness"}, conf.toString());
    PqKeypair kp = Args.getLocalWitnesses().getPqKeypairs().get(0);
    assertEquals(Hex.toHexString(ml.getPublicKey()), kp.getPublicKey());
  }

  @Test
  public void mlDsa44PublicKeyMismatchRejected() throws IOException {
    // When publicKey is present for ML_DSA_44 but does not match privateKey, it must be rejected.
    MLDSA44 ml = new MLDSA44(filled(MLDSA44.SEED_LENGTH, (byte) 0x0B));
    MLDSA44 other = new MLDSA44(filled(MLDSA44.SEED_LENGTH, (byte) 0x0C));
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"ML_DSA_44\","
            + " \"privateKey\": \"" + Hex.toHexString(ml.getPrivateKey()) + "\","
            + " \"publicKey\": \"" + Hex.toHexString(other.getPublicKey()) + "\" }"));

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("does not match"));
  }

  @Test
  public void fnDsa512MissingPublicKeyRejected() throws IOException {
    FNDSA512 fn = new FNDSA512(filled(FNDSA512.SEED_LENGTH, (byte) 0x0E));
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"FN_DSA_512\", \"privateKey\": \""
            + Hex.toHexString(fn.getPrivateKey()) + "\" }"));

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("publicKey is required"));
  }

  @Test
  public void fnDsa512PublicKeyMismatchRejected() throws IOException {
    FNDSA512 fn = new FNDSA512(filled(FNDSA512.SEED_LENGTH, (byte) 0x31));
    FNDSA512 other = new FNDSA512(filled(FNDSA512.SEED_LENGTH, (byte) 0x32));
    Path conf = writeConf(writeKeyFile(
        "{ \"scheme\": \"FN_DSA_512\","
            + " \"privateKey\": \"" + Hex.toHexString(fn.getPrivateKey()) + "\","
            + " \"publicKey\": \"" + Hex.toHexString(other.getPublicKey()) + "\" }"));

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("mismatch"));
  }

  @Test
  public void keyFileNotFoundRejected() throws IOException {
    Path conf = writeConf(tmp.getRoot().toPath().resolve("missing.json").toString());

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("key file not found"));
  }

  @Test
  public void malformedKeyFileRejected() throws IOException {
    Path conf = writeConf(writeKeyFile("{ not valid json"));

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("failed to parse key file"));
  }

  /** Write a JSON key-file with the given body and return its absolute path. */
  private String writeKeyFile(String jsonBody) throws IOException {
    Path keyFile = Files.createTempFile(tmp.getRoot().toPath(), "pq-key-", ".json");
    Files.write(keyFile, jsonBody.getBytes(StandardCharsets.UTF_8));
    return keyFile.toAbsolutePath().toString();
  }

  /** Write a node config whose localPqWitness.keys references the given file paths. */
  private Path writeConf(String... keyFilePaths) throws IOException {
    Path conf = Files.createTempFile(tmp.getRoot().toPath(), "pqc-args-", ".conf");
    StringBuilder keys = new StringBuilder();
    for (String p : keyFilePaths) {
      keys.append("    \"").append(p.replace("\\", "\\\\")).append("\",\n");
    }
    String body = "include classpath(\"" + TestConstants.TEST_CONF + "\")\n"
        + "localwitness = []\n"
        + "localPqWitness = {\n"
        + "  keys = [\n"
        + keys
        + "  ]\n"
        + "}\n";
    Files.write(conf, body.getBytes(StandardCharsets.UTF_8));
    return conf;
  }

  private static byte[] filled(int len, byte value) {
    byte[] out = new byte[len];
    Arrays.fill(out, value);
    return out;
  }
}
