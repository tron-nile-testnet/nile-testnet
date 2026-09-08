import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;

/**
 * Small BouncyCastle 1.84 interoperability probe for TIP-899.
 *
 * <p>This intentionally has no java-tron dependency. It mirrors the key and signature encodings
 * used by the reference branch so OpenSSL and the official Falcon C implementation can verify the
 * same raw artifacts.
 */
public final class Tip899BcInterop {
  private static final HexFormat HEX = HexFormat.of();
  private static final MLDSAParameters ML_PARAMS = MLDSAParameters.ml_dsa_44;
  private static final FalconParameters FN_PARAMS = FalconParameters.falcon_512;

  private static final int ML_SEED_LEN = 32;
  private static final int ML_SK_LEN = 2560;
  private static final int ML_PK_LEN = 1312;
  private static final int ML_SIG_LEN = 2420;

  private static final int FN_SEED_LEN = 48;
  private static final int FN_SK_LEN = 1280;
  private static final int FN_PK_LEN = 896;
  private static final int FN_SIG_MIN_LEN = 617;
  private static final int FN_SIG_MAX_LEN = 667;
  private static final byte FN_SIG_HEADER = 0x39;
  private static final int FN_SIGN_RETRIES = 16;

  private Tip899BcInterop() {}

  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      usage();
    }
    switch (args[0]) {
      case "generate-mldsa" -> {
        requireArgs(args, 4);
        generateMlDsa(parseSeed(args[1], ML_SEED_LEN), Path.of(args[2]), Path.of(args[3]));
      }
      case "verify-mldsa" -> {
        requireArgs(args, 4);
        exitForVerification(verifyMlDsa(read(args[1]), read(args[2]), read(args[3])));
      }
      case "generate-falcon" -> {
        requireArgs(args, 4);
        generateFalcon(parseSeed(args[1], FN_SEED_LEN), Path.of(args[2]), Path.of(args[3]));
      }
      case "sign-falcon" -> {
        requireArgs(args, 4);
        byte[] signature = signFalcon(read(args[1]), read(args[2]));
        write(Path.of(args[3]), signature);
        System.out.printf(
            "valid=true signatureLength=%d signatureSha256=%s%n",
            signature.length, sha256Hex(signature));
      }
      case "verify-falcon" -> {
        requireArgs(args, 4);
        exitForVerification(verifyFalcon(read(args[1]), read(args[2]), read(args[3])));
      }
      default -> usage();
    }
  }

  private static void generateMlDsa(byte[] seed, Path messagePath, Path outputDir)
      throws Exception {
    byte[] message = Files.readAllBytes(messagePath);
    MLDSAKeyPairGenerator generator = new MLDSAKeyPairGenerator();
    generator.init(new MLDSAKeyGenerationParameters(new FixedSecureRandom(seed), ML_PARAMS));
    AsymmetricCipherKeyPair pair = generator.generateKeyPair();
    MLDSAPrivateKeyParameters sk = (MLDSAPrivateKeyParameters) pair.getPrivate();
    MLDSAPublicKeyParameters pk = (MLDSAPublicKeyParameters) pair.getPublic();
    byte[] privateKey = sk.getEncoded();
    byte[] publicKey = pk.getEncoded();
    requireLength("ML-DSA private key", privateKey, ML_SK_LEN);
    requireLength("ML-DSA public key", publicKey, ML_PK_LEN);

    // Zero per-message entropy matches OpenSSL's deterministic=1 test mode. This is fixture-only;
    // production TIP-899 signing uses fresh randomness through ParametersWithRandom.
    MLDSASigner signer = new MLDSASigner();
    signer.init(true, new ParametersWithRandom(sk, new FixedSecureRandom(new byte[32])));
    signer.update(message, 0, message.length);
    byte[] signature = signer.generateSignature();
    requireLength("ML-DSA signature", signature, ML_SIG_LEN);

    Files.createDirectories(outputDir);
    write(outputDir.resolve("private-key.bin"), privateKey);
    write(outputDir.resolve("public-key.bin"), publicKey);
    write(outputDir.resolve("signature.bin"), signature);
    write(outputDir.resolve("address.bin"), tronAddress(publicKey));
    System.out.printf(
        "scheme=ML_DSA_44 pkLength=%d skLength=%d signatureLength=%d "
            + "pkSha256=%s skSha256=%s signatureSha256=%s%n",
        publicKey.length,
        privateKey.length,
        signature.length,
        sha256Hex(publicKey),
        sha256Hex(privateKey),
        sha256Hex(signature));
  }

  private static boolean verifyMlDsa(byte[] publicKey, byte[] message, byte[] signature) {
    if (publicKey.length != ML_PK_LEN || signature.length != ML_SIG_LEN) {
      return false;
    }
    try {
      MLDSAPublicKeyParameters pk = new MLDSAPublicKeyParameters(ML_PARAMS, publicKey);
      MLDSASigner verifier = new MLDSASigner();
      verifier.init(false, pk);
      verifier.update(message, 0, message.length);
      return verifier.verifySignature(signature);
    } catch (RuntimeException error) {
      return false;
    }
  }

  private static void generateFalcon(byte[] seed, Path messagePath, Path outputDir)
      throws Exception {
    byte[] message = Files.readAllBytes(messagePath);
    FalconKeyPairGenerator generator = new FalconKeyPairGenerator();
    generator.init(new FalconKeyGenerationParameters(new FixedSecureRandom(seed), FN_PARAMS));
    AsymmetricCipherKeyPair pair = generator.generateKeyPair();
    FalconPrivateKeyParameters sk = (FalconPrivateKeyParameters) pair.getPrivate();
    FalconPublicKeyParameters pk = (FalconPublicKeyParameters) pair.getPublic();
    byte[] privateKey = sk.getEncoded();
    byte[] publicKey = pk.getH();
    requireLength("Falcon private key", privateKey, FN_SK_LEN);
    requireLength("Falcon public key", publicKey, FN_PK_LEN);
    byte[] signature = signFalcon(privateKey, message);

    Files.createDirectories(outputDir);
    write(outputDir.resolve("private-key.bin"), privateKey);
    write(outputDir.resolve("public-key.bin"), publicKey);
    write(outputDir.resolve("signature.bin"), signature);
    write(outputDir.resolve("address.bin"), tronAddress(publicKey));
    System.out.printf(
        "scheme=FN_DSA_512 pkLength=%d skLength=%d signatureLength=%d "
            + "pkSha256=%s skSha256=%s signatureSha256=%s%n",
        publicKey.length,
        privateKey.length,
        signature.length,
        sha256Hex(publicKey),
        sha256Hex(privateKey),
        sha256Hex(signature));
  }

  private static byte[] signFalcon(byte[] privateKey, byte[] message) {
    if (privateKey.length == FN_SK_LEN + FN_PK_LEN) {
      privateKey = Arrays.copyOf(privateKey, FN_SK_LEN);
    }
    requireLength("Falcon private key", privateKey, FN_SK_LEN);
    byte[] f = Arrays.copyOfRange(privateKey, 0, 384);
    byte[] g = Arrays.copyOfRange(privateKey, 384, 768);
    byte[] bigF = Arrays.copyOfRange(privateKey, 768, 1280);
    FalconPrivateKeyParameters sk =
        new FalconPrivateKeyParameters(FN_PARAMS, f, g, bigF, new byte[0]);
    FalconSigner signer = new FalconSigner();
    signer.init(true, new ParametersWithRandom(sk, new SecureRandom()));
    RuntimeException lastFailure = null;
    for (int attempt = 0; attempt < FN_SIGN_RETRIES; attempt++) {
      try {
        byte[] signature = signer.generateSignature(message);
        if (signature.length >= FN_SIG_MIN_LEN
            && signature.length <= FN_SIG_MAX_LEN
            && signature[0] == FN_SIG_HEADER) {
          return signature;
        }
      } catch (RuntimeException error) {
        lastFailure = error;
      }
    }
    throw new IllegalStateException("Falcon signature did not fit TIP-899 bounds", lastFailure);
  }

  private static boolean verifyFalcon(byte[] publicKey, byte[] message, byte[] signature) {
    if (publicKey.length != FN_PK_LEN
        || signature.length < FN_SIG_MIN_LEN
        || signature.length > FN_SIG_MAX_LEN
        || signature[0] != FN_SIG_HEADER) {
      return false;
    }
    try {
      FalconPublicKeyParameters pk = new FalconPublicKeyParameters(FN_PARAMS, publicKey);
      FalconSigner verifier = new FalconSigner();
      verifier.init(false, pk);
      return verifier.verifySignature(message, signature);
    } catch (RuntimeException error) {
      return false;
    }
  }

  private static byte[] tronAddress(byte[] publicKey) {
    KeccakDigest digest = new KeccakDigest(256);
    digest.update(publicKey, 0, publicKey.length);
    byte[] hash = new byte[32];
    digest.doFinal(hash, 0);
    byte[] address = new byte[21];
    address[0] = 0x41;
    System.arraycopy(hash, 12, address, 1, 20);
    return address;
  }

  private static byte[] parseSeed(String value, int expectedBytes) {
    byte[] seed = HEX.parseHex(value);
    requireLength("seed", seed, expectedBytes);
    return seed;
  }

  private static byte[] read(String path) throws IOException {
    return Files.readAllBytes(Path.of(path));
  }

  private static void write(Path path, byte[] bytes) throws IOException {
    Path parent = path.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.write(path, bytes);
  }

  private static void requireLength(String label, byte[] value, int expected) {
    if (value.length != expected) {
      throw new IllegalArgumentException(
          label + " length must be " + expected + ", got " + value.length);
    }
  }

  private static String sha256Hex(byte[] value) throws Exception {
    return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(value));
  }

  private static void exitForVerification(boolean valid) {
    System.out.println("valid=" + valid);
    if (!valid) {
      System.exit(1);
    }
  }

  private static void requireArgs(String[] args, int expected) {
    if (args.length != expected) {
      usage();
    }
  }

  private static void usage() {
    System.err.println("Usage:");
    System.err.println("  generate-mldsa <32-byte-seed-hex> <message.bin> <output-dir>");
    System.err.println("  verify-mldsa <public-key.bin> <message.bin> <signature.bin>");
    System.err.println("  generate-falcon <48-byte-seed-hex> <message.bin> <output-dir>");
    System.err.println("  sign-falcon <private-key.bin> <message.bin> <signature.bin>");
    System.err.println("  verify-falcon <public-key.bin> <message.bin> <signature.bin>");
    System.exit(2);
  }
}
