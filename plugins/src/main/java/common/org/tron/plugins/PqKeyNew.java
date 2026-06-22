package org.tron.plugins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.Callable;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.utils.StringUtil;
import org.tron.protos.Protocol.PQScheme;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

@Command(name = "new",
    mixinStandardHelpOptions = true,
    description = "Generate a new post-quantum key JSON file."
        + " The file contains seed, privateKey, publicKey, and the derived TRON address."
        + " privateKey takes priority at load time; seed is retained as a backup.")
public class PqKeyNew implements Callable<Integer> {

  private static final DateTimeFormatter TIMESTAMP_FMT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss").withZone(ZoneOffset.UTC);

  @Spec
  private CommandSpec spec;

  @Option(names = {"--scheme"},
      description = "PQ signature scheme: FN_DSA_512, ML_DSA_44 (default: ${DEFAULT-VALUE})",
      defaultValue = "FN_DSA_512")
  private String scheme;

  @Option(names = {"--output-dir"},
      description = "Directory to write the key JSON file (default: ${DEFAULT-VALUE})",
      defaultValue = "Wallet")
  private File outputDir;

  @Option(names = {"--json"},
      description = "Print a JSON summary (address, scheme, file path) instead of"
          + " human-readable text")
  private boolean json;

  @Option(names = {"--seed"},
      description = "Optional hex-encoded seed to derive the key from."
          + " Length must match the scheme (FN_DSA_512: 48 bytes / 96 hex chars,"
          + " ML_DSA_44: 32 bytes / 64 hex chars)."
          + " If omitted, a random seed is generated.")
  private String seed;

  @Override
  public Integer call() {
    PrintWriter out = spec.commandLine().getOut();
    PrintWriter err = spec.commandLine().getErr();
    try {
      PQScheme pqScheme = parseScheme(scheme, err);
      if (pqScheme == null) {
        return 1;
      }

      KeystoreCliUtils.ensureDirectory(outputDir);

      int seedLen = pqScheme == PQScheme.FN_DSA_512
          ? FNDSA512.SEED_LENGTH : MLDSA44.SEED_LENGTH;
      byte[] seedBytes = parseSeed(seed, pqScheme, seedLen, err);
      if (seedBytes == null) {
        return 1;
      }

      PQSignature kp = pqScheme == PQScheme.FN_DSA_512
          ? new FNDSA512(seedBytes) : new MLDSA44(seedBytes);
      String address = StringUtil.encode58Check(kp.getAddress());

      String keyJson = buildJson(pqScheme, seedBytes, kp, address);
      String fileName = buildFileName(pqScheme, address);
      File outFile = new File(outputDir, fileName);
      writeSecureFile(outFile.toPath(), keyJson);

      if (json) {
        ObjectMapper mapper = KeystoreCliUtils.mapper();
        ObjectNode node = mapper.createObjectNode();
        node.put("address", address);
        node.put("scheme", pqScheme.name());
        node.put("file", outFile.getPath());
        out.println(mapper.writeValueAsString(node));
      } else {
        out.println("Your new PQ key was generated");
        out.println();
        out.println("Scheme:                      " + pqScheme.name());
        out.println("Public address of the key:   " + address);
        out.println("Path of the key file:        " + outFile.getPath());
        out.println();
        out.println("- You can share your public address with anyone.");
        out.println("- You must NEVER share the key file with anyone!"
            + " The key grants full control over the corresponding address!");
        out.println("- You must BACKUP your key file! Loss of the file means"
            + " loss of access to the address.");
        out.println("- privateKey takes priority at load time; seed is retained as a backup.");
        if (pqScheme == PQScheme.FN_DSA_512) {
          out.println();
          out.println("NOTE (FN_DSA_512): The seed in this file is for reference only."
              + " Falcon keygen is NOT bit-stable across JVM versions, so the stored"
              + " privateKey + publicKey are always used.");
        }
      }
      return 0;
    } catch (Exception e) {
      err.println("Error: " + e.getMessage());
      return 1;
    }
  }

  private static PQScheme parseScheme(String name, PrintWriter err) {
    if ("FN_DSA_512".equalsIgnoreCase(name)) {
      return PQScheme.FN_DSA_512;
    }
    if ("ML_DSA_44".equalsIgnoreCase(name)) {
      return PQScheme.ML_DSA_44;
    }
    err.println("Unknown scheme '" + name + "'. Valid values: FN_DSA_512, ML_DSA_44");
    return null;
  }

  /**
   * Returns the seed bytes to derive the key from. When {@code seedHex} is null or blank a fresh
   * random seed of {@code seedLen} bytes is generated. Otherwise the hex string is decoded and its
   * length validated against the scheme. Returns null (after printing to err) on any error.
   */
  private static byte[] parseSeed(String seedHex, PQScheme scheme, int seedLen, PrintWriter err) {
    if (seedHex == null || seedHex.trim().isEmpty()) {
      byte[] seedBytes = new byte[seedLen];
      new SecureRandom().nextBytes(seedBytes);
      return seedBytes;
    }
    String normalized = seedHex.trim();
    if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
      normalized = normalized.substring(2);
    }
    byte[] seedBytes;
    try {
      seedBytes = Hex.decode(normalized);
    } catch (Exception e) {
      err.println("Invalid seed: not a valid hex string.");
      return null;
    }
    if (seedBytes.length != seedLen) {
      err.println("Invalid seed length for " + scheme.name() + ": expected " + seedLen
          + " bytes (" + (seedLen * 2) + " hex chars), got " + seedBytes.length + " bytes.");
      return null;
    }
    return seedBytes;
  }

  private static String buildJson(PQScheme scheme, byte[] seedBytes,
      PQSignature kp, String address) {
    StringBuilder sb = new StringBuilder();
    sb.append("{\n");
    sb.append("  \"scheme\": \"").append(scheme.name()).append("\",\n");
    sb.append("  \"seed\": \"").append(Hex.toHexString(seedBytes)).append("\",\n");
    sb.append("  \"privateKey\": \"").append(Hex.toHexString(kp.getPrivateKey())).append("\",\n");
    sb.append("  \"publicKey\": \"").append(Hex.toHexString(kp.getPublicKey())).append("\"");
    sb.append(",\n  \"address\": \"").append(address).append("\"");
    sb.append("\n}\n");
    return sb.toString();
  }

  private static String buildFileName(PQScheme scheme, String address) {
    String ts = TIMESTAMP_FMT.format(Instant.now());
    return ts + "--" + scheme.name() + "--" + address + ".json";
  }

  private static void writeSecureFile(Path path, String content) throws Exception {
    byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
    try {
      // Create the file with 0600 permissions atomically.
      Set<PosixFilePermission> perms = EnumSet.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE);
      FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
      Files.createFile(path, attr);
      Files.write(path, bytes, StandardOpenOption.WRITE);
    } catch (UnsupportedOperationException ignored) {
      // Non-POSIX filesystem (e.g. Windows): fall back to plain write.
      Files.write(path, bytes);
    }
  }
}
