import com.google.protobuf.ByteString;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import org.apache.commons.lang3.tuple.Pair;
import org.tron.common.crypto.pqc.PQAuthSigValidator;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.runtime.vm.DataWord;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;
import org.tron.core.vm.config.VMConfig;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.Transaction;

/** Executes checked-in public vectors through the actual checkout, not a copied validator. */
public final class Tip899ProtocolProbe {
  private static final HexFormat HEX = HexFormat.of();

  private Tip899ProtocolProbe() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      throw new IllegalArgumentException("expected manifest.tsv and fixture directory");
    }
    int count = 0;
    try {
      for (int id : new int[] {1, 2}) {
        DataWord address = address(id);
        flags(0, 0);
        require(PrecompiledContracts.getContractForAddress(address) == null, "both-off gate");
        flags(id == 1 ? 0 : 1, id == 2 ? 0 : 1);
        require(
            PrecompiledContracts.getContractForAddress(address) == null, "other-scheme-only gate");
        flags(id == 1 ? 1 : 0, id == 2 ? 1 : 0);
        require(PrecompiledContracts.getContractForAddress(address) != null, "own-scheme-on gate");
        System.out.println("PASS activation-gates scheme=" + id);
        count += 3;
      }
      flags(1, 1);
      for (String line : Files.readAllLines(Path.of(args[0]))) {
        String[] fields = line.split("\t");
        int id = Integer.parseInt(fields[1]);
        PQScheme scheme = PQScheme.forNumber(id);
        if ("crypto".equals(fields[0])) {
          byte[] pk = Files.readAllBytes(Path.of(fields[3]));
          byte[] message = Files.readAllBytes(Path.of(fields[4]));
          byte[] signature = Files.readAllBytes(Path.of(fields[5]));
          PQAuthSig auth =
              PQAuthSig.newBuilder()
                  .setScheme(scheme)
                  .setPublicKey(ByteString.copyFrom(pk))
                  .setSignature(ByteString.copyFrom(signature))
                  .build();
          require(
              PQAuthSigValidator.isLengthWithinBounds(auth) == Boolean.parseBoolean(fields[6]),
              fields[2] + " admission bounds");
          boolean verified = false;
          try {
            verified = PQSchemeRegistry.verify(scheme, pk, message, signature);
          } catch (IllegalArgumentException error) {
            // The real primitive throws on malformed argument sizes. Only this documented
            // size rejection may satisfy a negative; unrelated exceptions must fail the run.
            require(!Boolean.parseBoolean(fields[6]), fields[2] + " unexpected argument failure");
            String label = id == 1 ? "FN-DSA" : "ML-DSA";
            String expectedMessage =
                pk.length != PQSchemeRegistry.getPublicKeyLength(scheme)
                    ? label
                        + " public key length must be "
                        + PQSchemeRegistry.getPublicKeyLength(scheme)
                    : label + " signature length must be " + (id == 1 ? "617..667" : "2420");
            require(
                expectedMessage.equals(error.getMessage()), fields[2] + " unexpected exception");
          }
          require(verified == Boolean.parseBoolean(fields[7]), fields[2] + " crypto verification");
          if (fields[2].endsWith("/valid")) {
            require(
                Arrays.equals(PQSchemeRegistry.computeAddress(scheme, pk), HEX.parseHex(fields[8])),
                fields[2] + " canonical TRON address");
          }
        } else if ("precompile".equals(fields[0])) {
          PrecompiledContract contract = PrecompiledContracts.getContractForAddress(address(id));
          require(contract != null, "active precompile lookup");
          Pair<Boolean, byte[]> result = contract.execute(Files.readAllBytes(Path.of(fields[3])));
          require(result.getLeft(), fields[2] + " precompile execution status");
          require(
              Arrays.equals(HEX.parseHex(fields[4]), result.getRight()),
              fields[2] + " precompile word");
        } else {
          throw new IllegalArgumentException("unknown manifest row type");
        }
        System.out.println("PASS " + fields[0] + " " + fields[2]);
        count++;
      }
      for (String name : new String[] {"fn-dsa-512", "ml-dsa-44"}) {
        Path fixtures = Path.of(args[1]);
        byte[] wire = Files.readAllBytes(fixtures.resolve(name + ".pq-auth-sig.bin"));
        PQAuthSig auth = PQAuthSig.parseFrom(wire);
        require(PQAuthSigValidator.isLengthWithinBounds(auth), name + " fixture admission");
        require(Arrays.equals(wire, auth.toByteArray()), name + " actual PQAuthSig wire encoding");
        Transaction tx =
            Transaction.parseFrom(
                Files.readAllBytes(fixtures.resolve(name + ".transaction-field.bin")));
        require(
            tx.getPqAuthSigCount() == 1 && tx.getPqAuthSig(0).equals(auth),
            name + " actual Transaction field 6 semantics");
        require(
            Arrays.equals(
                tx.toByteArray(),
                Files.readAllBytes(fixtures.resolve(name + ".transaction-field.bin"))),
            name + " actual Transaction wire");
        System.out.println("PASS protobuf " + name);
        count++;
      }
      System.out.println("status=PASS checks=" + count + " scope=local-checkout-not-chain");
    } finally {
      flags(0, 0);
    }
  }

  private static DataWord address(int id) {
    return new DataWord(
        "000000000000000000000000000000000000000000000000000000000200001" + (id == 1 ? "6" : "8"));
  }

  private static void flags(long falcon, long mlDsa) {
    VMConfig.initAllowFnDsa512(falcon);
    VMConfig.initAllowMlDsa44(mlDsa);
  }

  private static void require(boolean condition, String message) {
    if (!condition) throw new IllegalStateException(message);
  }
}
