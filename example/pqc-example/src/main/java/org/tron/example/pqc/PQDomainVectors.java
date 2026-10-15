package org.tron.example.pqc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.pqc.PQDomain;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.protos.Protocol.PQScheme;

public class PQDomainVectors {

  private static final String DEFAULT_OUT =
      "framework/src/test/resources/pqc/pq-domain-v1.json";
  private static final byte[] TARGET = Hex.decode(
      "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd");
  private static final String RAW = "RAW";

  public static void main(String[] args) throws Exception {
    ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    ObjectNode root = mapper.createObjectNode();
    root.put("version", "pq-domain-v1");
    root.put("binding", "SHA-256(len(tag) || tag || target), len(tag) one byte, tag ASCII");
    ObjectNode activation = root.putObject("activation");
    activation.put("proposal", "ALLOW_PQ_DOMAIN_SEPARATION");
    activation.put("proposal_id", 1002);
    activation.put("inactive", "signed bytes are the raw target");
    activation.put("active", "signed bytes are the bound digest of the verifying domain");
    root.put("target", Hex.toHexString(TARGET));

    ArrayNode domains = root.putArray("domains");
    for (PQDomain domain : PQDomain.values()) {
      byte[] tag = tagOf(domain);
      byte[] preimage = new byte[1 + tag.length + TARGET.length];
      preimage[0] = (byte) tag.length;
      System.arraycopy(tag, 0, preimage, 1, tag.length);
      System.arraycopy(TARGET, 0, preimage, 1 + tag.length, TARGET.length);
      if (!MessageDigest.isEqual(
          MessageDigest.getInstance("SHA-256").digest(preimage), domain.bind(TARGET))) {
        throw new IllegalStateException("binding mismatch " + domain);
      }
      ObjectNode d = domains.addObject();
      d.put("name", domain.name());
      d.put("tag", new String(tag, StandardCharsets.US_ASCII));
      d.put("preimage", Hex.toHexString(preimage));
      d.put("bound", Hex.toHexString(domain.bind(TARGET)));
    }

    ArrayNode schemes = root.putArray("schemes");
    for (PQScheme scheme : new PQScheme[] {PQScheme.FN_DSA_512, PQScheme.ML_DSA_44}) {
      byte[] seed = new byte[PQSchemeRegistry.getSeedLength(scheme)];
      for (int i = 0; i < seed.length; i++) {
        seed[i] = (byte) i;
      }
      PQSignature key = PQSchemeRegistry.fromSeed(scheme, seed);
      Map<String, byte[]> sigs = new LinkedHashMap<>();
      sigs.put(RAW, key.sign(TARGET));
      for (PQDomain domain : PQDomain.values()) {
        sigs.put(domain.name(), key.sign(domain.bind(TARGET)));
      }

      ObjectNode s = schemes.addObject();
      s.put("scheme", scheme.name());
      s.put("seed", Hex.toHexString(seed));
      s.put("public_key", Hex.toHexString(key.getPublicKey()));
      ObjectNode sigNode = s.putObject("signatures");
      sigs.forEach((name, sig) -> sigNode.put(name, Hex.toHexString(sig)));

      ArrayNode cases = s.putArray("cases");
      for (Map.Entry<String, byte[]> sig : sigs.entrySet()) {
        addCase(cases, scheme, key, sig.getKey(), sig.getValue(), false, null);
      }
      for (PQDomain domain : PQDomain.values()) {
        for (Map.Entry<String, byte[]> sig : sigs.entrySet()) {
          addCase(cases, scheme, key, sig.getKey(), sig.getValue(), true, domain);
        }
      }
    }

    File out = new File(args.length > 0 ? args[0] : DEFAULT_OUT);
    out.getParentFile().mkdirs();
    mapper.writeValue(out, root);
    System.out.println("wrote " + out.getPath());
  }

  private static void addCase(ArrayNode cases, PQScheme scheme, PQSignature key, String signedAs,
      byte[] sig, boolean active, PQDomain domain) {
    byte[] message = active ? domain.bind(TARGET) : TARGET;
    boolean expected = active ? domain.name().equals(signedAs) : RAW.equals(signedAs);
    if (PQSchemeRegistry.verify(scheme, key.getPublicKey(), message, sig) != expected) {
      throw new IllegalStateException(scheme + " " + signedAs + " " + active + " " + domain);
    }
    ObjectNode c = cases.addObject();
    c.put("signature", signedAs);
    c.put("active", active);
    if (active) {
      c.put("domain", domain.name());
    } else {
      c.putNull("domain");
    }
    c.put("message", Hex.toHexString(message));
    c.put("expected", expected);
  }

  private static byte[] tagOf(PQDomain domain) {
    return ("TRON/PQ/" + domain.name() + "/V1").getBytes(StandardCharsets.US_ASCII);
  }
}
