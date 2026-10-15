package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

public class PQDomainVectorsTest {

  private static JsonNode vectors;
  private static byte[] target;

  @BeforeClass
  public static void load() throws Exception {
    try (InputStream is = PQDomainVectorsTest.class.getResourceAsStream(
        "/pqc/pq-domain-v1.json")) {
      assertNotNull(is);
      vectors = new ObjectMapper().readTree(is);
    }
    target = Hex.decode(vectors.get("target").asText());
  }

  @Test
  public void boundDigestsMatchPQDomain() {
    assertEquals(PQDomain.values().length, vectors.get("domains").size());
    for (JsonNode d : vectors.get("domains")) {
      PQDomain domain = PQDomain.valueOf(d.get("name").asText());
      assertArrayEquals(Hex.decode(d.get("bound").asText()), domain.bind(target));
    }
  }

  @Test
  public void seedsReproduceThePublishedKeys() {
    for (JsonNode s : vectors.get("schemes")) {
      PQScheme scheme = PQScheme.valueOf(s.get("scheme").asText());
      PQSignature key = PQSchemeRegistry.fromSeed(scheme, Hex.decode(s.get("seed").asText()));
      assertArrayEquals(Hex.decode(s.get("public_key").asText()), key.getPublicKey());
    }
  }

  @Test
  public void everyCaseVerifiesAsExpected() {
    for (JsonNode s : vectors.get("schemes")) {
      PQScheme scheme = PQScheme.valueOf(s.get("scheme").asText());
      byte[] publicKey = Hex.decode(s.get("public_key").asText());
      assertEquals(25, s.get("cases").size());
      for (JsonNode c : s.get("cases")) {
        boolean active = c.get("active").asBoolean();
        byte[] message = active
            ? PQDomain.valueOf(c.get("domain").asText()).bindIf(true, target)
            : target;
        String label = scheme + " " + c.get("signature").asText() + " " + c.get("domain");
        assertArrayEquals(label, Hex.decode(c.get("message").asText()), message);
        byte[] sig = Hex.decode(s.get("signatures").get(c.get("signature").asText()).asText());
        assertEquals(label, c.get("expected").asBoolean(),
            PQSchemeRegistry.verify(scheme, publicKey, message, sig));
      }
    }
  }
}
