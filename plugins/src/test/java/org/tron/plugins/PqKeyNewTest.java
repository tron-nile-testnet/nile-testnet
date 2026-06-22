package org.tron.plugins;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Locale;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import picocli.CommandLine;

public class PqKeyNewTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  @Test
  public void testNewMlDsa44Key() throws Exception {
    File dir = tempFolder.newFolder("pq-ml");

    int exitCode = new CommandLine(new Toolkit())
        .execute("pq-key", "new",
            "--scheme", "ML_DSA_44",
            "--output-dir", dir.getAbsolutePath());

    assertEquals(0, exitCode);
    File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
    assertNotNull(files);
    assertEquals("Should create exactly one key file", 1, files.length);

    JsonNode key = MAPPER.readTree(files[0]);
    assertEquals("ML_DSA_44", key.get("scheme").asText());
    assertEquals("seed should be 64 hex chars", 64, key.get("seed").asText().length());
    assertEquals("privateKey should be 5120 hex chars",
        5120, key.get("privateKey").asText().length());
    assertEquals("publicKey should be 2624 hex chars",
        2624, key.get("publicKey").asText().length());
    assertTrue("address should start with T", key.get("address").asText().startsWith("T"));
  }

  @Test
  public void testNewFnDsa512Key() throws Exception {
    File dir = tempFolder.newFolder("pq-fn");

    int exitCode = new CommandLine(new Toolkit())
        .execute("pq-key", "new",
            "--scheme", "FN_DSA_512",
            "--output-dir", dir.getAbsolutePath());

    assertEquals(0, exitCode);
    File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
    assertNotNull(files);
    assertEquals(1, files.length);

    JsonNode key = MAPPER.readTree(files[0]);
    assertEquals("FN_DSA_512", key.get("scheme").asText());
    assertEquals("seed should be 96 hex chars", 96, key.get("seed").asText().length());
    assertEquals("privateKey should be 2560 hex chars",
        2560, key.get("privateKey").asText().length());
    assertEquals("publicKey should be 1792 hex chars",
        1792, key.get("publicKey").asText().length());
    assertTrue("address should start with T", key.get("address").asText().startsWith("T"));
  }

  @Test
  public void testJsonOutput() throws Exception {
    File dir = tempFolder.newFolder("pq-json");

    StringWriter out = new StringWriter();
    CommandLine cmd = new CommandLine(new Toolkit());
    cmd.setOut(new PrintWriter(out));

    int exitCode = cmd.execute("pq-key", "new",
        "--scheme", "ML_DSA_44",
        "--output-dir", dir.getAbsolutePath(),
        "--json");

    assertEquals(0, exitCode);
    JsonNode summary = MAPPER.readTree(out.toString().trim());
    assertTrue("address should start with T", summary.get("address").asText().startsWith("T"));
    assertEquals("ML_DSA_44", summary.get("scheme").asText());
    assertTrue("file path should be present", summary.has("file"));
  }

  @Test
  public void testInvalidScheme() throws Exception {
    StringWriter err = new StringWriter();
    CommandLine cmd = new CommandLine(new Toolkit());
    cmd.setErr(new PrintWriter(err));

    int exitCode = cmd.execute("pq-key", "new", "--scheme", "UNKNOWN");

    assertEquals(1, exitCode);
    assertTrue(err.toString().contains("Unknown scheme"));
  }

  @Test
  public void testOutputDirCreated() throws Exception {
    File dir = new File(tempFolder.getRoot(), "nested/pq/keys");

    int exitCode = new CommandLine(new Toolkit())
        .execute("pq-key", "new",
            "--scheme", "ML_DSA_44",
            "--output-dir", dir.getAbsolutePath());

    assertEquals(0, exitCode);
    assertTrue("Nested output dir should be created", dir.exists());
    File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
    assertNotNull(files);
    assertEquals(1, files.length);
  }

  @Test
  public void testFilePermissions() throws Exception {
    String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    org.junit.Assume.assumeTrue("POSIX permissions test, skip on Windows",
        !os.contains("win"));

    File dir = tempFolder.newFolder("pq-perms");

    int exitCode = new CommandLine(new Toolkit())
        .execute("pq-key", "new",
            "--scheme", "ML_DSA_44",
            "--output-dir", dir.getAbsolutePath());

    assertEquals(0, exitCode);
    File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
    assertNotNull(files);
    assertEquals(1, files.length);

    java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
        Files.getPosixFilePermissions(files[0].toPath());
    assertEquals("Key file should have owner-only permissions (rw-------)",
        java.util.EnumSet.of(
            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE),
        perms);
  }

  @Test
  public void testFileNameContainsScheme() throws Exception {
    File dir = tempFolder.newFolder("pq-name");

    int exitCode = new CommandLine(new Toolkit())
        .execute("pq-key", "new",
            "--scheme", "FN_DSA_512",
            "--output-dir", dir.getAbsolutePath());

    assertEquals(0, exitCode);
    File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
    assertNotNull(files);
    assertEquals(1, files.length);
    assertTrue("File name should contain scheme",
        files[0].getName().contains("FN_DSA_512"));
  }

  @Test
  public void testKeyFileIsValidJson() throws Exception {
    File dir = tempFolder.newFolder("pq-valid");

    int exitCode = new CommandLine(new Toolkit())
        .execute("pq-key", "new",
            "--scheme", "ML_DSA_44",
            "--output-dir", dir.getAbsolutePath());

    assertEquals(0, exitCode);
    File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
    assertNotNull(files);
    String content = new String(Files.readAllBytes(files[0].toPath()), StandardCharsets.UTF_8);
    JsonNode node = MAPPER.readTree(content);
    assertNotNull("File content must be valid JSON", node);
  }
}
