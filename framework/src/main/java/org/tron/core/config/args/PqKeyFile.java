package org.tron.core.config.args;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

/**
 * Shape of a PQ witness key JSON file referenced from {@code localPqWitness.keys}.
 * Each file holds one keypair. Exactly one material source is supplied:
 * {@code seed}, or {@code privateKey} (plus {@code publicKey} for schemes whose
 * public key BouncyCastle cannot derive from the private key, i.e. FN_DSA_512).
 * For ML_DSA_44 the public key is derived from the private key, so
 * {@code publicKey} must be omitted. Parsed by Jackson in {@link WitnessInitializer}.
 *
 * <pre>
 *   { "scheme": "FN_DSA_512", "privateKey": "&lt;hex&gt;", "publicKey": "&lt;hex&gt;" }
 *   { "scheme": "ML_DSA_44",  "privateKey": "&lt;hex&gt;" }
 *   { "scheme": "FN_DSA_512", "seed": "&lt;hex&gt;" }
 * </pre>
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class PqKeyFile {

  private String scheme;
  private String seed;
  private String privateKey;
  private String publicKey;
}
