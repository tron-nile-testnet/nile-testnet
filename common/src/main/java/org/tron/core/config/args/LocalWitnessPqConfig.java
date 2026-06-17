package org.tron.core.config.args;

import com.typesafe.config.Optional;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.tron.core.exception.TronError;

/**
 * Auto-bound shape of the {@code localPqWitness} section. Bound via
 * {@link com.typesafe.config.ConfigBeanFactory}. All fields are {@link Optional}
 * so the section may appear with no {@code accountAddress} and/or no entries
 * (reference.conf ships an empty key list).
 *
 * <p>{@code keys} is a list of JSON file paths; each file holds one PQ witness
 * keypair ({@code scheme} plus either {@code seed} or {@code privateKey} [+
 * {@code publicKey}]). The files are read and the key material validated later
 * in WitnessInitializer, which has access to the crypto module.
 */
@Getter
@Setter
public class LocalWitnessPqConfig {

  /**
   * Counterpart to {@code localWitnessAccountAddress} for the PQ witness path:
   * overrides the on-chain witness account address for the single-PQ-witness
   * case. Independent of the ECDSA address.
   * Validated in {@link Args} / WitnessInitializer.
   */
  @Optional
  private String accountAddress;

  /**
   * Paths to per-keypair JSON key files (see WitnessInitializer for the file
   * schema). Relative paths are resolved against the working directory.
   */
  @Optional
  private List<String> keys = new ArrayList<>();

  /**
   * Validate the structural shape of the bound entries: every {@code keys} path
   * must be non-blank. Scheme validity and key material (hex length, public-key
   * recovery) are checked later in WitnessInitializer.
   */
  public void postProcess() {
    for (int i = 0; i < keys.size(); i++) {
      if (StringUtils.isBlank(keys.get(i))) {
        throw witnessError("%s[%d] must be a non-blank JSON key file path",
            LocalWitnessConfig.PQ_KEYS_PATH, i);
      }
    }
  }

  private static TronError witnessError(String format, Object... args) {
    return new TronError(String.format(format, args), TronError.ErrCode.WITNESS_INIT);
  }
}
