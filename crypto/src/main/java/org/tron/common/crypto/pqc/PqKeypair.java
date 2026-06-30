package org.tron.common.crypto.pqc;

import lombok.ToString;
import lombok.Value;
import org.tron.protos.Protocol.PQScheme;

/**
 * Immutable hex-encoded post-quantum keypair (scheme + private + public key).
 * Bundles the three together so each witness key can declare its own PQ scheme,
 * supporting a node that hosts SRs under different PQ algorithms (e.g. Falcon-512
 * and ML-DSA-44 side by side).
 *
 * <p>{@code privateKey} is excluded from {@link #toString()} to prevent
 * accidental leakage of secret-key material into logs.
 */
@Value
public class PqKeypair {
  PQScheme scheme;
  @ToString.Exclude
  String privateKey;
  String publicKey;
}
