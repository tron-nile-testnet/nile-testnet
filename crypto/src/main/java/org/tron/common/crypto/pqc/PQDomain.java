package org.tron.common.crypto.pqc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Purpose a PQ signature is made for. Every PQ signature covers
 * {@code SHA-256(len(tag) ‖ tag ‖ target)} so a signature made for one purpose is never valid for
 * another, for example a TVM message signature replayed as a transaction signature.
 */
public enum PQDomain {
  TRANSACTION("TRON/PQ/TRANSACTION/V1"),
  BLOCK("TRON/PQ/BLOCK/V1"),
  RELAY("TRON/PQ/RELAY/V1"),
  MESSAGE("TRON/PQ/MESSAGE/V1");

  private final byte[] tag;

  PQDomain(String label) {
    this.tag = label.getBytes(StandardCharsets.US_ASCII);
  }

  public byte[] bind(byte[] target) {
    if (target == null) {
      throw new IllegalArgumentException("target must not be null");
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update((byte) tag.length);
      digest.update(tag);
      digest.update(target);
      return digest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
