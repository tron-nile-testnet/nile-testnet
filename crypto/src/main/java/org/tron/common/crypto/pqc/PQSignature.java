package org.tron.common.crypto.pqc;

import org.tron.protos.Protocol.PQScheme;

/**
 * Post-quantum signature scheme facade bound to a keypair. Instance methods
 * (sign/verify/getAddress/getPublicKey/getPrivateKey) operate on the held
 * keypair. Stateless dispatch by {@link PQScheme} is provided by
 * {@link PQSchemeRegistry}.
 */
public interface PQSignature {

  PQScheme getScheme();

  int getPrivateKeyLength();

  int getPublicKeyLength();

  int getSignatureLength();

  /**
   * Signature length is logically a band {@code [min, max]}; fixed-length
   * schemes degenerate to the singleton {@code [max, max]}. The default
   * returns {@link #getSignatureLength()} so any new fixed-length scheme
   * gets exact-equality validation for free; variable-length schemes
   * (e.g. FN-DSA-512) override this to return their true lower bound.
   */
  default int getSignatureMinLength() {
    return getSignatureLength();
  }

  byte[] getPrivateKey();

  byte[] getPublicKey();

  /**
   * 21-byte TRON address derived from the held public key as
   * {@code 0x41 ‖ deriveHash(scheme, public_key)[12..32]} (see
   * {@link PQSchemeRegistry#computeAddress}).
   */
  byte[] getAddress();

  /** Sign {@code message} with the held private key; returns the raw signature. */
  byte[] sign(byte[] message);

  /**
   * Verify {@code signature} over {@code message} against the held public key.
   *
   * @return true iff the signature is cryptographically valid for the bound keypair
   */
  boolean verify(byte[] message, byte[] signature);

  default void validatePrivateKey(byte[] privateKey) {
    if (privateKey == null || privateKey.length != getPrivateKeyLength()) {
      throw new IllegalArgumentException(
          "invalid " + getScheme() + " private key length: "
              + (privateKey == null ? "null" : privateKey.length)
              + ", expected " + getPrivateKeyLength());
    }
  }

  default void validatePublicKey(byte[] publicKey) {
    if (publicKey == null || publicKey.length != getPublicKeyLength()) {
      throw new IllegalArgumentException(
          "invalid " + getScheme() + " public key length: "
              + (publicKey == null ? "null" : publicKey.length)
              + ", expected " + getPublicKeyLength());
    }
  }

  /**
   * Default band check {@code [getSignatureMinLength(), getSignatureLength()]}.
   * Fixed-length schemes inherit the singleton {@code [max, max]} band — no
   * override needed; variable-length schemes only need to override
   * {@link #getSignatureMinLength()}.
   */
  default void validateSignature(byte[] signature) {
    int min = getSignatureMinLength();
    int max = getSignatureLength();
    if (signature == null || signature.length < min || signature.length > max) {
      throw new IllegalArgumentException(
          "invalid " + getScheme() + " signature length: "
              + (signature == null ? "null" : signature.length)
              + ", expected " + (min == max ? String.valueOf(max) : (min + ".." + max)));
    }
  }
}
