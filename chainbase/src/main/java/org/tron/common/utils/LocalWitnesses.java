/*
 * java-tron is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * java-tron is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.tron.common.utils;

import com.google.common.collect.Lists;
import java.util.Arrays;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.core.config.Parameter.ChainConstant;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.PQScheme;

@Slf4j(topic = "app")
public class LocalWitnesses {

  @Getter
  private List<String> privateKeys = Lists.newArrayList();

  /**
   * The ECDSA SR account address. Derived from the local ECDSA witness key and
   * used by the legacy (secp256k1) block-production / signing path.
   */
  @Setter
  @Getter
  private byte[] witnessAccountAddress;

  /**
   * Pre-derived PQ keypairs (scheme + private + public, hex), one per witness.
   * Each keypair declares its own PQ scheme so a single node can host SRs
   * running different PQ algorithms (e.g. some Falcon-512, some ML-DSA-44).
   * Expected byte lengths depend on the keypair's scheme: FN-DSA-512 uses a
   * 1280-byte private key (2560 hex) and 896-byte public key (1792 hex).
   *
   * <p>Configured directly (rather than derived from a seed on the node) so
   * the runtime path is not exposed to potential cross-platform floating-point
   * non-determinism in BC's Falcon keygen — operators generate the keypair
   * off-line and ship both halves to the node.
   */
  @Getter
  private List<PqKeypair> pqKeypairs = Lists.newArrayList();

  /**
   * PQ-side counterpart to {@link #witnessAccountAddress}. Distinct from the
   * ECDSA address so a node can host two different SRs (one ECDSA + one PQ).
   * When the same SR account authorises both an ECDSA key and a PQ key, both
   * fields point to the same address.
   */
  @Setter
  @Getter
  private byte[] pqWitnessAccountAddress;

  public LocalWitnesses() {
  }

  public LocalWitnesses(String privateKey) {
    addPrivateKeys(privateKey);
  }

  public LocalWitnesses(List<String> privateKeys) {
    setPrivateKeys(privateKeys);
  }

  /**
   * Resolve the ECDSA witness account address from an explicit override, or
   * fall back to the first ECDSA private key. PQ-side resolution is handled
   * separately by {@link #initPqWitnessAccountAddress(byte[])} so the two
   * consensus paths do not interfere on nodes hosting one SR per scheme.
   */
  public void initWitnessAccountAddress(final byte[] witnessAddress,
      boolean isECKeyCryptoEngine) {
    if (witnessAddress != null) {
      this.witnessAccountAddress = witnessAddress;
      return;
    }
    if (!CollectionUtils.isEmpty(privateKeys)) {
      byte[] privateKey = ByteArray.fromHexString(getPrivateKey());
      final SignInterface ecKey = SignUtils.fromPrivate(privateKey,
          isECKeyCryptoEngine);
      this.witnessAccountAddress = ecKey.getAddress();
    }
  }

  /**
   * Resolve the PQ witness account address from an explicitAccountAddress override, or fall
   * back to the first configured PQ keypair's public key. Kept separate from
   * {@link #initWitnessAccountAddress} so a node running two SRs (one ECDSA +
   * one PQ) can carry both addresses without one path overwriting the other.
   */
  public void initPqWitnessAccountAddress(final byte[] explicitAccountAddress) {
    if (explicitAccountAddress != null) {
      this.pqWitnessAccountAddress = explicitAccountAddress;
      return;
    }
    if (!CollectionUtils.isEmpty(pqKeypairs)) {
      PqKeypair first = pqKeypairs.get(0);
      byte[] pubKey = ByteArray.fromHexString(first.getPublicKey());
      this.pqWitnessAccountAddress = PQSchemeRegistry.computeAddress(first.getScheme(), pubKey);
    }
  }

  /**
   * One account address should authorise its witness permission to only one key
   * (either ECDSA or PQ). Throws if the same address is configured for both.
   */
  public void checkWitnessAddressConflict() {
    if (witnessAccountAddress != null && pqWitnessAccountAddress != null
        && Arrays.equals(witnessAccountAddress, pqWitnessAccountAddress)) {
      throw new TronError(
          String.format("Witness account address %s is authorised to both an ECDSA and a PQ key; "
                  + "one account address should authorise witness permission to only one key.",
              ByteArray.toHexString(witnessAccountAddress)),
          TronError.ErrCode.WITNESS_INIT);
    }
  }

  /**
   * Private key of ECKey.
   */
  public void setPrivateKeys(final List<String> privateKeys) {
    if (CollectionUtils.isEmpty(privateKeys)) {
      return;
    }
    for (String privateKey : privateKeys) {
      validate(privateKey);
    }
    this.privateKeys = privateKeys;
  }

  private void validate(String privateKey) {
    if (StringUtils.startsWithIgnoreCase(privateKey, "0X")) {
      privateKey = privateKey.substring(2);
    }

    if (StringUtils.isBlank(privateKey)
        || privateKey.length() != ChainConstant.PRIVATE_KEY_LENGTH) {
      throw new TronError(String.format("private key must be %d hex string, actual: %d",
          ChainConstant.PRIVATE_KEY_LENGTH,
          StringUtils.isBlank(privateKey) ? 0 : privateKey.length()),
          TronError.ErrCode.WITNESS_INIT);
    }
    if (!StringUtil.isHexadecimal(privateKey)) {
      throw new TronError("private key must be hex string",
          TronError.ErrCode.WITNESS_INIT);
    }
  }

  public void addPrivateKeys(String privateKey) {
    validate(privateKey);
    this.privateKeys.add(privateKey);
  }

  /**
   * Pre-derived PQ keypairs (scheme + priv + pub) used as signing keys. Each
   * entry's scheme must be registered and its private/public hex byte lengths
   * must match that scheme's required sizes; the scheme is per-entry so
   * different witnesses on the same node can use different PQ algorithms.
   */
  public void setPqKeypairs(final List<PqKeypair> pqKeypairs) {
    if (CollectionUtils.isEmpty(pqKeypairs)) {
      return;
    }
    for (PqKeypair kp : pqKeypairs) {
      PQScheme scheme = kp.getScheme();
      if (scheme == null || !PQSchemeRegistry.contains(scheme)) {
        throw new TronError("unsupported PQ signature scheme: " + scheme,
            TronError.ErrCode.WITNESS_INIT);
      }
      int expectedPrivLen = PQSchemeRegistry.getPrivateKeyLength(scheme);
      int expectedPubLen = PQSchemeRegistry.getPublicKeyLength(scheme);
      validatePqKey(kp.getPrivateKey(), expectedPrivLen, "PQ private key");
      validatePqKey(kp.getPublicKey(), expectedPubLen, "PQ public key");
      try {
        PQSchemeRegistry.fromKeypair(scheme,
            ByteArray.fromHexString(kp.getPrivateKey()),
            ByteArray.fromHexString(kp.getPublicKey()));
      } catch (IllegalArgumentException e) {
        throw new TronError("PQ private/public keypair mismatch for scheme: " + scheme,
            TronError.ErrCode.WITNESS_INIT);
      }
    }
    this.pqKeypairs = pqKeypairs;
  }

  private static void validatePqKey(String key, int expectedLen, String label) {
    String hex = key;
    // Match downstream ByteArray.fromHexString, which only strips lowercase "0x".
    if (StringUtils.startsWith(hex, "0x")) {
      hex = hex.substring(2);
    }
    int expectedHexLen = expectedLen * 2;
    if (StringUtils.isBlank(hex) || hex.length() != expectedHexLen) {
      throw new TronError(String.format("%s must be %d hex chars, actual: %d",
          label, expectedHexLen, StringUtils.isBlank(hex) ? 0 : hex.length()),
          TronError.ErrCode.WITNESS_INIT);
    }
    if (!StringUtil.isHexadecimal(hex)) {
      throw new TronError(label + " must be hex string", TronError.ErrCode.WITNESS_INIT);
    }
  }

  //get the first one recently
  public String getPrivateKey() {
    if (CollectionUtils.isEmpty(privateKeys)) {
      logger.warn("PrivateKey is null.");
      return null;
    }
    return privateKeys.get(0);
  }

  public byte[] getPublicKey() {
    if (CollectionUtils.isEmpty(privateKeys)) {
      logger.warn("PrivateKey is null.");
      return null;
    }
    byte[] privateKey = ByteArray.fromHexString(getPrivateKey());
    final ECKey ecKey = ECKey.fromPrivate(privateKey);
    return ecKey.getAddress();
  }

}
