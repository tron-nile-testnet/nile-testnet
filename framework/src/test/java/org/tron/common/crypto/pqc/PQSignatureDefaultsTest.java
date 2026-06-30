package org.tron.common.crypto.pqc;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

/**
 * Drives the {@link PQSignature} default validator branches (null and
 * length-mismatch) via a minimal in-test implementation. {@link FNDSA512}
 * exposes these defaults but the cryptographic instances exercise mostly the
 * happy paths; the explicit fixture here forces the error legs.
 */
public class PQSignatureDefaultsTest {

  private PQSignature stub;

  @Before
  public void setUp() {
    stub = new PQSignature() {
      @Override
      public PQScheme getScheme() {
        return PQScheme.FN_DSA_512;
      }

      @Override
      public int getPrivateKeyLength() {
        return 16;
      }

      @Override
      public int getPublicKeyLength() {
        return 8;
      }

      @Override
      public int getSignatureLength() {
        return 32;
      }

      @Override
      public byte[] getPrivateKey() {
        return new byte[getPrivateKeyLength()];
      }

      @Override
      public byte[] getPublicKey() {
        return new byte[getPublicKeyLength()];
      }

      @Override
      public byte[] getAddress() {
        return new byte[21];
      }

      @Override
      public byte[] sign(byte[] message) {
        return new byte[1];
      }

      @Override
      public boolean verify(byte[] message, byte[] signature) {
        return false;
      }
    };
  }

  @Test
  public void validatePrivateKeyRejectsNull() {
    try {
      stub.validatePrivateKey(null);
      fail("null private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
      assertTrue(expected.getMessage().contains("null"));
    }
  }

  @Test
  public void validatePrivateKeyRejectsWrongLength() {
    try {
      stub.validatePrivateKey(new byte[stub.getPrivateKeyLength() - 1]);
      fail("short private key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("private key length"));
    }
  }

  @Test
  public void validatePrivateKeyAcceptsExactLength() {
    stub.validatePrivateKey(new byte[stub.getPrivateKeyLength()]);
  }

  @Test
  public void validatePublicKeyRejectsNull() {
    try {
      stub.validatePublicKey(null);
      fail("null public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
      assertTrue(expected.getMessage().contains("null"));
    }
  }

  @Test
  public void validatePublicKeyRejectsWrongLength() {
    try {
      stub.validatePublicKey(new byte[stub.getPublicKeyLength() + 1]);
      fail("over-long public key must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("public key length"));
    }
  }

  @Test
  public void validatePublicKeyAcceptsExactLength() {
    stub.validatePublicKey(new byte[stub.getPublicKeyLength()]);
  }

  @Test
  public void validateSignatureRejectsNull() {
    try {
      stub.validateSignature(null);
      fail("null signature must be rejected");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("signature length"));
      assertTrue(expected.getMessage().contains("null"));
    }
  }
}
