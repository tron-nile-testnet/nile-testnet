package org.tron.core.actuator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.Test;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.capsule.BlockCapsule;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.BlockHeader;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

public class VMActuatorTest {

  @Test
  public void testConstantCallUsesConfiguredTimeoutVerbatim() {
    assertEquals(123_000L, VMActuator.calculateCpuLimitInUs(true, 80L, 5.0, 123L));
  }

  @Test
  public void testConstantCallWithoutConfiguredTimeoutUsesNetworkDeadline() {
    assertEquals(400_000L, VMActuator.calculateCpuLimitInUs(true, 80L, 5.0, 0L));
  }

  @Test
  public void testNonConstantCallIgnoresConfiguredTimeout() {
    assertEquals(400_000L, VMActuator.calculateCpuLimitInUs(false, 80L, 5.0, 123L));
  }

  /**
   * isCheckTransaction() must treat a block as "to be checked" when it carries EITHER
   * an ECDSA witness_signature OR a post-quantum pq_auth_sig. A PQ-only signed block
   * must not be mistaken for an unsigned (being-generated) block.
   */
  @Test
  public void isCheckTransactionRecognizesBothSignatureChannels() throws Exception {
    VMActuator actuator = new VMActuator(false);
    Field blockCapField = VMActuator.class.getDeclaredField("blockCap");
    blockCapField.setAccessible(true);
    Method isCheckTransaction = VMActuator.class.getDeclaredMethod("isCheckTransaction");
    isCheckTransaction.setAccessible(true);

    // No block (e.g. a constant call): not a check transaction.
    blockCapField.set(actuator, null);
    assertFalse((Boolean) isCheckTransaction.invoke(actuator));

    // Unsigned block (being generated): neither channel set -> not a check transaction.
    BlockCapsule unsigned = new BlockCapsule(1L, Sha256Hash.ZERO_HASH, 1L, ByteString.EMPTY);
    blockCapField.set(actuator, unsigned);
    assertFalse((Boolean) isCheckTransaction.invoke(actuator));

    // ECDSA witness_signature set -> check transaction.
    Block witnessSignedBlock = Block.newBuilder()
        .setBlockHeader(BlockHeader.newBuilder()
            .setWitnessSignature(ByteString.copyFrom(new byte[] {1, 2, 3})))
        .build();
    blockCapField.set(actuator, new BlockCapsule(witnessSignedBlock));
    assertTrue((Boolean) isCheckTransaction.invoke(actuator));

    // PQ pq_auth_sig set (no witness_signature) -> also a check transaction.
    BlockCapsule pqSigned = new BlockCapsule(1L, Sha256Hash.ZERO_HASH, 1L, ByteString.EMPTY);
    pqSigned.setPqAuthSig(PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setSignature(ByteString.copyFrom(new byte[] {1, 2, 3}))
        .build());
    blockCapField.set(actuator, pqSigned);
    assertTrue((Boolean) isCheckTransaction.invoke(actuator));
  }
}
