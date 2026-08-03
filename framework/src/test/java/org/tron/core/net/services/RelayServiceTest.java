package org.tron.core.net.services;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

import com.google.protobuf.ByteString;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import javax.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ReflectUtils;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.net.P2pEventHandlerImpl;
import org.tron.core.net.TronNetDelegate;
import org.tron.core.net.TronNetService;
import org.tron.core.net.message.adv.BlockMessage;
import org.tron.core.net.message.handshake.HelloMessage;
import org.tron.core.net.peer.Item;
import org.tron.core.net.peer.PeerConnection;
import org.tron.core.net.peer.PeerManager;
import org.tron.core.net.service.relay.RelayService;
import org.tron.p2p.P2pConfig;
import org.tron.p2p.connection.Channel;
import org.tron.p2p.discover.Node;
import org.tron.p2p.utils.NetUtil;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

@Slf4j(topic = "net")
public class RelayServiceTest extends BaseTest {

  @Resource
  private RelayService service;

  @Resource
  private P2pEventHandlerImpl p2pEventHandler;

  @Resource
  private TronNetService tronNetService;

  static {
    Args.setParam(new String[]{"--output-directory", dbPath(), "--debug"},
        TestConstants.TEST_CONF);
  }

  @After
  public void clearPeers() {
    closePeer();
  }

  @Test
  public void test() throws Exception {
    initWitness();
    testGetNextWitnesses();
    testBroadcast();
    testCheckHelloMessage();
  }

  private void initWitness() {
    // key: 0154435f065a57fec6af1e12eaa2fa600030639448d7809f4c65bdcf8baed7e5
    // Hex: 418A8D690BF36806C36A7DAE3AF796643C1AA9CC01
    // Base58: TNboetpFgv9SqMoHvaVt626NLXETnbdW1K
    byte[] key = Hex.decode("418A8D690BF36806C36A7DAE3AF796643C1AA9CC01");//exist already
    WitnessCapsule witnessCapsule = chainBaseManager.getWitnessStore().get(key);
    witnessCapsule.setVoteCount(1000);
    chainBaseManager.getWitnessStore().put(key, witnessCapsule);
    List<ByteString> list = new ArrayList<>();
    List<WitnessCapsule> witnesses = chainBaseManager.getWitnessStore().getAllWitnesses();
    witnesses.sort(Comparator.comparingLong(w -> -w.getVoteCount()));
    witnesses.forEach(witness -> list.add(witness.getAddress()));
    chainBaseManager.getWitnessScheduleStore().saveActiveWitnesses(list);
  }

  public void testGetNextWitnesses() throws Exception {
    Method method = service.getClass().getDeclaredMethod(
            "getNextWitnesses", ByteString.class, Integer.class);
    method.setAccessible(true);
    Set<ByteString> s1 = (Set<ByteString>) method.invoke(
            service, getFromHexString("418A8D690BF36806C36A7DAE3AF796643C1AA9CC01"), 3);
    Assert.assertEquals(3, s1.size());
    assertContains(s1, "41299F3DB80A24B20A254B89CE639D59132F157F13");
    assertContains(s1, "41807337F180B62A77576377C1D0C9C24DF5C0DD62");
    assertContains(s1, "415430A3F089154E9E182DDD6FE136A62321AF22A7");

    Set<ByteString> s2 = (Set<ByteString>) method.invoke(
            service, getFromHexString("41FAB5FBF6AFB681E4E37E9D33BDDB7E923D6132E5"), 3);
    Assert.assertEquals(3, s2.size());
    assertContains(s2, "4114EEBE4D30A6ACB505C8B00B218BDC4733433C68");
    assertContains(s2, "418A8D690BF36806C36A7DAE3AF796643C1AA9CC01");
    assertContains(s2, "41299F3DB80A24B20A254B89CE639D59132F157F13");

    Set<ByteString> s3 = (Set<ByteString>) method.invoke(
            service, getFromHexString("418A8D690BF36806C36A7DAE3AF796643C1AA9CC01"), 1);
    Assert.assertEquals(1, s3.size());
    assertContains(s3, "41299F3DB80A24B20A254B89CE639D59132F157F13");
  }

  private void testBroadcast() {
    try {
      PeerConnection peer = new PeerConnection();
      InetSocketAddress a1 = new InetSocketAddress("127.0.0.2", 10001);
      Channel c1 = mock(Channel.class);
      Mockito.when(c1.getInetSocketAddress()).thenReturn(a1);
      Mockito.when(c1.getInetAddress()).thenReturn(a1.getAddress());
      doNothing().when(c1).send((byte[]) any());

      peer.setChannel(c1);
      peer.setAddress(getFromHexString("41299F3DB80A24B20A254B89CE639D59132F157F13"));
      peer.setNeedSyncFromPeer(false);
      peer.setNeedSyncFromUs(false);

      List<PeerConnection> peers = new ArrayList<>();
      peers.add(peer);

      TronNetDelegate tronNetDelegate = Mockito.mock(TronNetDelegate.class);
      Mockito.doReturn(peers).when(tronNetDelegate).getActivePeer();

      Field field = service.getClass().getDeclaredField("tronNetDelegate");
      field.setAccessible(true);
      field.set(service, tronNetDelegate);

      BlockCapsule blockCapsule = new BlockCapsule(chainBaseManager.getHeadBlockNum() + 1,
              chainBaseManager.getHeadBlockId(),
              0, getFromHexString("418A8D690BF36806C36A7DAE3AF796643C1AA9CC01"));
      BlockMessage msg = new BlockMessage(blockCapsule);
      service.broadcast(msg);
      Item item = new Item(blockCapsule.getBlockId(), Protocol.Inventory.InventoryType.BLOCK);
      Assert.assertEquals(1, peer.getAdvInvSpread().size());
      Assert.assertNotNull(peer.getAdvInvSpread().getIfPresent(item));
      peer.getChannel().close();
    } catch (Exception e) {
      logger.info("", e);
      assert false;
    }
  }

  private void assertContains(Set<ByteString> set, String string) {
    ByteString bytes = getFromHexString(string);
    Assert.assertTrue(set.contains(bytes));
  }

  private ByteString getFromHexString(String s) {
    return ByteString.copyFrom(Hex.decode(s));
  }

  private void testCheckHelloMessage() {
    String key = "0154435f065a57fec6af1e12eaa2fa600030639448d7809f4c65bdcf8baed7e5";
    ByteString address = getFromHexString("418A8D690BF36806C36A7DAE3AF796643C1AA9CC01");
    InetSocketAddress a1 = new InetSocketAddress("127.0.0.1", 10001);
    Node node = new Node(NetUtil.getNodeId(), a1.getAddress().getHostAddress(),
        null, a1.getPort());

    SignInterface cryptoEngine = SignUtils.fromPrivate(ByteArray.fromHexString(key),
            Args.getInstance().isECKeyCryptoEngine());
    HelloMessage helloMessage = new HelloMessage(node, System.currentTimeMillis(),
        ChainBaseManager.getChainBaseManager());
    ByteString sig = ByteString.copyFrom(cryptoEngine.Base64toBytes(cryptoEngine
        .signHash(Sha256Hash.of(CommonParameter.getInstance()
            .isECKeyCryptoEngine(), ByteArray.fromLong(helloMessage
            .getTimestamp())).getBytes())));
    helloMessage.setHelloMessage(helloMessage.getHelloMessage().toBuilder()
        .setAddress(address)
        .setSignature(sig)
        .build());

    Channel c1 = mock(Channel.class);
    Mockito.when(c1.getInetSocketAddress()).thenReturn(a1);
    Mockito.when(c1.getInetAddress()).thenReturn(a1.getAddress());
    Channel c2 = mock(Channel.class);
    Mockito.when(c2.getInetSocketAddress()).thenReturn(a1);
    Mockito.when(c2.getInetAddress()).thenReturn(a1.getAddress());

    Args.getInstance().fastForward = true;
    ApplicationContext ctx = (ApplicationContext) ReflectUtils.getFieldObject(p2pEventHandler,
        "ctx");
    PeerConnection peer1 = PeerManager.add(ctx, c1);
    assert peer1 != null;
    peer1.setAddress(address);
    PeerConnection peer2 = PeerManager.add(ctx, c2);
    assert peer2 != null;
    peer2.setAddress(address);

    ReflectUtils.setFieldValue(tronNetService, "p2pConfig", new P2pConfig());

    try {
      Field field = service.getClass().getDeclaredField("witnessScheduleStore");
      field.setAccessible(true);
      field.set(service, chainBaseManager.getWitnessScheduleStore());

      Field field2 = service.getClass().getDeclaredField("manager");
      field2.setAccessible(true);
      field2.set(service, dbManager);

      boolean res = service.checkHelloMessage(helloMessage, c1);
      Assert.assertTrue(res);

      HelloMessage shortSigMsg = new HelloMessage(node, System.currentTimeMillis(),
          ChainBaseManager.getChainBaseManager());
      shortSigMsg.setHelloMessage(shortSigMsg.getHelloMessage().toBuilder()
          .setAddress(address)
          .setSignature(ByteString.copyFrom(new byte[64]))
          .build());
      Assert.assertFalse(service.checkHelloMessage(shortSigMsg, c1));

      HelloMessage longSigMsg = new HelloMessage(node, System.currentTimeMillis(),
          ChainBaseManager.getChainBaseManager());
      longSigMsg.setHelloMessage(longSigMsg.getHelloMessage().toBuilder()
          .setAddress(address)
          .setSignature(ByteString.copyFrom(new byte[69]))
          .build());
      Assert.assertFalse(service.checkHelloMessage(longSigMsg, c1));

      HelloMessage emptySigMsg = new HelloMessage(node, System.currentTimeMillis(),
          ChainBaseManager.getChainBaseManager());
      emptySigMsg.setHelloMessage(emptySigMsg.getHelloMessage().toBuilder()
          .setAddress(address)
          .setSignature(ByteString.EMPTY)
          .build());
      Assert.assertFalse(service.checkHelloMessage(emptySigMsg, c1));
    } catch (Exception e) {
      logger.info("", e);
      assert false;
    }
  }

  @Test
  public void testPqHelloMessage() throws Exception {
    FNDSA512 pqKeypair = new FNDSA512();
    byte[] pqAddress = PQSchemeRegistry.computeAddress(
        PQScheme.FN_DSA_512, pqKeypair.getPublicKey());
    ByteString pqAddressBs = ByteString.copyFrom(pqAddress);

    // Snapshot prior active-witness list (if any) so other tests are not perturbed.
    List<ByteString> previousActive;
    try {
      previousActive = new ArrayList<>(
          chainBaseManager.getWitnessScheduleStore().getActiveWitnesses());
    } catch (Exception ignored) {
      previousActive = null;
    }
    List<ByteString> active = previousActive == null
        ? new ArrayList<>() : new ArrayList<>(previousActive);
    if (!active.contains(pqAddressBs)) {
      active.add(pqAddressBs);
    }
    chainBaseManager.getWitnessScheduleStore().saveActiveWitnesses(active);

    // Activate FN-DSA-512 on chain so verifyPqAuthSig accepts the scheme.
    long previousAllowFnDsa = chainBaseManager.getDynamicPropertiesStore().getAllowFnDsa512();
    chainBaseManager.getDynamicPropertiesStore().saveAllowFnDsa512(1L);

    Args.getInstance().fastForward = true;

    InetSocketAddress addr = new InetSocketAddress("127.0.0.1", 10001);
    Node node = new Node(NetUtil.getNodeId(), addr.getAddress().getHostAddress(),
        null, addr.getPort());
    HelloMessage helloMessage = new HelloMessage(node, System.currentTimeMillis(),
        ChainBaseManager.getChainBaseManager());
    byte[] digest = Sha256Hash.of(CommonParameter.getInstance().isECKeyCryptoEngine(),
        ByteArray.fromLong(helloMessage.getTimestamp())).getBytes();
    byte[] pqSig = FNDSA512.sign(pqKeypair.getPrivateKey(), digest);
    PQAuthSig pqAuthSig = PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(pqKeypair.getPublicKey()))
        .setSignature(ByteString.copyFrom(pqSig))
        .build();

    Protocol.HelloMessage base = helloMessage.getHelloMessage().toBuilder()
        .setAddress(pqAddressBs)
        .clearSignature()
        .setPqAuthSig(pqAuthSig)
        .build();
    helloMessage.setHelloMessage(base);

    Channel channel = mock(Channel.class);
    Mockito.when(channel.getInetSocketAddress()).thenReturn(addr);
    Mockito.when(channel.getInetAddress()).thenReturn(addr.getAddress());
    PeerManager.add((ApplicationContext) ReflectUtils.getFieldObject(p2pEventHandler, "ctx"),
        channel).setAddress(pqAddressBs);

    ReflectUtils.setFieldValue(tronNetService, "p2pConfig", new P2pConfig());
    Field scheduleField = service.getClass().getDeclaredField("witnessScheduleStore");
    scheduleField.setAccessible(true);
    scheduleField.set(service, chainBaseManager.getWitnessScheduleStore());
    Field managerField = service.getClass().getDeclaredField("manager");
    managerField.setAccessible(true);
    managerField.set(service, dbManager);

    try {
      // Happy path: valid PQ-only signature.
      Assert.assertTrue(service.checkHelloMessage(helloMessage, channel));

      // Both legacy signature and pq_auth_sig set → mutex rejects.
      helloMessage.setHelloMessage(base.toBuilder()
          .setSignature(ByteString.copyFrom(new byte[]{0x01}))
          .build());
      Assert.assertFalse(service.checkHelloMessage(helloMessage, channel));

      // Neither legacy signature nor pq_auth_sig set → mutex rejects.
      helloMessage.setHelloMessage(base.toBuilder().clearSignature().clearPqAuthSig().build());
      Assert.assertFalse(service.checkHelloMessage(helloMessage, channel));

      // PQ public key length mismatch → reject.
      helloMessage.setHelloMessage(base.toBuilder()
          .setPqAuthSig(pqAuthSig.toBuilder()
              .setPublicKey(ByteString.copyFrom(new byte[]{0x00})))
          .build());
      Assert.assertFalse(service.checkHelloMessage(helloMessage, channel));

      // Derived PQ address does not match the claimed witness address → reject.
      FNDSA512 strayKeypair = new FNDSA512();
      byte[] strayDigest = Sha256Hash.of(CommonParameter.getInstance().isECKeyCryptoEngine(),
          ByteArray.fromLong(helloMessage.getTimestamp())).getBytes();
      byte[] straySig = FNDSA512.sign(strayKeypair.getPrivateKey(), strayDigest);
      helloMessage.setHelloMessage(base.toBuilder()
          .setPqAuthSig(PQAuthSig.newBuilder()
              .setScheme(PQScheme.FN_DSA_512)
              .setPublicKey(ByteString.copyFrom(strayKeypair.getPublicKey()))
              .setSignature(ByteString.copyFrom(straySig)))
          .build());
      Assert.assertFalse(service.checkHelloMessage(helloMessage, channel));

      // Scheme not activated on chain → reject.
      helloMessage.setHelloMessage(base);
      chainBaseManager.getDynamicPropertiesStore().saveAllowFnDsa512(0L);
      Assert.assertFalse(service.checkHelloMessage(helloMessage, channel));
    } finally {
      chainBaseManager.getDynamicPropertiesStore().saveAllowFnDsa512(previousAllowFnDsa);
      if (previousActive != null) {
        chainBaseManager.getWitnessScheduleStore().saveActiveWitnesses(previousActive);
      }
    }
  }

  @Test
  public void testNullWitnessAddress() {
    try {
      Class<?> clazz = service.getClass();

      Field ecdsaKeySizeField = clazz.getDeclaredField("ecdsaKeySize");
      ecdsaKeySizeField.setAccessible(true);
      ecdsaKeySizeField.set(service, 0);
      Field pqKeySizeField = clazz.getDeclaredField("pqKeySize");
      pqKeySizeField.setAccessible(true);
      pqKeySizeField.set(service, 0);

      Field ecdsaField = clazz.getDeclaredField("ecdsaWitnessAddress");
      ecdsaField.setAccessible(true);
      Field pqField = clazz.getDeclaredField("pqWitnessAddress");
      pqField.setAccessible(true);
      ecdsaField.set(service, null);
      pqField.set(service, null);

      Method isActiveWitnessMethod = clazz.getDeclaredMethod("isActiveWitness");
      isActiveWitnessMethod.setAccessible(true);

      Boolean result = (Boolean) isActiveWitnessMethod.invoke(service);
      Assert.assertNotEquals(Boolean.TRUE, result);

      ecdsaField.set(service, ByteString.copyFrom(new byte[21]));
      result = (Boolean) isActiveWitnessMethod.invoke(service);
      Assert.assertNotEquals(Boolean.TRUE, result);
    } catch (NoSuchMethodException | NoSuchFieldException
             | IllegalAccessException | InvocationTargetException e) {
      Assert.fail("Reflection invocation failed: " + e.getMessage());
    }
  }
}
