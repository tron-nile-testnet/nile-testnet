package org.tron.core.net.services;

import static org.mockito.Mockito.mock;
import static org.tron.core.net.message.handshake.HelloMessage.getEndpointFromNode;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.UnknownFieldSet;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.Random;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.tron.common.TestConstants;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.ReflectUtils;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.exception.P2pException;
import org.tron.core.net.P2pEventHandlerImpl;
import org.tron.core.net.TronNetService;
import org.tron.core.net.message.handshake.HelloMessage;
import org.tron.core.net.peer.PeerConnection;
import org.tron.core.net.peer.PeerManager;
import org.tron.core.net.service.handshake.HandshakeService;
import org.tron.p2p.P2pConfig;
import org.tron.p2p.base.Parameter;
import org.tron.p2p.connection.Channel;
import org.tron.p2p.discover.Node;
import org.tron.p2p.utils.NetUtil;
import org.tron.program.Version;
import org.tron.protos.Discover.Endpoint;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.HelloMessage.Builder;

public class HandShakeServiceTest {

  private static TronApplicationContext context;
  private PeerConnection peer;
  private static P2pEventHandlerImpl p2pEventHandler;
  private static ApplicationContext ctx;
  @ClassRule
  public static final TemporaryFolder temporaryFolder = new TemporaryFolder();

  @BeforeClass
  public static void init() throws Exception {
    Args.setParam(new String[] {"--output-directory",
        temporaryFolder.newFolder().toString(), "--debug"}, TestConstants.TEST_CONF);
    context = new TronApplicationContext(DefaultConfig.class);
    p2pEventHandler = context.getBean(P2pEventHandlerImpl.class);
    ctx = (ApplicationContext) ReflectUtils.getFieldObject(p2pEventHandler, "ctx");

    TronNetService tronNetService = context.getBean(TronNetService.class);
    Parameter.p2pConfig = new P2pConfig();
    ReflectUtils.setFieldValue(tronNetService, "p2pConfig", Parameter.p2pConfig);
  }

  @AfterClass
  public static void destroy() {
    Args.clearParam();
    context.destroy();
  }

  @After
  public void clearPeers() {
    for (PeerConnection p : PeerManager.getPeers()) {
      PeerManager.remove(p.getChannel());
    }
  }

  @Test
  public void testOkHelloMessage()
      throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    InetSocketAddress a1 = new InetSocketAddress("127.0.0.1", 10001);
    Channel c1 = mock(Channel.class);
    Mockito.when(c1.getInetSocketAddress()).thenReturn(a1);
    Mockito.when(c1.getInetAddress()).thenReturn(a1.getAddress());
    PeerManager.add(ctx, c1);
    peer = PeerManager.getPeers().get(0);

    Method method = p2pEventHandler.getClass()
        .getDeclaredMethod("processMessage", PeerConnection.class, byte[].class);
    method.setAccessible(true);

    //ok
    Node node = new Node(NetUtil.getNodeId(), a1.getAddress().getHostAddress(), null, a1.getPort());
    HelloMessage helloMessage = new HelloMessage(node, System.currentTimeMillis(),
        ChainBaseManager.getChainBaseManager());
    Assert.assertNotNull(helloMessage.toString());

    Assert.assertEquals(Version.getVersion(),
        new String(helloMessage.getHelloMessage().getCodeVersion().toByteArray()));
    method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());

    //dup hello message
    peer.setHelloMessageReceive(helloMessage);
    method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());

    //dup peer
    peer.setHelloMessageReceive(null);
    Mockito.when(c1.isDisconnect()).thenReturn(true);
    method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());
  }

  @Test
  public void testInvalidHelloMessage() {
    InetSocketAddress a1 = new InetSocketAddress("127.0.0.1", 10001);
    Node node = new Node(NetUtil.getNodeId(), a1.getAddress().getHostAddress(), null, a1.getPort());
    Protocol.HelloMessage.Builder builder =
        getHelloMessageBuilder(node, System.currentTimeMillis(),
            ChainBaseManager.getChainBaseManager());
    //block hash is empty
    try {
      BlockCapsule.BlockId hid = ChainBaseManager.getChainBaseManager().getHeadBlockId();
      Protocol.HelloMessage.BlockId okBlockId = Protocol.HelloMessage.BlockId.newBuilder()
          .setHash(ByteString.copyFrom(new byte[32]))
          .setNumber(hid.getNum())
          .build();
      Protocol.HelloMessage.BlockId invalidBlockId = Protocol.HelloMessage.BlockId.newBuilder()
          .setHash(ByteString.copyFrom(new byte[31]))
          .setNumber(hid.getNum())
          .build();
      builder.setHeadBlockId(invalidBlockId);
      HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
      Assert.assertFalse(helloMessage.valid());

      builder.setHeadBlockId(okBlockId);
      builder.setGenesisBlockId(invalidBlockId);
      HelloMessage helloMessage2 = new HelloMessage(builder.build().toByteArray());
      Assert.assertFalse(helloMessage2.valid());

      builder.setGenesisBlockId(okBlockId);
      builder.setSolidBlockId(invalidBlockId);
      HelloMessage helloMessage3 = new HelloMessage(builder.build().toByteArray());
      Assert.assertFalse(helloMessage3.valid());
    } catch (Exception e) {
      Assert.fail();
    }
  }

  @Test
  public void testInvalidHelloMessage2() throws Exception {
    Protocol.HelloMessage.Builder builder = getTestHelloMessageBuilder();
    Assert.assertTrue(new HelloMessage(builder.build().toByteArray()).valid());

    builder.setAddress(ByteString.copyFrom(new byte[201]));
    HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
    Assert.assertFalse(helloMessage.valid());

    builder.setAddress(ByteString.copyFrom(new byte[200]));
    helloMessage = new HelloMessage(builder.build().toByteArray());
    Assert.assertTrue(helloMessage.valid());

    builder.setSignature(ByteString.copyFrom(new byte[201]));
    helloMessage = new HelloMessage(builder.build().toByteArray());
    Assert.assertFalse(helloMessage.valid());

    builder.setSignature(ByteString.copyFrom(new byte[200]));
    helloMessage = new HelloMessage(builder.build().toByteArray());
    Assert.assertTrue(helloMessage.valid());

    builder.setCodeVersion(ByteString.copyFrom(new byte[201]));
    helloMessage = new HelloMessage(builder.build().toByteArray());
    Assert.assertFalse(helloMessage.valid());

    builder.setCodeVersion(ByteString.copyFrom(new byte[200]));
    helloMessage = new HelloMessage(builder.build().toByteArray());
    Assert.assertTrue(helloMessage.valid());
  }


  // A pq_auth_sig whose public_key/signature are within bounds but which
  // carries a nested unknown field must be rejected: PQAuthSig retains and
  // re-serializes unknown fields, so otherwise it could smuggle extra bytes
  // past the per-field length checks.
  @Test
  public void testPqAuthSigNestedUnknownFieldRejected() throws Exception {
    int pkLen = PQSchemeRegistry.getPublicKeyLength(Protocol.PQScheme.FN_DSA_512);
    int sigLen = PQSchemeRegistry.getSignatureLength(Protocol.PQScheme.FN_DSA_512);

    // control: a well-formed pq_auth_sig (real per-scheme lengths) passes valid().
    Protocol.PQAuthSig okPq = Protocol.PQAuthSig.newBuilder()
        .setScheme(Protocol.PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(new byte[pkLen]))
        .setSignature(ByteString.copyFrom(new byte[sigLen]))
        .build();
    HelloMessage ok = new HelloMessage(
        getTestHelloMessageBuilder().setPqAuthSig(okPq).build().toByteArray());
    Assert.assertTrue(ok.valid());

    // same, but with a nested unknown field (#99) inside PQAuthSig -> rejected.
    UnknownFieldSet nestedUnknown = UnknownFieldSet.newBuilder()
        .addField(99, UnknownFieldSet.Field.newBuilder()
            .addLengthDelimited(ByteString.copyFrom(new byte[16])).build())
        .build();
    Protocol.PQAuthSig pqWithUnknown = Protocol.PQAuthSig.newBuilder()
        .setScheme(Protocol.PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(new byte[pkLen]))
        .setSignature(ByteString.copyFrom(new byte[sigLen]))
        .setUnknownFields(nestedUnknown)
        .build();
    HelloMessage bad = new HelloMessage(
        getTestHelloMessageBuilder().setPqAuthSig(pqWithUnknown).build().toByteArray());
    Assert.assertFalse(bad.valid());
  }

  // The raw inbound size is bounded before parsing. Covers the three ways the
  // parsed object stays small while the wire payload bloats toward the 5MB
  // frame limit: repeated singular pq_auth_sig (parser merges, last value
  // wins), a top-level unknown field, and an unbounded bytes sub-field of
  // `from` (Endpoint).
  @Test
  public void testHelloMessageRawSizeBound() throws Exception {
    int over = HelloMessage.MAX_HELLO_MESSAGE_SIZE + 1024;

    // 1) repeated top-level pq_auth_sig: first huge, then legal. The merged
    // object is legal (public_key overwritten), but raw bytes exceed the cap.
    Protocol.PQAuthSig huge = Protocol.PQAuthSig.newBuilder()
        .setPublicKey(ByteString.copyFrom(new byte[over]))
        .build();
    Protocol.PQAuthSig legal = Protocol.PQAuthSig.newBuilder()
        .setScheme(Protocol.PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(
            new byte[PQSchemeRegistry.getPublicKeyLength(Protocol.PQScheme.FN_DSA_512)]))
        .setSignature(ByteString.copyFrom(
            new byte[PQSchemeRegistry.getSignatureLength(Protocol.PQScheme.FN_DSA_512)]))
        .build();
    byte[] base = getTestHelloMessageBuilder().build().toByteArray();
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(base);
    CodedOutputStream cos = CodedOutputStream.newInstance(bos);
    cos.writeMessage(12, huge);   // pq_auth_sig = field 12
    cos.writeMessage(12, legal);
    cos.flush();
    assertRejectedBySize(bos.toByteArray());

    // 2) oversized top-level unknown field.
    UnknownFieldSet topUnknown = UnknownFieldSet.newBuilder()
        .addField(2000, UnknownFieldSet.Field.newBuilder()
            .addLengthDelimited(ByteString.copyFrom(new byte[over])).build())
        .build();
    assertRejectedBySize(
        getTestHelloMessageBuilder().setUnknownFields(topUnknown).build().toByteArray());

    // 3) oversized bytes sub-field of `from` (a known field valid() never bounds).
    Endpoint fatFrom = Endpoint.newBuilder()
        .setNodeId(ByteString.copyFrom(new byte[over]))
        .setPort(10001)
        .build();
    assertRejectedBySize(
        getTestHelloMessageBuilder().setFrom(fatFrom).build().toByteArray());
  }

  private static void assertRejectedBySize(byte[] wire) {
    Assert.assertTrue("test fixture should exceed the cap",
        wire.length > HelloMessage.MAX_HELLO_MESSAGE_SIZE);
    try {
      new HelloMessage(wire);
      Assert.fail("oversized hello should be rejected before parsing");
    } catch (P2pException e) {
      Assert.assertEquals(P2pException.TypeEnum.BAD_MESSAGE, e.getType());
    } catch (Exception e) {
      Assert.fail("expected P2pException, got " + e);
    }
  }

  @Test
  public void testRelayHelloMessage() throws NoSuchMethodException {
    InetSocketAddress a1 = new InetSocketAddress("127.0.0.1", 10001);
    Channel c1 = mock(Channel.class);
    Mockito.when(c1.getInetSocketAddress()).thenReturn(a1);
    Mockito.when(c1.getInetAddress()).thenReturn(a1.getAddress());
    PeerManager.add(ctx, c1);
    peer = PeerManager.getPeers().get(0);

    Method method = p2pEventHandler.getClass()
        .getDeclaredMethod("processMessage", PeerConnection.class, byte[].class);
    method.setAccessible(true);

    //address is empty
    Args.getInstance().fastForward = true;
    clearPeers();
    Node node2 = new Node(NetUtil.getNodeId(), a1.getAddress().getHostAddress(), null, 10002);
    Protocol.HelloMessage.Builder builder =
        getHelloMessageBuilder(node2, System.currentTimeMillis(),
            ChainBaseManager.getChainBaseManager());

    try {
      HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
      method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());
    } catch (Exception e) {
      Assert.fail();
    }
    Args.getInstance().fastForward = false;
  }

  @Test
  public void testLowAndGenesisBlockNum() throws NoSuchMethodException {
    InetSocketAddress a1 = new InetSocketAddress("127.0.0.1", 10001);
    Channel c1 = mock(Channel.class);
    Mockito.when(c1.getInetSocketAddress()).thenReturn(a1);
    Mockito.when(c1.getInetAddress()).thenReturn(a1.getAddress());
    PeerManager.add(ctx, c1);
    peer = PeerManager.getPeers().get(0);

    Method method = p2pEventHandler.getClass()
        .getDeclaredMethod("processMessage", PeerConnection.class, byte[].class);
    method.setAccessible(true);

    Node node2 = new Node(NetUtil.getNodeId(), a1.getAddress().getHostAddress(), null, 10002);

    //peer's lowestBlockNum > my headBlockNum => peer is light, LIGHT_NODE_SYNC_FAIL
    Protocol.HelloMessage.Builder builder =
        getHelloMessageBuilder(node2, System.currentTimeMillis(),
            ChainBaseManager.getChainBaseManager());
    builder.setLowestBlockNum(ChainBaseManager.getChainBaseManager().getLowestBlockNum() + 1);
    try {
      HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
      method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());
    } catch (Exception e) {
      Assert.fail();
    }

    //genesisBlock is not equal => INCOMPATIBLE_CHAIN
    builder = getHelloMessageBuilder(node2, System.currentTimeMillis(),
        ChainBaseManager.getChainBaseManager());
    BlockCapsule.BlockId gid = ChainBaseManager.getChainBaseManager().getGenesisBlockId();
    Protocol.HelloMessage.BlockId gBlockId = Protocol.HelloMessage.BlockId.newBuilder()
        .setHash(gid.getByteString())
        .setNumber(gid.getNum() + 1)
        .build();
    builder.setGenesisBlockId(gBlockId);
    try {
      HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
      method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());
    } catch (Exception e) {
      Assert.fail();
    }

    // peer's solidityBlock <= my solidityBlock, but not contained
    // and my lowestBlockNum <= peer's solidityBlock  => FORKED
    builder = getHelloMessageBuilder(node2, System.currentTimeMillis(),
        ChainBaseManager.getChainBaseManager());

    BlockCapsule.BlockId sid = ChainBaseManager.getChainBaseManager().getSolidBlockId();

    Random gen = new Random();
    byte[] randomHash = new byte[Sha256Hash.LENGTH];
    gen.nextBytes(randomHash);

    Protocol.HelloMessage.BlockId sBlockId = Protocol.HelloMessage.BlockId.newBuilder()
        .setHash(ByteString.copyFrom(randomHash))
        .setNumber(sid.getNum())
        .build();
    builder.setSolidBlockId(sBlockId);
    try {
      HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
      method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());
    } catch (Exception e) {
      Assert.fail();
    }

    // peer's solidityBlock <= my solidityBlock, but not contained
    // and my lowestBlockNum > peer's solidityBlock  => i am light, LIGHT_NODE_SYNC_FAIL
    ChainBaseManager.getChainBaseManager().setLowestBlockNum(2);
    try {
      HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
      method.invoke(p2pEventHandler, peer, helloMessage.getSendBytes());
    } catch (Exception e) {
      Assert.fail();
    }
  }

  @Test
  public void testProcessHelloMessage() {
    InetSocketAddress a1 = new InetSocketAddress("127.0.0.1", 10001);
    Channel c1 = mock(Channel.class);
    Mockito.when(c1.getInetSocketAddress()).thenReturn(a1);
    Mockito.when(c1.getInetAddress()).thenReturn(a1.getAddress());
    PeerManager.add(ctx, c1);
    PeerConnection p = PeerManager.getPeers().get(0);

    try {
      Node node = new Node(NetUtil.getNodeId(), a1.getAddress().getHostAddress(),
          null, a1.getPort());
      Protocol.HelloMessage.Builder builder =
          getHelloMessageBuilder(node, System.currentTimeMillis(),
              ChainBaseManager.getChainBaseManager());
      BlockCapsule.BlockId hid = ChainBaseManager.getChainBaseManager().getHeadBlockId();
      Protocol.HelloMessage.BlockId invalidBlockId = Protocol.HelloMessage.BlockId.newBuilder()
          .setHash(ByteString.copyFrom(new byte[31]))
          .setNumber(hid.getNum())
          .build();
      builder.setHeadBlockId(invalidBlockId);

      HelloMessage helloMessage = new HelloMessage(builder.build().toByteArray());
      HandshakeService handshakeService = new HandshakeService();
      handshakeService.processHelloMessage(p, helloMessage);
    } catch (Exception e) {
      Assert.fail();
    }
  }

  private Protocol.HelloMessage.Builder getHelloMessageBuilder(Node from, long timestamp,
      ChainBaseManager chainBaseManager) {
    Endpoint fromEndpoint = getEndpointFromNode(from);

    BlockCapsule.BlockId gid = chainBaseManager.getGenesisBlockId();
    Protocol.HelloMessage.BlockId gBlockId = Protocol.HelloMessage.BlockId.newBuilder()
        .setHash(gid.getByteString())
        .setNumber(gid.getNum())
        .build();

    BlockCapsule.BlockId sid = chainBaseManager.getSolidBlockId();
    Protocol.HelloMessage.BlockId sBlockId = Protocol.HelloMessage.BlockId.newBuilder()
        .setHash(sid.getByteString())
        .setNumber(sid.getNum())
        .build();

    BlockCapsule.BlockId hid = chainBaseManager.getHeadBlockId();
    Protocol.HelloMessage.BlockId hBlockId = Protocol.HelloMessage.BlockId.newBuilder()
        .setHash(hid.getByteString())
        .setNumber(hid.getNum())
        .build();
    Builder builder = Protocol.HelloMessage.newBuilder();
    builder.setFrom(fromEndpoint);
    builder.setVersion(Args.getInstance().getNodeP2pVersion());
    builder.setTimestamp(timestamp);
    builder.setGenesisBlockId(gBlockId);
    builder.setSolidBlockId(sBlockId);
    builder.setHeadBlockId(hBlockId);
    builder.setNodeType(chainBaseManager.getNodeType().getType());
    builder.setLowestBlockNum(chainBaseManager.isLiteNode()
        ? chainBaseManager.getLowestBlockNum() : 0);

    return builder;
  }

  private Protocol.HelloMessage.Builder getTestHelloMessageBuilder() {
    InetSocketAddress a1 = new InetSocketAddress("127.0.0.1", 10001);
    Node node = new Node(NetUtil.getNodeId(), a1.getAddress().getHostAddress(), null, a1.getPort());
    Protocol.HelloMessage.Builder builder =
        getHelloMessageBuilder(node, System.currentTimeMillis(),
            ChainBaseManager.getChainBaseManager());
    return builder;
  }
}
