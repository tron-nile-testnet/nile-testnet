package org.tron.core.services.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.stubbing.Answer;
import org.springframework.context.ApplicationContext;
import org.springframework.test.util.ReflectionTestUtils;
import org.tron.api.GrpcAPI;
import org.tron.common.TestConstants;
import org.tron.core.ChainBaseManager;
import org.tron.core.Wallet;
import org.tron.core.config.args.Args;
import org.tron.core.db.Manager;
import org.tron.core.db2.core.Chainbase.Cursor;
import org.tron.core.services.filter.HttpApiAccessFilter;
import org.tron.core.services.filter.LiteFnQueryHttpFilter;
import org.tron.core.services.filter.SolidityCursorFilter;
import org.tron.core.services.http.HttpApi.Surface;
import org.tron.core.services.http.servlets.RateLimiterServlet;
import org.tron.core.services.http.servlets.Util;
import org.tron.core.services.http.solidity.SolidityNodeHttpApiService;
import org.tron.core.services.interfaceOnSolidity.HttpApiOnSolidityService;
import org.tron.core.services.ratelimiter.RateLimiterContainer;
import org.tron.core.services.ratelimiter.RuntimeData;
import org.tron.core.services.ratelimiter.adapter.IRateLimiter;
import org.tron.protos.contract.ShieldContract.IncrementalMerkleVoucherInfo;

public class NileShieldedHttpApiTest {

  private static final String[] ENDPOINTS = {"getmerkletreevoucherinfo", "scanandmarknotebyivk",
      "scannotebyivk", "scannotebyovk", "isspend"};

  private final ThreadLocal<Cursor> cursor = ThreadLocal.withInitial(() -> Cursor.HEAD);
  private final Map<String, IRateLimiter> limiters = new HashMap<>();
  private Wallet wallet;
  private Manager manager;
  private Cursor expectedCursor;
  private Server server;
  private LocalConnector connector;

  @Before
  public void setUp() throws Exception {
    Args.setParam(new String[0], TestConstants.TEST_CONF);
    wallet = mock(Wallet.class);
    manager = mock(Manager.class);
    doAnswer(invocation -> {
      cursor.set(invocation.getArgument(0));
      return null;
    }).when(manager).setCursor(any(Cursor.class));
    doAnswer(invocation -> {
      cursor.remove();
      return null;
    }).when(manager).resetCursor();
    when(wallet.getMerkleTreeVoucherInfo(any())).thenAnswer(
        onExpectedCursor(IncrementalMerkleVoucherInfo.getDefaultInstance()));
    when(wallet.scanAndMarkNoteByIvk(anyLong(), anyLong(), any(), any(), any()))
        .thenAnswer(onExpectedCursor(GrpcAPI.DecryptNotesMarked.getDefaultInstance()));
    when(wallet.scanNoteByIvk(anyLong(), anyLong(), any()))
        .thenAnswer(onExpectedCursor(GrpcAPI.DecryptNotes.getDefaultInstance()));
    when(wallet.scanNoteByOvk(anyLong(), anyLong(), any()))
        .thenAnswer(onExpectedCursor(GrpcAPI.DecryptNotes.getDefaultInstance()));
    when(wallet.isSpend(any())).thenAnswer(
        onExpectedCursor(GrpcAPI.SpendResult.newBuilder().setResult(true).build()));
  }

  @After
  public void tearDown() throws Exception {
    try {
      if (server != null) {
        server.stop();
      }
    } finally {
      Args.clearParam();
    }
  }

  @Test(timeout = 60_000)
  public void solidityRequestsReachWalletWithSolidityCursor() throws Exception {
    start(Surface.SOLIDITY);
    assertAllEndpointsReachWallet();
    verify(manager, times(ENDPOINTS.length)).setCursor(Cursor.SOLIDITY);
    verify(manager, times(ENDPOINTS.length)).resetCursor();
  }

  @Test(timeout = 60_000)
  public void standaloneSolidityRequestsReachWallet() throws Exception {
    start(Surface.SOLIDITY_NODE);
    assertAllEndpointsReachWallet();
    verify(manager, never()).setCursor(any(Cursor.class));
  }

  @Test(timeout = 60_000)
  public void configuredApiDisableStillBlocksRestoredRoute() throws Exception {
    Args.getInstance().setDisabledApiList(Collections.singletonList("scannotebyivk"));
    start(Surface.SOLIDITY);
    assertTrue(post("scannotebyivk").startsWith("HTTP/1.1 404 "));
    verifyNoInteractions(wallet);
  }

  @Test(timeout = 60_000)
  public void restoredRouteKeepsSolidityRateLimit() throws Exception {
    start(Surface.SOLIDITY);
    when(limiters.get("ScanNoteByIvkServlet").acquirePermit(any(RuntimeData.class)))
        .thenReturn(false);
    assertTrue(post("scannotebyivk").contains(Util.RATE_LIMITER_ERROR_MSG));
    verifyNoInteractions(wallet);
    verify(manager).resetCursor();
  }

  private <T> Answer<T> onExpectedCursor(T response) {
    return invocation -> {
      assertEquals(expectedCursor, cursor.get());
      return response;
    };
  }

  private void assertAllEndpointsReachWallet() throws Exception {
    for (String endpoint : ENDPOINTS) {
      String response = post(endpoint);
      assertTrue(endpoint + ": " + response, response.startsWith("HTTP/1.1 200 "));
      assertFalse(endpoint + ": " + response, response.contains("\"Error\""));
    }
    verify(wallet).getMerkleTreeVoucherInfo(any());
    verify(wallet).scanAndMarkNoteByIvk(anyLong(), anyLong(), any(), any(), any());
    verify(wallet).scanNoteByIvk(anyLong(), anyLong(), any());
    verify(wallet).scanNoteByOvk(anyLong(), anyLong(), any());
    verify(wallet).isSpend(any());
  }

  private void start(Surface surface) throws Exception {
    expectedCursor = surface == Surface.SOLIDITY ? Cursor.SOLIDITY : Cursor.HEAD;
    RateLimiterContainer container = new RateLimiterContainer();
    ApplicationContext beans = mock(ApplicationContext.class);
    when(beans.getBean(any(Class.class))).thenAnswer(invocation -> {
      Class<?> type = invocation.getArgument(0);
      if (type.getSimpleName().matches(
          "GetMerkleTreeVoucherInfoServlet|ScanAndMarkNoteByIvkServlet|ScanNoteByIvkServlet"
              + "|ScanNoteByOvkServlet|IsSpendServlet")) {
        RateLimiterServlet servlet =
            (RateLimiterServlet) type.getDeclaredConstructor().newInstance();
        ReflectionTestUtils.setField(servlet, "wallet", wallet);
        ReflectionTestUtils.setField(servlet, "container", container);
        IRateLimiter limiter = mock(IRateLimiter.class);
        when(limiter.acquirePermit(any(RuntimeData.class))).thenReturn(true);
        container.add("http_", RateLimiterServlet.limiterName(type, surface), limiter);
        limiters.put(type.getSimpleName(), limiter);
        return servlet;
      }
      return mock(type.asSubclass(HttpServlet.class));
    });
    Class<?> serviceType = surface == Surface.SOLIDITY
        ? HttpApiOnSolidityService.class : SolidityNodeHttpApiService.class;
    Object service = mock(serviceType, withSettings().defaultAnswer(Answers.CALLS_REAL_METHODS));
    ReflectionTestUtils.setField(service, "appContext", beans);
    ReflectionTestUtils.setField(service, "httpApiAccessFilter", new HttpApiAccessFilter());
    if (surface == Surface.SOLIDITY) {
      LiteFnQueryHttpFilter liteFilter = new LiteFnQueryHttpFilter();
      ReflectionTestUtils.setField(liteFilter, "chainBaseManager", mock(ChainBaseManager.class));
      ReflectionTestUtils.setField(service, "liteFnQueryHttpFilter", liteFilter);
      ReflectionTestUtils.setField(service, "solidityCursorFilter",
          new SolidityCursorFilter(manager));
    }
    ServletContextHandler context = new ServletContextHandler();
    context.setContextPath("/");
    for (String methodName : new String[]{"addServletsFromRegistry", "addFilter"}) {
      Method method = serviceType.getDeclaredMethod(methodName, ServletContextHandler.class);
      method.setAccessible(true);
      method.invoke(service, context);
    }
    server = new Server();
    connector = new LocalConnector(server);
    server.addConnector(connector);
    server.setHandler(context);
    server.start();
  }

  private String post(String endpoint) throws Exception {
    return connector.getResponse("POST /walletsolidity/" + endpoint + " HTTP/1.1\r\n"
        + "Host: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n"
        + "Content-Length: 2\r\n\r\n{}");
  }
}
