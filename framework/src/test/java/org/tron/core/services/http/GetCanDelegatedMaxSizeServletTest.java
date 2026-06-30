package org.tron.core.services.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.tron.protos.Protocol.PQScheme;

public class GetCanDelegatedMaxSizeServletTest {

  @Test
  public void parsePqSchemeBlankFallsBackToUnknown() {
    // null / empty / whitespace means "no PQ hint": keep the ECDSA-sized estimate.
    assertEquals(PQScheme.UNKNOWN_PQ_SCHEME,
        GetCanDelegatedMaxSizeServlet.parsePqScheme(null));
    assertEquals(PQScheme.UNKNOWN_PQ_SCHEME,
        GetCanDelegatedMaxSizeServlet.parsePqScheme(""));
    assertEquals(PQScheme.UNKNOWN_PQ_SCHEME,
        GetCanDelegatedMaxSizeServlet.parsePqScheme("   "));
  }

  @Test
  public void parsePqSchemeByNumber() {
    assertEquals(PQScheme.UNKNOWN_PQ_SCHEME,
        GetCanDelegatedMaxSizeServlet.parsePqScheme("0"));
    assertEquals(PQScheme.FN_DSA_512,
        GetCanDelegatedMaxSizeServlet.parsePqScheme("1"));
    assertEquals(PQScheme.ML_DSA_44,
        GetCanDelegatedMaxSizeServlet.parsePqScheme("2"));
    // surrounding whitespace is tolerated.
    assertEquals(PQScheme.ML_DSA_44,
        GetCanDelegatedMaxSizeServlet.parsePqScheme(" 2 "));
  }

  @Test
  public void parsePqSchemeByName() {
    assertEquals(PQScheme.UNKNOWN_PQ_SCHEME,
        GetCanDelegatedMaxSizeServlet.parsePqScheme("UNKNOWN_PQ_SCHEME"));
    assertEquals(PQScheme.FN_DSA_512,
        GetCanDelegatedMaxSizeServlet.parsePqScheme("FN_DSA_512"));
    assertEquals(PQScheme.ML_DSA_44,
        GetCanDelegatedMaxSizeServlet.parsePqScheme("ML_DSA_44"));
  }

  @Test
  public void parsePqSchemeUnknownNumberThrows() {
    // 99 is not a registered enum number; reject instead of silently ignoring.
    assertThrows(IllegalArgumentException.class,
        () -> GetCanDelegatedMaxSizeServlet.parsePqScheme("99"));
  }

  @Test
  public void parsePqSchemeUnknownNameThrows() {
    assertThrows(IllegalArgumentException.class,
        () -> GetCanDelegatedMaxSizeServlet.parsePqScheme("NOT_A_SCHEME"));
  }
}
