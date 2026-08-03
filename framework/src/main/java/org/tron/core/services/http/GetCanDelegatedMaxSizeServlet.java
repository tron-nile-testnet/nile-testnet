package org.tron.core.services.http;

import com.google.protobuf.ByteString;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.api.GrpcAPI;
import org.tron.common.utils.ByteArray;
import org.tron.core.Wallet;
import org.tron.protos.Protocol.PQScheme;

@Component
@Slf4j(topic = "API")
public class GetCanDelegatedMaxSizeServlet extends RateLimiterServlet {

  @Autowired
  private Wallet wallet;

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    try {
      boolean visible = Util.getVisible(request);
      int type = 0;
      String typeStr = request.getParameter("type");
      if (typeStr != null) {
        type = Integer.parseInt(typeStr);
      }
      String ownerAddress = request.getParameter("owner_address");
      if (visible) {
        ownerAddress = Util.getHexAddress(ownerAddress);
      }
      PQScheme pqScheme = parsePqScheme(request.getParameter("pq_scheme"));
      fillResponse(visible,
              ByteString.copyFrom(ByteArray.fromHexString(ownerAddress)),
              type, pqScheme, response);
    } catch (Exception e) {
      Util.processError(e, response);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    try {
      PostParams params = PostParams.getPostParams(request);
      GrpcAPI.CanDelegatedMaxSizeRequestMessage.Builder build =
              GrpcAPI.CanDelegatedMaxSizeRequestMessage.newBuilder();
      JsonFormat.merge(params.getParams(), build, params.isVisible());
      fillResponse(params.isVisible(),
              build.getOwnerAddress(),
              build.getType(), build.getPqScheme(), response);
    } catch (Exception e) {
      Util.processError(e, response);
    }
  }

  // Accepts either the enum name (e.g. "ML_DSA_44") or its number; null/blank falls back to
  // UNKNOWN_PQ_SCHEME (ECDSA-sized estimate). A present-but-unrecognized value throws, matching the
  // POST/JsonFormat path which rejects unknown enum names and numbers.
  static PQScheme parsePqScheme(String value) {
    if (value == null || value.trim().isEmpty()) {
      return PQScheme.UNKNOWN_PQ_SCHEME;
    }
    String trimmed = value.trim();
    PQScheme scheme;
    try {
      scheme = PQScheme.forNumber(Integer.parseInt(trimmed));
    } catch (NumberFormatException e) {
      scheme = PQScheme.valueOf(trimmed);
    }
    if (scheme == null) {
      throw new IllegalArgumentException("invalid pq_scheme: " + trimmed);
    }
    return scheme;
  }

  private void fillResponse(boolean visible,
                            ByteString ownerAddress,
                            int resourceType,
                            PQScheme pqScheme,
                            HttpServletResponse response) throws IOException {
    GrpcAPI.CanDelegatedMaxSizeResponseMessage reply =
            wallet.getCanDelegatedMaxSize(ownerAddress, resourceType, pqScheme);
    if (reply != null) {
      response.getWriter().println(JsonFormat.printToString(reply, visible));
    } else {
      response.getWriter().println("{}");
    }
  }
}
