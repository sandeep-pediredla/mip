package com.forcepoint.dlp.mip.java_lib_integration;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.informationprotection.IAuthDelegate;
import com.microsoft.informationprotection.Identity;

import java.net.MalformedURLException;
import java.util.concurrent.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthDelegateUserCredentials implements IAuthDelegate {

  final static Logger logger = LogManager.getLogger(AuthDelegateUserCredentials.class);

  private String userName;
  private String password;
  private String clientId;
  private String sccToken;
  private String protectionToken;

  public AuthDelegateUserCredentials(String userName, String password, String clientId,
      String sccToken, String protectionToken) {
    this.userName = userName;
    this.password = password;
    this.sccToken = sccToken;
    this.clientId = clientId;
    this.protectionToken = protectionToken;
  }

  @Override
  public String acquireToken(Identity identity, String authority, String resource, String claims) {
    logger.info("Acquiring token");

    if ((userName == null || password == null) && protectionToken == null && sccToken == null) {
      throw new IllegalArgumentException("Login without user & password or token is not supported");
    }

    if (resource.equalsIgnoreCase("https://syncservice.o365syncservice.com/")) {
      if (sccToken != null && !sccToken.isEmpty()) {
        return sccToken;
      }
    } else if (protectionToken != null && !protectionToken.isEmpty()) {
      return protectionToken;
    }

    ExecutorService service = Executors.newFixedThreadPool(1);
    AuthenticationContext authContext;
    try {
      authContext = new AuthenticationContext(authority, false, service);
      Future<AuthenticationResult> authenticationResultFuture = authContext
          .acquireToken(resource, clientId, userName, password, null);
      AuthenticationResult authenticationResult = authenticationResultFuture.get();
      String accessToken = authenticationResult.getAccessToken();
      logger.info("accessToken acquired");
      return accessToken;
    } catch (MalformedURLException | InterruptedException | ExecutionException e) {
      logger.error("Failed to get token", e);
      e.printStackTrace();
      throw new RuntimeException(e);
    } catch (Exception e) {
      logger.error("Failed to get token", e);
      e.printStackTrace();
      throw new RuntimeException(e);
    } finally {
      logger.info("Shutting down service");

      service.shutdown();
      try {
        if (!service.awaitTermination(500, TimeUnit.MILLISECONDS)){
          service.shutdownNow();
        }
      } catch (InterruptedException e) {
        logger.error("Failed to shutdown service", e);
        service.shutdownNow();
      }
    }
  }
}
