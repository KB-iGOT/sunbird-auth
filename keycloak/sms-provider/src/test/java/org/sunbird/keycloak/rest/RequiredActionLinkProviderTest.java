package org.sunbird.keycloak.rest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.ext.RuntimeDelegate;
import jakarta.ws.rs.core.MediaType;
import org.junit.BeforeClass;
import org.junit.Before;
import org.junit.Test;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;
import org.keycloak.representations.idm.ErrorRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.sunbird.keycloak.utils.Constants;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ RequiredActionLinkProviderFactory.class, KeycloakSession.class,
    KeycloakContext.class, KeycloakModelUtils.class, RealmModel.class, RedirectUtils.class,
    AppAuthManager.class, AppAuthManager.BearerTokenAuthenticator.class, RequiredActionLinkProvider.class,
    UriInfo.class, AccessToken.class, Access.class, AuthResult.class, LoginActionsService.class,
    ExecuteActionsActionToken.class })
@PowerMockIgnore({ "javax.management.*", "javax.net.ssl.*", "javax.security.*", "jakarta.ws.rs.*",
    "javax.crypto.*", "com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "org.w3c.dom.*",
    "com.sun.org.apache.xalan.*", "javax.activation.*", "javax.net.*" })
public class RequiredActionLinkProviderTest {

  private static KeycloakSession session;
  private static KeycloakContext context;
  private static RealmModel model;
  private static AppAuthManager.BearerTokenAuthenticator authenticator;
  private static AppAuthManager authMangr;
  private static AuthResult authResult;
  private static UserModel userModel;
  private static ClientModel client;
  private static org.keycloak.models.KeycloakUriInfo keycloakUriInfo;
  private static UriInfo uriInfo;
  private Map<String, String> request;

  @BeforeClass
  public static void setUpClass() throws Exception {
    RuntimeDelegate.setInstance(new MockRuntimeDelegate());
    session = PowerMockito.mock(KeycloakSession.class);
    context = PowerMockito.mock(KeycloakContext.class);
    model = PowerMockito.mock(RealmModel.class);
    authenticator = PowerMockito.mock(AppAuthManager.BearerTokenAuthenticator.class);
    authMangr = PowerMockito.mock(AppAuthManager.class);
    authResult = PowerMockito.mock(AuthResult.class);
    userModel = PowerMockito.mock(UserModel.class);
    client = PowerMockito.mock(ClientModel.class);
    keycloakUriInfo = PowerMockito.mock(org.keycloak.models.KeycloakUriInfo.class);
    uriInfo = PowerMockito.mock(UriInfo.class);

    PowerMockito.when(session.getContext()).thenReturn(context);
    PowerMockito.when(context.getRealm()).thenReturn(model);
    PowerMockito.when(context.getUri()).thenReturn(keycloakUriInfo);
  }

  @Before
  public void setUp() {
    request = new HashMap<>();
    request.put(Constants.REDIRECT_URI, "/login");
    request.put(Constants.CLIENT_ID, "master");
    request.put(Constants.REQUIRED_ACTION, "UPDATE_PASSWORD");
    request.put(Constants.USERNAME, "amit");

  }

  @Test
  public void testCheckRealmAdminAccessForUnAuthorized() throws Exception {
    PowerMockito.whenNew(AppAuthManager.BearerTokenAuthenticator.class)
        .withArguments(session).thenReturn(authenticator);
    PowerMockito.when(authenticator.authenticate()).thenReturn(null);

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      System.out.println("DEBUG: Status=" + ex.getResponse().getStatus());
      System.out.println("DEBUG: Entity=" + ex.getResponse().getEntity());
      System.out.println("DEBUG: Message=" + ex.getMessage());
      if (ex.getCause() != null) {
        System.out.println("DEBUG: Cause=" + ex.getCause().getClass().getName() + ": " + ex.getCause().getMessage());
      }
      assertEquals(Status.UNAUTHORIZED.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertEquals(Constants.ERROR_NOT_AUTHORIZED, error.getErrorMessage());
    }
  }

  @Test
  public void testCheckRealmAdminAccessForForbidden() throws Exception {
    PowerMockito.whenNew(AppAuthManager.BearerTokenAuthenticator.class)
        .withArguments(session).thenReturn(authenticator);
    PowerMockito.when(authenticator.authenticate()).thenReturn(authResult);

    AccessToken accessToken = PowerMockito.mock(AccessToken.class);
    Access access = PowerMockito.mock(Access.class);

    PowerMockito.when(authResult.getToken()).thenReturn(accessToken);
    PowerMockito.when(accessToken.getRealmAccess()).thenReturn(access);
    PowerMockito.when(access.isUserInRole(Constants.ADMIN)).thenReturn(false);

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.FORBIDDEN.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertEquals(Constants.ERROR_REALM_ADMIN_ROLE_ACCESS, error.getErrorMessage());
    }
  }

  @Test
  public void testUsernameMandatoryCheck() throws Exception {
    setupValidAuth();

    request.put(Constants.USERNAME, null);
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertTrue(error.getErrorMessage().contains(Constants.USERNAME));
    }
  }

  @Test
  public void testUsernameEmptyCheck() throws Exception {
    setupValidAuth();

    request.put(Constants.USERNAME, "");
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
    }
  }

  @Test
  public void testInvalidUserNameCheck() throws Exception {
    setupValidAuth();

    String userName = "nonexistent";
    request.put(Constants.USERNAME, userName);

    PowerMockito.mockStatic(KeycloakModelUtils.class);
    PowerMockito.when(KeycloakModelUtils.findUserByNameOrEmail(session, model, userName))
        .thenReturn(null);

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertTrue(error.getErrorMessage().contains(userName));
    }
  }

  @Test
  public void testUserDisabledCheck() throws Exception {
    setupValidAuth();
    setupValidUser(false);

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertEquals(Constants.ERROR_USER_IS_DISABLED, error.getErrorMessage());
    }
  }

  @Test
  public void testClientIdMandatoryCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);

    request.put(Constants.CLIENT_ID, null);
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
    }
  }

  @Test
  public void testClientIdEmptyCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);

    request.put(Constants.CLIENT_ID, "");
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
    }
  }

  @Test
  public void testInvalidClientIdCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);

    String clientId = "nonexistent";
    request.put(Constants.CLIENT_ID, clientId);

    PowerMockito.when(model.getClientByClientId(clientId)).thenReturn(null);
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertTrue(error.getErrorMessage().contains(clientId));
    }
  }

  @Test
  public void testClientDisabledCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);

    String clientId = "disabled-client";
    request.put(Constants.CLIENT_ID, clientId);

    PowerMockito.when(model.getClientByClientId(clientId)).thenReturn(client);
    PowerMockito.when(client.isEnabled()).thenReturn(false);

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertTrue(error.getErrorMessage().contains(Constants.ERROR_NOT_ENABLED));
    }
  }

  @Test
  public void testInvalidRedirectUriCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);
    setupValidClient();

    String redirectUri = "invalid-uri";
    request.put(Constants.REDIRECT_URI, redirectUri);

    PowerMockito.mockStatic(RedirectUtils.class);
    PowerMockito.when(RedirectUtils.verifyRedirectUri(session, redirectUri, client))
        .thenReturn(null);

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertTrue(error.getErrorMessage().contains(redirectUri));
    }
  }

  @Test
  public void testRequiredActionMandatoryCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);
    setupValidClient();
    setupValidRedirectUri();

    request.put(Constants.REQUIRED_ACTION, null);
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
    }
  }

  @Test
  public void testInvalidRequiredActionCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);
    setupValidClient();
    setupValidRedirectUri();

    String invalidAction = "INVALID_ACTION";
    request.put(Constants.REQUIRED_ACTION, invalidAction);
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertTrue(error.getErrorMessage().contains(invalidAction));
    }
  }

  @Test
  public void testInvalidExpirationCheck() throws Exception {
    setupValidAuth();
    setupValidUser(true);
    setupValidClient();
    setupValidRedirectUri();

    request.put(Constants.EXPIRATION_IN_SECS, "invalid");
    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
    }
  }

  @Test
  public void testSuccessfulLinkGenerationWithUpdatePassword() throws Exception {
    setupSuccessfulScenario();
    request.put(Constants.REQUIRED_ACTION, "UPDATE_PASSWORD");

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);
    Response response = provider.generateRequiredActionLink(request);

    assertEquals(200, response.getStatus());
    @SuppressWarnings("unchecked")
    Map<String, Object> responseEntity = (Map<String, Object>) response.getEntity();
    assertNotNull(responseEntity.get(Constants.LINK));
  }

  @Test
  public void testSuccessfulLinkGenerationWithVerifyEmail() throws Exception {
    setupSuccessfulScenario();
    request.put(Constants.REQUIRED_ACTION, "VERIFY_EMAIL");

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);
    Response response = provider.generateRequiredActionLink(request);

    assertEquals(200, response.getStatus());
    @SuppressWarnings("unchecked")
    Map<String, Object> responseEntity = (Map<String, Object>) response.getEntity();
    assertNotNull(responseEntity.get(Constants.LINK));
  }

  @Test
  public void testSuccessfulLinkGenerationWithCustomExpiration() throws Exception {
    setupSuccessfulScenario();
    request.put(Constants.EXPIRATION_IN_SECS, "7200");

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);
    Response response = provider.generateRequiredActionLink(request);

    assertEquals(200, response.getStatus());
  }

  @Test
  public void testSuccessfulLinkGenerationWithoutRedirectUri() throws Exception {
    setupSuccessfulScenario();
    request.remove(Constants.REDIRECT_URI);

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);
    Response response = provider.generateRequiredActionLink(request);

    assertEquals(200, response.getStatus());
  }

  @Test
  public void testLinkGenerationException() throws Exception {
    setupValidAuth();
    setupValidUser(true);
    setupValidClient();
    setupValidRedirectUri();

    // Mock LoginActionsService to throw exception
    PowerMockito.mockStatic(LoginActionsService.class);
    PowerMockito.when(LoginActionsService.actionTokenProcessor(uriInfo))
        .thenThrow(new RuntimeException("Test exception"));

    RequiredActionLinkProvider provider = new RequiredActionLinkProvider(session);

    try {
      provider.generateRequiredActionLink(request);
      fail("Expected WebApplicationException");
    } catch (WebApplicationException ex) {
      assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), ex.getResponse().getStatus());
      ErrorRepresentation error = (ErrorRepresentation) ex.getResponse().getEntity();
      assertEquals(Constants.ERROR_CREATE_LINK, error.getErrorMessage());
    }
  }

  private void setupValidAuth() throws Exception {
    PowerMockito.whenNew(AppAuthManager.BearerTokenAuthenticator.class)
        .withArguments(session).thenReturn(authenticator);
    PowerMockito.when(authenticator.authenticate()).thenReturn(authResult);

    AccessToken accessToken = PowerMockito.mock(AccessToken.class);
    Access access = PowerMockito.mock(Access.class);

    PowerMockito.when(authResult.getToken()).thenReturn(accessToken);
    PowerMockito.when(accessToken.getRealmAccess()).thenReturn(access);
    PowerMockito.when(access.isUserInRole(Constants.ADMIN)).thenReturn(true);
  }

  private void setupValidUser(boolean enabled) {
    PowerMockito.mockStatic(KeycloakModelUtils.class);
    PowerMockito.when(KeycloakModelUtils.findUserByNameOrEmail(session, model, "amit"))
        .thenReturn(userModel);
    PowerMockito.when(userModel.isEnabled()).thenReturn(enabled);
    PowerMockito.when(userModel.getId()).thenReturn("user-id");
  }

  private void setupValidClient() {
    PowerMockito.when(model.getClientByClientId("master")).thenReturn(client);
    PowerMockito.when(client.isEnabled()).thenReturn(true);
  }

  private void setupValidRedirectUri() {
    PowerMockito.mockStatic(RedirectUtils.class);
    PowerMockito.when(RedirectUtils.verifyRedirectUri(session, "/login", client))
        .thenReturn("/login");
  }

  private void setupSuccessfulScenario() throws Exception {
    setupValidAuth();
    setupValidUser(true);
    setupValidClient();
    setupValidRedirectUri();

    // Mock successful token creation
    PowerMockito.mockStatic(LoginActionsService.class);
    UriBuilder uriBuilder = PowerMockito.mock(UriBuilder.class);
    PowerMockito.when(LoginActionsService.actionTokenProcessor(uriInfo)).thenReturn(uriBuilder);
    PowerMockito.when(uriBuilder.queryParam(Mockito.anyString(), Mockito.anyString())).thenReturn(uriBuilder);
    PowerMockito.when(uriBuilder.build("test-realm")).thenReturn(java.net.URI.create("http://test.com/link"));
    PowerMockito.when(model.getName()).thenReturn("test-realm");
  }

  public static class MockRuntimeDelegate extends RuntimeDelegate {
    @Override
    public Response.ResponseBuilder createResponseBuilder() {
      Response.ResponseBuilder builder = Mockito.mock(Response.ResponseBuilder.class);
      final int[] statusHolder = new int[1];
      final Object[] entityHolder = new Object[1];

      // Handle int status code
      Mockito.when(builder.status(Mockito.anyInt())).thenAnswer(inv -> {
        statusHolder[0] = inv.getArgument(0);
        return builder;
      });
      // Handle Status enum - must come before StatusType to match more specific type
      // first
      Mockito.when(builder.status(org.mockito.ArgumentMatchers.any(Response.Status.class))).thenAnswer(inv -> {
        Response.Status status = inv.getArgument(0);
        statusHolder[0] = status.getStatusCode();
        return builder;
      });
      // Handle StatusType interface (parent of Status enum)
      Mockito.when(builder.status(org.mockito.ArgumentMatchers.any(Response.StatusType.class))).thenAnswer(inv -> {
        Response.StatusType status = inv.getArgument(0);
        statusHolder[0] = status.getStatusCode();
        return builder;
      });
      Mockito.when(builder.entity(Mockito.any())).thenAnswer(inv -> {
        entityHolder[0] = inv.getArgument(0);
        return builder;
      });
      Mockito.when(builder.type(Mockito.any(MediaType.class))).thenReturn(builder);
      Mockito.when(builder.type(Mockito.anyString())).thenReturn(builder);

      Mockito.when(builder.build()).thenAnswer(inv -> {
        Response response = Mockito.mock(Response.class);
        Mockito.when(response.getStatus()).thenReturn(statusHolder[0]);
        Mockito.when(response.getEntity()).thenReturn(entityHolder[0]);
        return response;
      });
      return builder;
    }

    @Override
    public UriBuilder createUriBuilder() {
      return null;
    }

    @Override
    public jakarta.ws.rs.core.Variant.VariantListBuilder createVariantListBuilder() {
      return null;
    }

    @Override
    public <T> T createEndpoint(jakarta.ws.rs.core.Application application, Class<T> endpointType) {
      return null;
    }

    @Override
    public <T> RuntimeDelegate.HeaderDelegate<T> createHeaderDelegate(Class<T> type) {
      return null;
    }

    @Override
    public jakarta.ws.rs.core.Link.Builder createLinkBuilder() {
      return null;
    }

    @Override
    public jakarta.ws.rs.core.EntityPart.Builder createEntityPartBuilder(String partName) {
      return null;
    }

    @Override
    public jakarta.ws.rs.SeBootstrap.Configuration.Builder createConfigurationBuilder() {
      return null;
    }

    @Override
    public java.util.concurrent.CompletionStage<jakarta.ws.rs.SeBootstrap.Instance> bootstrap(
        jakarta.ws.rs.core.Application application, jakarta.ws.rs.SeBootstrap.Configuration configuration) {
      return null;
    }

    @Override
    public java.util.concurrent.CompletionStage<jakarta.ws.rs.SeBootstrap.Instance> bootstrap(
        Class<? extends jakarta.ws.rs.core.Application> clazz, jakarta.ws.rs.SeBootstrap.Configuration configuration) {
      return null;
    }
  }
}
