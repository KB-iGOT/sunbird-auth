package org.sunbird.keycloak.rest;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class RequiredActionLinkProviderFactory implements RealmResourceProviderFactory {

  private static Logger logger =
      Logger.getLogger(RequiredActionLinkProviderFactory.class);
  public static final String PROVIDER_ID = "get-required-action-link";

  @Override
  public String getId() {
      logger.info("RestResourceProviderFactory: getId called ");
    logger.debug("RestResourceProviderFactory: getId called ");
    return PROVIDER_ID;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
      logger.info("RestResourceProviderFactory: create called ");
    return new RequiredActionLinkProvider(session);
  }

  @Override
  public void init(Scope config) {
      logger.info("RequiredActionLinkProviderFactory@init - called");

  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
      logger.info("RequiredActionLinkProviderFactory@postInit - called");

  }

  @Override
  public void close() {
      logger.info("RequiredActionLinkProviderFactory@close - called");

  }

}
