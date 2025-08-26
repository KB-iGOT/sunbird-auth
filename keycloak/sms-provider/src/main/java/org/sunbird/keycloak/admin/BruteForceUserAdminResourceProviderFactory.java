package org.sunbird.keycloak.admin;

import org.keycloak.Config;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.jboss.logging.Logger;

public class BruteForceUserAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    private static final Logger logger = Logger.getLogger(BruteForceUserAdminResourceProviderFactory.class);
    public static final String ID = "ui-ext";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        logger.debug("FACTORY CREATE CALLED - Creating BruteForceUserResourceProvider");
        try {
            BruteForceUserAdminResourceProvider provider = new BruteForceUserAdminResourceProvider(session);
            logger.debug("FACTORY CREATE SUCCESS - Provider created: " + provider);
            return provider;
        } catch (Exception e) {
            logger.error("FACTORY CREATE FAILED: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void init(Scope config) {
        logger.debug("FACTORY INIT CALLED");
        // Empty implementation
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.debug("FACTORY POST-INIT CALLED");
        // Empty implementation
    }

    @Override
    public void close() {
        logger.debug("FACTORY CLOSE CALLED");
        // Empty implementation
    }
    
}