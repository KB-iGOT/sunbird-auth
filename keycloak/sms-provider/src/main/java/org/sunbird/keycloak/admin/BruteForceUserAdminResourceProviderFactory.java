package org.sunbird.keycloak.admin;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.jboss.logging.Logger;

public class BruteForceUserAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    private static final Logger logger = Logger.getLogger(BruteForceUserAdminResourceProviderFactory.class);
    public static final String ID = "sunbird-admin-ext";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        try {
            return new BruteForceUserAdminResourceProvider(session);
        } catch (Exception e) {
            logger.error("Failed to create BruteForceUserAdminResourceProvider: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void init(Scope config) {
        // Empty implementation
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Empty implementation
    }

    @Override
    public void close() {
        // Empty implementation
    }

}