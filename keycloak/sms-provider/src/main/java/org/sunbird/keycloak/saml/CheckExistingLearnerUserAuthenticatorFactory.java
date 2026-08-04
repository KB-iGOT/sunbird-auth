package org.sunbird.keycloak.saml;

import java.util.Collections;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory for {@link CheckExistingLearnerUserAuthenticator}.
 *
 * <p>Bind this as an <b>Alternative</b> execution ahead of the built-in "Create User If Unique" in
 * the "first broker login" flow's user-creation-or-linking subflow (the same subflow "Create User If
 * Unique" and "Handle Existing Account" already live in). Ordering matters: this must run and be
 * evaluated before "Create User If Unique" so a returning learner never gets a throwaway native
 * Keycloak user created in the first place.
 */
public class CheckExistingLearnerUserAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "check-existing-learner-user";

    private static final CheckExistingLearnerUserAuthenticator SINGLETON =
            new CheckExistingLearnerUserAuthenticator();

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.ALTERNATIVE, Requirement.REQUIRED, Requirement.DISABLED };

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Check Existing Learner User (SAML)";
    }

    @Override
    public String getReferenceCategory() {
        return "user creation or linking";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Looks up the SAML assertion's email against the learner-service user_lookup table "
                + "before Keycloak creates a local user. If a learner user already exists, points the "
                + "session at it directly so no throwaway native Keycloak user is ever created for a "
                + "returning learner. Bind as an Alternative ahead of 'Create User If Unique'.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public void init(Scope config) {
        // No initialization required.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization required.
    }

    @Override
    public void close() {
        // No resources to release.
    }
}
