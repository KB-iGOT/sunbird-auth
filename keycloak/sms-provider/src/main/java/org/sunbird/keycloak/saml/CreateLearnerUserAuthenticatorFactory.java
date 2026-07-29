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
 * Factory for {@link CreateLearnerUserAuthenticator}.
 *
 * <p>Registers the authenticator so it can be bound as an execution in the "First Broker Login"
 * flow. It provisions the Sunbird learner-service user after the brokered user is created from the
 * incoming SAML assertion.
 */
public class CreateLearnerUserAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "create-learner-user";

    private static final CreateLearnerUserAuthenticator SINGLETON = new CreateLearnerUserAuthenticator();

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED, Requirement.DISABLED };

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
        return "Create Learner User (SAML First Login)";
    }

    @Override
    public String getReferenceCategory() {
        return "post broker login";
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
        return "Provisions the Sunbird learner-service user during First Broker Login "
                + "(idempotent: searches before create).";
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
