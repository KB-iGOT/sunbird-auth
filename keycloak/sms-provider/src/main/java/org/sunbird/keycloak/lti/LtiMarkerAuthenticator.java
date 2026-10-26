package org.sunbird.keycloak.lti;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

/**
 * Additive, pass-through step for the existing browser flow: if the incoming authorize
 * request carries {@code lti_message_hint} (a param only Moodle's LTI launch ever sends),
 * stash it as a user-session note so {@link LtiProtocolMapper} can see it later when the
 * token is built. For every normal iGOT login this param is absent, the step does nothing,
 * and {@link #authenticate} always succeeds - it never blocks or alters existing login
 * behavior.
 */
public class LtiMarkerAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(LtiMarkerAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String ltiMessageHint = context.getAuthenticationSession()
                .getClientNote(LtiConstants.LTI_MESSAGE_HINT_PARAM);

        if (ltiMessageHint != null && !ltiMessageHint.isEmpty()) {
            logger.debug("LtiMarkerAuthenticator: lti_message_hint present, marking session for LTI claim injection");
            context.getAuthenticationSession().setUserSessionNote(
                    LtiConstants.LTI_MESSAGE_HINT_PARAM, ltiMessageHint);

            // target_link_uri claim should match the redirect_uri the Tool actually registered
            // for this launch - propagate it the same way, rather than hardcoding it.
            String redirectUri = context.getAuthenticationSession().getClientNote("redirect_uri");
            if (redirectUri != null) {
                context.getAuthenticationSession().setUserSessionNote("lti_target_link_uri", redirectUri);
            }
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {
        // no-op
    }

    @Override
    public void close() {
        // no-op, stateless
    }
}
