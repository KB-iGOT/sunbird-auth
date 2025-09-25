/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.sunbird.keycloak.login.phone;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PhonePasswordForm extends AbstractPhoneFormAuthenticator implements Authenticator {
    protected static ServicesLogger log = ServicesLogger.LOGGER;
    private static final Logger logger = Logger.getLogger(PhonePasswordForm.class);

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("PhonePasswordForm@action - called");
        logger.debug("PhonePasswordForm@action - called");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.info("Form Data: " + formData);
        if (formData.containsKey("cancel")) {
            logger.info("Authentication cancelled by user");
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            logger.info("Validation of form failed");
            return;
        }
        context.success();
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("PhonePasswordForm@validateForm - called");
        logger.debug("PhonePasswordForm@validateForm - called");
        return validateUserAndPassword(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("PhonePasswordForm@authenticate - called");
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        logger.info("Login hint: " + loginHint);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());
        logger.info("Remember me username: " + rememberMeUsername);

        if (loginHint != null || rememberMeUsername != null) {
            logger.info("Pre-filling username in the login form");
            if (loginHint != null) {
                logger.info("Using login hint for username");
                formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
            } else {
                logger.info("Using remember me username");
                formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                formData.add("rememberMe", "on");
                logger.info("Remember me set to on");
            }
        }
        Response challengeResponse = challenge(context, formData);
        logger.info("Challenge response created : " + challengeResponse);
        logger.info("Displaying login form");
        context.challenge(challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("PhonePasswordForm@challenge - called");
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createLogin();
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }
}
