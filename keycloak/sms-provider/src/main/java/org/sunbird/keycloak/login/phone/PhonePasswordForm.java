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
        logger.info("PhonePasswordForm@action - started");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("Decoded form parameters: %s", formData);
        if (formData.containsKey("cancel")) {
            logger.info("Cancel key found in formData → cancelling login");
            context.cancelLogin();
            logger.info("PhonePasswordForm@action - exiting with cancelLogin()");
            return;
        }
        logger.info("Validating form data...");
        if (!validateForm(context, formData)) {
            logger.info("Form validation failed → exiting with result=false");
            return;
        }
        logger.info("Form validation succeeded → marking authentication success");
        context.success();
        logger.info("PhonePasswordForm@action - completed successfully");
    }


    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.debug("PhonePasswordForm@validateForm - called");
        return validateUserAndPassword(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("PhonePasswordForm@authenticate - started");
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        logger.info("Initialized empty formData");
        String loginHint = context.getAuthenticationSession()
                .getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        logger.infof("Fetched loginHint from authentication session: %s", loginHint);
        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(
                context.getRealm(),
                context.getHttpRequest().getHttpHeaders()
        );
        logger.infof("Fetched rememberMeUsername from headers: %s", rememberMeUsername);
        if (loginHint != null || rememberMeUsername != null) {
            logger.info("Either loginHint or rememberMeUsername is present");

            if (loginHint != null) {
                formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                logger.infof("Added loginHint '%s' into formData as FORM_USERNAME", loginHint);
            } else {
                formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                formData.add("rememberMe", "on");
                logger.infof("Added rememberMeUsername '%s' into formData and set rememberMe=on", rememberMeUsername);
            }
        } else {
            logger.info("No loginHint or rememberMeUsername found → formData remains empty");
        }
        Response challengeResponse = challenge(context, formData);
        logger.infof("Created challengeResponse with formData: %s", formData);
        context.challenge(challengeResponse);
        logger.info("PhonePasswordForm@authenticate - issued challenge and exiting");
    }


    @Override
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
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
