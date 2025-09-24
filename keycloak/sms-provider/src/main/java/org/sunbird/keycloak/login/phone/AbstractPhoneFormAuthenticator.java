/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates and other contributors as indicated by
 * the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.sunbird.keycloak.login.phone;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.keycloak.utils.SunbirdModelUtils;

public abstract class AbstractPhoneFormAuthenticator extends AbstractUsernameFormAuthenticator {

  private static final Logger logger = Logger.getLogger(AbstractPhoneFormAuthenticator.class);

    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context,
                                           MultivaluedMap<String, String> inputData) {
        logger.info("validateUserAndPassword() called in AbstractPhoneFormAuthenticator");

        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        logger.infof("Raw username from form: %s", username);

        if (username == null) {
            logger.info("Username is null → failing with USER_NOT_FOUND");
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, Messages.INVALID_USER);
            logger.info("Created challenge for missing username");
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            logger.info("Exiting validateUserAndPassword() with result=false (username missing)");
            return false;
        }

        // remove leading and trailing whitespace
        username = username.trim();
        logger.infof("Trimmed username: '%s'", username);

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession()
                .setAuthNote(AbstractPhoneFormAuthenticator.ATTEMPTED_USERNAME, username);
        logger.infof("Stored attempted username in session: %s", username);

        UserModel user = null;
        try {
            logger.infof("Looking up user by username/email/phone: %s", username);
            user = SunbirdModelUtils.getUserByNameEmailOrPhone(context, username);
            if (user != null) {
                logger.infof("User found: %s (enabled=%s)", user.getUsername(), user.isEnabled());
            } else {
                logger.infof("No user found for username: %s", username);
            }
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);
            logger.error("ModelDuplicateException occurred while looking up user", mde);

            if (mde.getDuplicateFieldName() != null
                    && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                logger.info("Duplicate user conflict on EMAIL");
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
                        AuthenticationFlowError.USER_CONFLICT);
            } else if (mde.getDuplicateFieldName() != null
                    && mde.getDuplicateFieldName().equals(UserModel.USERNAME)) {
                logger.info("Duplicate user conflict on USERNAME");
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
                        AuthenticationFlowError.USER_CONFLICT);
            } else if (mde.getDuplicateFieldName() != null
                    && mde.getDuplicateFieldName().equals(KeycloakSmsAuthenticatorConstants.ATTR_MOBILE)) {
                logger.info("Duplicate user conflict on MOBILE");
                setDuplicateUserChallenge(context, Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE,
                        Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE, AuthenticationFlowError.USER_CONFLICT);
            }

            logger.info("Exiting validateUserAndPassword() with result=false (duplicate user)");
            return false;
        }

        if (invalidUser(context, user)) {
            logger.info("User validation failed → invalidUser() returned false");
            return false;
        }

        if (!validatePassword(context, user, inputData)) {
            logger.infof("Password validation failed for user: %s", username);
            return false;
        }

        if (!enabledUser(context, user)) {
            logger.infof("User %s is disabled → enabledUser() check failed", username);
            return false;
        }

        String rememberMe = inputData.getFirst("rememberMe");
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        logger.infof("RememberMe flag from form: %s → resolved remember=%s", rememberMe, remember);

        if (remember) {
            logger.info("Setting REMEMBER_ME note in authentication session");
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            logger.info("Clearing REMEMBER_ME note from authentication session");
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }

        context.setUser(user);
        logger.infof("User %s successfully set in context", user != null ? user.getUsername() : "null");
        logger.info("Exiting validateUserAndPassword() with result=true");

        return true;
    }

    protected Response temporarilyDisabledUser(AuthenticationFlowContext context) {
      return context.form()
              .setError(Messages.ACCOUNT_TEMPORARILY_DISABLED).createLogin();
  }

}
