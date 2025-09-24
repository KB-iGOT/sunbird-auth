package org.sunbird.keycloak.resetcredential.chooseuser;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticator;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.keycloak.utils.SunbirdModelUtils;


/**
 * 
 * @author Amit Kumar
 *
 *         This class will override the choose user action for reset credential flow under
 *         Authentication. Here we are overriding action method for getting user details by
 *         attributes (i.e phone)
 */
public class ResetCredentialChooseUserAuthenticator implements Authenticator {


  private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticator.class);
  public static final String PROVIDER_ID = "spi-reset-credentials-choose-user";


    @Override
    public void authenticate(AuthenticationFlowContext context) {

        logger.info("Starting authenticate() in ResetPassword flow");

        String existingUserId =
                context.getAuthenticationSession().getAuthNote(AbstractIdpAuthenticator.EXISTING_USER_INFO);
        logger.info("Fetched existingUserId from authNote: %s", existingUserId);

        if (existingUserId != null) {
            UserModel existingUser = AbstractIdpAuthenticator.getExistingUser(
                    context.getSession(),
                    context.getRealm(),
                    context.getAuthenticationSession()
            );

            logger.info("Reauthentication after first broker login. Using user: %s", existingUser.getUsername());
            context.setUser(existingUser);
            context.success();
            logger.info("authenticate() completed with context.success() for existingUserId path");
            return;
        }

        String actionTokenUserId =
                context.getAuthenticationSession().getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
        logger.info("Fetched actionTokenUserId from authNote: %s", actionTokenUserId);

        if (actionTokenUserId != null) {
            UserModel existingUser =
                    context.getSession().users().getUserById(actionTokenUserId, context.getRealm());

            logger.info("Reauthentication via action token. Using user: %s", existingUser.getUsername());
            context.setUser(existingUser);
            context.success();
            logger.info("authenticate() completed with context.success() for actionTokenUserId path");
            return;
        }

        logger.info("No existingUserId or actionTokenUserId found. Triggering password reset flow");
        Response challenge = context.form().createPasswordReset();
        context.challenge(challenge);
        logger.info("authenticate() completed with context.challenge() for password reset");
    }


    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("action() started in ResetPassword flow");

        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("Decoded form parameters: %s", formData);

        String username = formData.getFirst("username");
        logger.infof("Extracted username: %s", username);

        if (username == null || username.isEmpty()) {
            logger.info("Username is missing in form data");
            event.error(Errors.USERNAME_MISSING);
            Response challenge = context.form().setError(Messages.MISSING_USERNAME).createPasswordReset();
            logger.info("Created challenge for missing username");
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            logger.info("Exiting action() with failureChallenge: USERNAME_MISSING");
            return;
        }

        UserModel user = null;
        try {
            logger.infof("Looking up user by username/email/phone: %s", username);
            user = SunbirdModelUtils.getUserByNameEmailOrPhone(context, username);

            if (user == null) {
                logger.infof("No user found for username: %s", username);
                event.error(Messages.INVALID_USER);
                Response challenge = context.form().setError(Errors.USER_NOT_FOUND).createPasswordReset();
                logger.info("Created challenge for user not found");
                context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
                logger.info("Exiting action() with failureChallenge: USER_NOT_FOUND");
                return;
            }

            logger.infof("User found: %s (enabled=%s)", user.getUsername(), user.isEnabled());
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);
            logger.error("Duplicate user exception occurred", mde);

            String errMsg = "";
            if (mde.getDuplicateFieldName() != null
                    && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                errMsg = Constants.MULTIPLE_USER_ASSOCIATED_WITH_EMAIL;
            } else if (mde.getDuplicateFieldName() != null
                    && mde.getDuplicateFieldName().equals(UserModel.USERNAME)) {
                errMsg = Constants.MULTIPLE_USER_ASSOCIATED_WITH_USERNAME;
            } else if (mde.getDuplicateFieldName() != null
                    && mde.getDuplicateFieldName().equals(KeycloakSmsAuthenticatorConstants.ATTR_MOBILE)) {
                errMsg = Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE;
            }

            logger.infof("Duplicate user conflict on field: %s", mde.getDuplicateFieldName());
            event.error(Messages.INVALID_USER);
            Response challenge = context.form().setError(errMsg).createPasswordReset();
            logger.info("Created challenge for duplicate user conflict");
            context.failureChallenge(AuthenticationFlowError.USER_CONFLICT, challenge);
            logger.info("Exiting action() with failureChallenge: USER_CONFLICT");
            return;
        }

        context.getAuthenticationSession()
                .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);
        logger.infof("Stored attempted username in authentication session: %s", username);

        if (user == null) {
            logger.info("User is null after lookup — notifying as USER_NOT_FOUND");
            event.clone().detail(Details.USERNAME, username).error(Errors.USER_NOT_FOUND);
        } else if (!user.isEnabled()) {
            logger.infof("User %s is disabled", username);
            event.clone().detail(Details.USERNAME, username).user(user).error(Errors.USER_DISABLED);
        } else {
            logger.infof("Setting authenticated user: %s", username);
            context.setUser(user);
        }

        context.success();
        logger.info("action() completed successfully with context.success()");
    }


    @Override
  public void close() {
    logger.debug("ResetCredentialChooseUserAuthenticator close called ... ");
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    logger.debug("ResetCredentialChooseUserAuthenticator setRequiredActions called ... ");
  }

}
