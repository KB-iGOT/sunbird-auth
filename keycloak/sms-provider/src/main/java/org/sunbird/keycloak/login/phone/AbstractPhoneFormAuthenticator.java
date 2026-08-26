package org.sunbird.keycloak.login.phone;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
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
import org.keycloak.credential.UserCredentialManager;
import org.keycloak.credential.CredentialInput;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.models.UserCredentialModel;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public abstract class AbstractPhoneFormAuthenticator extends AbstractUsernameFormAuthenticator {

  private static final Logger logger = Logger.getLogger(AbstractPhoneFormAuthenticator.class);

  @Override
  public boolean validateUserAndPassword(AuthenticationFlowContext context,
      MultivaluedMap<String, String> inputData) {
    String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
    logger.debug("AbstractPhoneFormAuthenticator@validateUserAndPassword - Username -" + username);

    if (username == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse = challenge(context, Messages.INVALID_USER);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return false;
    }

    // remove leading and trailing whitespace
    username = username.trim();

    context.getEvent().detail(Details.USERNAME, username);
    context.getAuthenticationSession()
        .setAuthNote(AbstractPhoneFormAuthenticator.ATTEMPTED_USERNAME, username);

    UserModel user = null;
    try {
      
      user = SunbirdModelUtils.getUserByNameEmailOrPhone(context, username);
      
    } catch (ModelDuplicateException mde) {
      ServicesLogger.LOGGER.modelDuplicateException(mde);

      // Could happen during federation import
      if (mde.getDuplicateFieldName() != null
          && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
        setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
            AuthenticationFlowError.USER_CONFLICT);
      } else if (mde.getDuplicateFieldName() != null
          && mde.getDuplicateFieldName().equals(UserModel.USERNAME)) {
        setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
            AuthenticationFlowError.USER_CONFLICT);
      } else if (mde.getDuplicateFieldName() != null
          && mde.getDuplicateFieldName().equals(KeycloakSmsAuthenticatorConstants.ATTR_MOBILE)) {
        setDuplicateUserChallenge(context, Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE,
            Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE, AuthenticationFlowError.USER_CONFLICT);
      }

      return false;
    }

    if (invalidUser(context, user)) {
      return false;
    }

    if (!validatePassword(context, user, inputData, false)) {
      return false;
    }

    if (!enabledUser(context, user)) {
      return false;
    }

    String rememberMe = inputData.getFirst("rememberMe");
    boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
    if (remember) {
      context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
      context.getEvent().detail(Details.REMEMBER_ME, "true");
    } else {
      context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
    }
    context.setUser(user);
    return true;
  }
  
  protected Response temporarilyDisabledUser(AuthenticationFlowContext context) {
      return context.form()
              .setError(Messages.ACCOUNT_TEMPORARILY_DISABLED).createForm("login.ftl");
  }

    private boolean invalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            return true;
        }
        if (!user.isEnabled()) {
            context.getEvent().error(Errors.USER_DISABLED);
            return true;
        }
        if (context.getRealm().isBruteForceProtected()) {
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                context.getEvent().error(Errors.USER_TEMPORARILY_DISABLED);
                return true;
            }
        }
        return false;
    }

    public boolean validatePassword(AuthenticationFlowContext context, UserModel user,
                                    MultivaluedMap<String, String> inputData) {
        String encryptedPassword = inputData.getFirst(CredentialRepresentation.PASSWORD);
        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        String iv = inputData.getFirst(Constants.IV);
        // Decrypt the password
        String decryptedPassword = decryptPassword(encryptedPassword, secretKey, iv);

        List<CredentialInput> credentials = new LinkedList<>();
        credentials.add(UserCredentialModel.password(decryptedPassword));

        return decryptedPassword != null && !decryptedPassword.isEmpty()
                && new UserCredentialManager(context.getSession(), context.getRealm(), user).isValid(credentials);
    }

    // Add the decryptPassword method
    private String decryptPassword(String encryptedPassword, String secretKey, String iv) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Error while decrypting password", e);
        }
    }

}
