package org.sunbird.keycloak.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;

/**
 * 
 * @author Amit Kumar
 * 
 *         Utility class for keycloak, it contains all the common method used across the
 *         application.
 * 
 */
public class SunbirdModelUtils {

  private static Logger logger = Logger.getLogger(SunbirdModelUtils.class);

  private SunbirdModelUtils() {}

  public static UserModel getUserByNameEmailOrPhone(AuthenticationFlowContext context,
      String username) {
      logger.info("SunbirdModelUtils:getUser getUserByNameEmailOrPhone called with username: "+username);
    String numberRegex = "\\d+";
    KeycloakSession session = context.getSession();
    if (username.matches(numberRegex)) {
        logger.info("SunbirdModelUtils:getUser username matched with phone regex");
      List<UserModel> userModels = session.users().searchForUserByUserAttribute(
          KeycloakSmsAuthenticatorConstants.ATTR_MOBILE, username, context.getRealm());
      logger.info("SunbirdModelUtils:getUser user model list size "+(userModels != null ? userModels.size() : 0));
      if (userModels != null && !userModels.isEmpty()) {
          logger.info("SunbirdModelUtils:getUser user found with phone number");
        // multiple user found for same attribute
    	for(UserModel model : userModels) {
      		logger.info("SunbirdModelUtils@getUser userModel id=" + model.getId()+", userName=" + model.getUsername()+", firstName"+model.getFirstName());
      	}  
    	if (userModels.size() > 1) {
            logger.info("SunbirdModelUtils@getUser filtering user models with federated id");
    		List<UserModel> filtered = new ArrayList<>();
    		Set<String> ids = new HashSet<>();
    		userModels.forEach(model->{
                logger.info("SunbirdModelUtils@getUser filtering user model id=" + model.getId()+", userName=" + model.getUsername()+", firstName"+model.getFirstName());
    			if(model.getId().startsWith("f:") && ids.add(model.getId())) {
    				filtered.add(model);
    			}
    		});
    		userModels = filtered;
    	}
    	logger.info("SunbirdModelUtils@getUser user model size "+userModels.size());
    	if (userModels.size() > 1) {
            logger.info("SunbirdModelUtils:getUser multiple user associated with phone");
          throw new ModelDuplicateException(Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE,
              KeycloakSmsAuthenticatorConstants.ATTR_MOBILE);
        }
        logger.info("SunbirdModelUtils:getUser user found with phone number");
        return userModels.get(0);
      } else {
          logger.info("SunbirdModelUtils:getUser no user found with phone number, search by name or email");
        return KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(),
            username);
      }
    } else {
        logger.info("SunbirdModelUtils:getUser username not matched with phone regex, search by name or email");
      return KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(),
          username);
    }
  }

}
