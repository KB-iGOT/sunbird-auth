package org.sunbird.keycloak.storage.spi;

import java.util.Collections;
import java.util.List;

import org.jboss.logging.Logger;
import org.sunbird.keycloak.utils.Constants;

public class UserService {

  private static Logger logger = Logger.getLogger(UserService.class);

  public UserService() {
  }

  public User getById(String id) {
    logger.info("UserService:getById get by id method called = " + id);
    List<User> users = getByKey(Constants.ID, id);
    if (null != users && !users.isEmpty()) {
      return users.get(0);
    }
    return new User();
  }

  public List<User> getByUsername(String username) {
      logger.info("UserService:getByUsername get by username method called = " + username);
    List<User> users = null;
    String numberRegex = "\\d+";
    String emailRegex = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
      + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
    // mobile number length is of 10 digit
    // assumption is either username will match with phone or email
    if (username.matches(numberRegex) && 10 == username.length()) {
        logger.info("UserService:getByUsername username matched with phone regex");
      users = getByKey(Constants.PHONE, username);
      if (users != null) {
          logger.info("UserService:getByUsername user found with phone number");
        return users;
      }
    } else if (username.matches(emailRegex)) {
        logger.info("UserService:getByUsername username matched with email regex");
      users = getByKey(Constants.EMAIL, username);
      if (users != null)
        return users;
    }
    users = getByKey(Constants.USERNAME, username);
    logger.info("UserService:getByUsername search user by username");
    if (users != null)
      return users;

    return Collections.emptyList();
  }

  public List<User> getByKey(String key, String searchValue) {
      logger.info("UserService:getByKey get by key method called with key: "+key+" and value: "+searchValue);
    return UserSearchService.getUserByKey(key, searchValue);
  }

}