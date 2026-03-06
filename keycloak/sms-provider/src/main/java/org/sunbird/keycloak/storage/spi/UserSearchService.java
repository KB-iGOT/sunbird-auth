package org.sunbird.keycloak.storage.spi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;

import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.sunbird.keycloak.utils.Constants;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sunbird.keycloak.utils.HttpClientUtil;

public class UserSearchService {

  private static Logger logger = Logger.getLogger(UserSearchService.class);

  private UserSearchService() {
  }

  @SuppressWarnings({ "unchecked" })
  public static List<User> getUserByKey(String key, String value) {
    Map<String, Object> userRequest = new HashMap<>();
    Map<String, Object> request = new HashMap<>();
    request.put("key", key.toLowerCase());
    request.put("value", value);
    request.put("fields", Arrays.asList("email", "firstName", "lastName", "id", "phone", "userName", "countryCode",
        "status", "rootorgid", "roles"));
    userRequest.put("request", request);
    logger.info("UserSearchService:getUserByKey sunbird_user_service_base_url "
        + System.getenv("sunbird_user_service_base_url"));
    String userLookupUrl = System.getenv("sunbird_user_service_base_url").isEmpty() ? "http://10.175.2.100/learner24"
        : System.getenv("sunbird_user_service_base_url") + "/private/user/v1/lookup";
    Map<String, Object> resMap = post(userRequest, userLookupUrl, System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION));
    logger.info("UserSearchService:getUserByKey responseMap " + resMap);
    Map<String, Object> result = null;
    List<Map<String, Object>> content = null;
    if (null != resMap) {
      result = (Map<String, Object>) resMap.get("result");
    }
    if (null != result) {
      content = (List<Map<String, Object>>) result.get("response");
    }
    logger.info("UserSearchService:getUserByKey keycloak_24 check: " + content);
    if (null != content) {
      List<User> userList = new ArrayList<>();
      if (!content.isEmpty()) {
        content.forEach(userMap -> {
          if (null != userMap) {
            userList.add(createUser(userMap));
          }
        });
      }
      logger.info("UserSearchService:getUserByKey keycloak_24 check userList: " + userList);
      return userList;
    }
    return Collections.emptyList();
  }

  private static User createUser(Map<String, Object> userMap) {
    User user = new User();
    user.setEmail((String) userMap.get(Constants.EMAIL));
    user.setFirstName((String) userMap.get("firstName"));
    user.setId((String) userMap.get(Constants.ID));
    user.setLastName((String) userMap.get("lastName"));
    user.setPhone((String) userMap.get(Constants.PHONE));
    user.setUsername((String) userMap.get("userName"));
    user.setCountryCode((String) userMap.get("countryCode"));
    user.setOrg((String) userMap.get("rootOrgId"));
    if (null != userMap.get("roles") && ((List) userMap.get("roles")).size() > 0) {
      user.setRoles((List<String>) userMap.get("roles"));
    } else {
      List roles = new ArrayList();
      roles.add("");
      user.setRoles(roles);
    }
    if (null != userMap.get("status") && ((Integer) userMap.get("status")) == 0) {
      user.setEnabled(false);
    } else {
      user.setEnabled(true);
    }
    return user;
  }

  /**
   * Validates a user's password against the Sunbird backend.
   * Calls POST ${sunbird_user_service_base_url}/private/user/v1/login
   * and returns true only when the response contains a non-null/non-empty
   * "result.response.accessToken" (or similar success indicator).
   *
   * @return true  if the backend confirms the credentials are valid
   *         false if the backend rejects them or the call fails
   */
  @SuppressWarnings("unchecked")
  public static boolean validateUserPassword(String username, String password) {
    try {
      String baseUrl = System.getenv("sunbird_user_service_base_url");
      if (baseUrl == null || baseUrl.isEmpty()) {
        logger.warn("UserSearchService:validateUserPassword sunbird_user_service_base_url is not set");
        return false;
      }
      String loginUrl = baseUrl + "/private/user/v1/login";
      Map<String, Object> request = new HashMap<>();
      request.put("userName", username);
      request.put("password", password);
      Map<String, Object> body = new HashMap<>();
      body.put("request", request);
      logger.info("UserSearchService:validateUserPassword calling: " + loginUrl + " for user: " + username);
      Map<String, Object> response = post(body, loginUrl, System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION));
      if (response == null) {
        logger.warn("UserSearchService:validateUserPassword null response from backend for user: " + username);
        return false;
      }
      // Sunbird LMS success response: {"responseCode":"OK","result":{"response":{"accessToken":"..."}}}
      String responseCode = (String) response.get("responseCode");
      if ("OK".equalsIgnoreCase(responseCode)) {
        logger.info("UserSearchService:validateUserPassword backend confirmed valid credentials for: " + username);
        return true;
      }
      logger.warn("UserSearchService:validateUserPassword backend rejected credentials for: "
          + username + ", responseCode=" + responseCode);
      return false;
    } catch (Exception e) {
      logger.error("UserSearchService:validateUserPassword exception for user: " + username + ": " + e.getMessage(), e);
      return false;
    }
  }

  public static Map<String, Object> post(Map<String, Object> requestBody, String uri,
      String authorizationKey) {
    try {
      logger.info("UserSearchService:post: uri = " + uri + ", body = " + requestBody);
      ObjectMapper mapper = new ObjectMapper();
      HttpClientUtil.getInstance();
      String authKey = Constants.BEARER + " " + authorizationKey;
      Map<String, String> headers = new HashMap<>();
      headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
      headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
      if (StringUtils.isNotBlank(authKey)) {
        headers.put(HttpHeaders.AUTHORIZATION, authKey);
      }
      String response = HttpClientUtil.post(uri, mapper.writeValueAsString(requestBody), headers);
      return mapper.readValue(response,
          new TypeReference<Map<String, Object>>() {
          });
    } catch (Exception ex) {
      logger.error("UserSearchService:post: Exception occurred = " + ex);
    }
    return null;
  }
}