package org.sunbird.keycloak.storage.spi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.sunbird.keycloak.utils.Constants;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sunbird.keycloak.utils.HttpClientUtil;

public class UserSearchService {

  private static Logger logger = Logger.getLogger(UserSearchService.class);

  private UserSearchService() {}

  @SuppressWarnings({"unchecked"})
  public static List<User> getUserByKey(String key, String value) {
    Map<String, Object> userRequest = new HashMap<>();
    Map<String, Object> request = new HashMap<>();
    request.put("key",key.toLowerCase());
    request.put("value", value);
    request.put("fields", Arrays.asList("email","firstName","lastName","id","phone","userName","countryCode","status","rootorgid","roles","channel","profileDetails"));
    userRequest.put("request", request);
    String userLookupUrl = System.getenv("sunbird_user_service_base_url")+"/private/user/v1/lookup";
    Map<String, Object> resMap =
      post(userRequest, userLookupUrl, System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION));
    logger.info("UserSearchService:getUserByKey responseMap "+resMap);
    Map<String, Object> result = null;
    List<Map<String, Object>> content = null;
    if (null != resMap) {
      result = (Map<String, Object>) resMap.get("result");
    }
    if (null != result) {
      content = (List<Map<String, Object>>) result.get("response");
    }
    if (null != content) {
      List<User> userList = new ArrayList<>();
      if (!content.isEmpty()) {
        content.forEach(userMap -> {
          if (null != userMap) {
            userList.add(createUser(userMap));
          }
        });
      }
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
    user.setOrgName((String) userMap.get("channel"));
    extractProfessionalDetails(userMap.get("profileDetails"), user);
    if ( null != userMap.get("roles") && ((List)userMap.get("roles")).size() > 0) {
      user.setRoles((List<String>) userMap.get("roles"));
    }
    else{
      List roles = new ArrayList();
      roles.add("");
      user.setRoles(roles);
    }
    if ( null != userMap.get("status") && ((Integer)userMap.get("status")) == 0) {
      user.setEnabled(false);
    } else {
      user.setEnabled(true);
    }
    return user;
  }

  @SuppressWarnings({"unchecked"})
  private static void extractProfessionalDetails(Object profileDetailsObj, User user) {
    if (profileDetailsObj == null) {
      return;
    }

    try {
      Map<String, Object> profileDetailsMap;
      ObjectMapper mapper = new ObjectMapper();
      if (profileDetailsObj instanceof String) {
        profileDetailsMap = mapper.readValue((String) profileDetailsObj,
          new TypeReference<Map<String, Object>>() {});
      } else if (profileDetailsObj instanceof Map) {
        profileDetailsMap = (Map<String, Object>) profileDetailsObj;
      } else {
        return;
      }

      Object professionalDetailsObj = profileDetailsMap.get(Constants.PROFESIONAL_DETAILS);
      if (!(professionalDetailsObj instanceof List)) {
        return;
      }

      List<Map<String, Object>> professionalDetails = (List<Map<String, Object>>) professionalDetailsObj;
      if (professionalDetails.isEmpty() || professionalDetails.get(0) == null) {
        return;
      }

      Map<String, Object> firstProfessionalDetail = professionalDetails.get(0);
      user.setDesignation((String) firstProfessionalDetail.get(Constants.DESIGNATION));
      user.setGroup((String) firstProfessionalDetail.get(Constants.GROUP));
    } catch (Exception ex) {
      logger.warn("UserSearchService:extractProfessionalDetails: failed to parse profileDetails", ex);
    }
  }

  public static Map<String, Object> post(Map<String, Object> requestBody, String uri,
                                         String authorizationKey) {
    try {
      logger.info("UserSearchService:post: uri = " + uri+ ", body = "+requestBody);
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
        new TypeReference<Map<String, Object>>() {});
    }catch (Exception ex) {
      logger.error("UserSearchService:post: Exception occurred = " + ex);
    }
    return null;
  }
}
