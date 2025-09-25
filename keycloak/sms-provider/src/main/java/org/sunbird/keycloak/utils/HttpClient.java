package org.sunbird.keycloak.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;

public class HttpClient {

  private static Logger logger = Logger.getLogger(HttpClient.class);

  private HttpClient() {}

  public static HttpResponse post(Map<String, Object> requestBody, String uri,
      String authorizationKey) {
      logger.info("HttpClient: post method called with uri: "+uri);
    logger.debug("HttpClient: post called");
    try (CloseableHttpClient client = HttpClients.createDefault()) {
        logger.info("HttpClient: post: creating http client");
      ObjectMapper mapper = new ObjectMapper();
      HttpPost httpPost = new HttpPost(uri);
      logger.debug("HttpClient:post: uri = " + uri);
      String authKey = Constants.BEARER + " " + authorizationKey;
      StringEntity entity = new StringEntity(mapper.writeValueAsString(requestBody));
      logger.debug("HttpClient:post: request entity = " + entity);
      logger.info("HttpClient: post: setting headers and entity" + entity) ;
      httpPost.setEntity(entity);
      httpPost.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
      httpPost.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
      if (StringUtils.isNotBlank(authKey)) {
        httpPost.setHeader(HttpHeaders.AUTHORIZATION, authKey);
      }
      CloseableHttpResponse response = client.execute(httpPost);
      logger.info("HttpClient: post: executed http post");
      logger.debug("HttpClient:post: statusCode = " + response.getStatusLine().getStatusCode());
      return response;
    } catch (Exception e) {
        logger.info("HttpClient: post: exception occurred");
      logger.error("HttpClient:post: Exception occurred = " + e);
    }
    return null;
  }

}
