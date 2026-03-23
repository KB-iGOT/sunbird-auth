package org.sunbird.keycloak.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.jboss.logging.Logger;

public class HttpClient {

  private static Logger logger = Logger.getLogger(HttpClient.class);
  private static final CloseableHttpClient SHARED_CLIENT;

  static {
      Properties props = new Properties();
      try (InputStream input = HttpClient.class.getClassLoader().getResourceAsStream("httpclient.properties")) {
          if (input != null) {
              props.load(input);
          } else {
              logger.warn("httpclient.properties not found in classpath. Using defaults.");
          }
      } catch (IOException ex) {
          logger.error("Error reading httpclient.properties", ex);
      }

      int maxTotal = Integer.parseInt(props.getProperty("http.maxTotal", "200"));
      int maxPerRoute = Integer.parseInt(props.getProperty("http.maxPerRoute", "50"));
      int connectTimeout = Integer.parseInt(props.getProperty("http.connectTimeout", "5000"));
      int socketTimeout = Integer.parseInt(props.getProperty("http.socketTimeout", "5000"));
      int connectionRequestTimeout = Integer.parseInt(props.getProperty("http.connectionRequestTimeout", "5000"));

      PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
      cm.setMaxTotal(maxTotal);
      cm.setDefaultMaxPerRoute(maxPerRoute);

      RequestConfig requestConfig = RequestConfig.custom()
              .setConnectTimeout(connectTimeout)
              .setSocketTimeout(socketTimeout)
              .setConnectionRequestTimeout(connectionRequestTimeout)
              .build();

      SHARED_CLIENT = HttpClients.custom()
              .setConnectionManager(cm)
              .setDefaultRequestConfig(requestConfig)
              .evictExpiredConnections()
              .build();
  }

  private HttpClient() {}

  public static HttpResponse post(Map<String, Object> requestBody, String uri,
      String authorizationKey) {
    logger.debug("HttpClient: post called");
    try {
      ObjectMapper mapper = new ObjectMapper();
      HttpPost httpPost = new HttpPost(uri);
      logger.debug("HttpClient:post: uri = " + uri);
      String authKey = Constants.BEARER + " " + authorizationKey;
      StringEntity entity = new StringEntity(mapper.writeValueAsString(requestBody));
      logger.debug("HttpClient:post: request entity = " + entity);
      httpPost.setEntity(entity);
      httpPost.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
      httpPost.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
      if (StringUtils.isNotBlank(authKey)) {
        httpPost.setHeader(HttpHeaders.AUTHORIZATION, authKey);
      }
      CloseableHttpResponse response = SHARED_CLIENT.execute(httpPost);
      logger.debug("HttpClient:post: statusCode = " + response.getStatusLine().getStatusCode());
      return response;
    } catch (Exception e) {
      logger.error("HttpClient:post: Exception occurred = " + e);
    }
    return null;
  }

}
