package org.sunbird.keycloak.utils;

import org.apache.http.HeaderElement;
import org.apache.http.HeaderElementIterator;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeaderElementIterator;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.HttpResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import org.apache.commons.lang3.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public class HttpClientUtil {

  private static Logger logger = Logger.getLogger(HttpClientUtil.class);
  private static final CloseableHttpClient httpclient;

  static {
      Properties props = new Properties();
      String filePath = new File(Constants.HTTP_CLIENT_CONFIGURATIONS_PATH).getAbsolutePath();
      try (InputStream input = new FileInputStream(filePath)) {
          props.load(input);
      } catch (IOException ex) {
          logger.warn("httpclient.properties not found at " + filePath + ". Using defaults.");
      }

      int maxTotal = Integer.parseInt(props.getProperty("http.maxTotal", "200"));
      int maxPerRoute = Integer.parseInt(props.getProperty("http.maxPerRoute", "150"));
      int connectTimeout = Integer.parseInt(props.getProperty("http.connectTimeout", "5000"));
      int socketTimeout = Integer.parseInt(props.getProperty("http.socketTimeout", "5000"));
      int connectionRequestTimeout = Integer.parseInt(props.getProperty("http.connectionRequestTimeout", "5000"));

      ConnectionKeepAliveStrategy keepAliveStrategy =
        (response, context) -> {
          HeaderElementIterator it =
            new BasicHeaderElementIterator(response.headerIterator(HTTP.CONN_KEEP_ALIVE));
          while (it.hasNext()) {
            HeaderElement he = it.nextElement();
            String param = he.getName();
            String value = he.getValue();
            if (value != null && param.equalsIgnoreCase("timeout")) {
              return Long.parseLong(value) * 1000;
            }
          }
          return 180 * 1000;
        };

      PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
      connectionManager.setMaxTotal(maxTotal);
      connectionManager.setDefaultMaxPerRoute(maxPerRoute);

      RequestConfig requestConfig = RequestConfig.custom()
              .setConnectTimeout(connectTimeout)
              .setSocketTimeout(socketTimeout)
              .setConnectionRequestTimeout(connectionRequestTimeout)
              .build();

      httpclient =
        HttpClients.custom()
          .setConnectionManager(connectionManager)
          .setDefaultRequestConfig(requestConfig)
          .useSystemProperties()
          .setKeepAliveStrategy(keepAliveStrategy)
          .evictExpiredConnections()
          .evictIdleConnections(180, TimeUnit.SECONDS)
          .build();
  }

  private HttpClientUtil() {}

  public static HttpClientUtil getInstance() {
     return new HttpClientUtil(); 
  }

  public static String post(String requestURL, String params, Map<String, String> headers) {
    CloseableHttpResponse response = null;
    try {
      HttpPost httpPost = new HttpPost(requestURL);
      if (null != headers && headers.size() >= 1) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
          httpPost.addHeader(entry.getKey(), entry.getValue());
        }
      }
      StringEntity entity = new StringEntity(params);
      httpPost.setEntity(entity);

      response = httpclient.execute(httpPost);
      int status = response.getStatusLine().getStatusCode();
      if (status >= 200 && status < 300) {
        HttpEntity httpEntity = response.getEntity();
        byte[] bytes = EntityUtils.toByteArray(httpEntity);
        StatusLine sl = response.getStatusLine();
        logger.info(
          "Response from post call : " + sl.getStatusCode() + " - " + sl.getReasonPhrase());
        return new String(bytes);
      } else {
        return "";
      }
    } catch (Exception ex) {
      logger.error("Exception occurred while calling Post method", ex);
      return "";
    } finally {
      if (null != response) {
        try {
          response.close();
        } catch (Exception ex) {
          logger.error("Exception occurred while closing Post response object", ex);
        }
      }
    }
  }

  public static HttpResponse post(Map<String, Object> requestBody, String uri, String authorizationKey) {
    logger.debug("HttpClientUtil: post(map) called");
    try {
      ObjectMapper mapper = new ObjectMapper();
      HttpPost httpPost = new HttpPost(uri);
      logger.debug("HttpClientUtil:post: uri = " + uri);
      String authKey = Constants.BEARER + " " + authorizationKey;
      StringEntity entity = new StringEntity(mapper.writeValueAsString(requestBody));
      logger.debug("HttpClientUtil:post: request entity = " + entity);
      httpPost.setEntity(entity);
      httpPost.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
      httpPost.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
      if (StringUtils.isNotBlank(authKey)) {
        httpPost.setHeader(HttpHeaders.AUTHORIZATION, authKey);
      }
      CloseableHttpResponse response = httpclient.execute(httpPost);
      logger.debug("HttpClientUtil:post: statusCode = " + response.getStatusLine().getStatusCode());
      return response;
    } catch (Exception e) {
      logger.error("HttpClientUtil:post: Exception occurred = " + e);
    }
    return null;
  }
}
