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

import java.util.Map;
import java.util.concurrent.TimeUnit;

public class HttpClientUtil {

  private static Logger logger = Logger.getLogger(HttpClientUtil.class);
  private static CloseableHttpClient httpclient = null;
  private static HttpClientUtil httpClientUtil;

  private HttpClientUtil() {
    ConnectionKeepAliveStrategy keepAliveStrategy =
      (response, context) -> {
        logger.info("ConnectionKeepAliveStrategy called");
        HeaderElementIterator it =
          new BasicHeaderElementIterator(response.headerIterator(HTTP.CONN_KEEP_ALIVE));
        while (it.hasNext()) {
            logger.info("Iterating through keep alive headers");
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
    logger.info("PoolingHttpClientConnectionManager called");
    connectionManager.setMaxTotal(200);
    connectionManager.setDefaultMaxPerRoute(150);
    connectionManager.closeIdleConnections(180, TimeUnit.SECONDS);
    httpclient =
      HttpClients.custom()
        .setConnectionManager(connectionManager)
        .useSystemProperties()
        .setKeepAliveStrategy(keepAliveStrategy)
        .build();
    logger.info("HttpClientUtil initialized");
  }

  public static HttpClientUtil getInstance() {
    if (httpClientUtil == null) {
        logger.info("HttpClientUtil instance is null, creating new instance");
      synchronized (HttpClientUtil.class) {
        if (httpClientUtil == null) {
            logger.info("HttpClientUtil instance is still null, creating new instance inside synchronized block");
          httpClientUtil = new HttpClientUtil();
        }
      }
    }
    logger.info("Returning HttpClientUtil instance");
    return httpClientUtil;
  }

  public static String post(String requestURL, String params, Map<String, String> headers) {
      logger.info("HttpClientUtil: post method called with URL: " + requestURL);
    CloseableHttpResponse response = null;
    try {
        logger.info("Creating HttpPost request");
      HttpPost httpPost = new HttpPost(requestURL);
      if (null != headers && headers.size() >= 1) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
          httpPost.addHeader(entry.getKey(), entry.getValue());
        }
      }
      StringEntity entity = new StringEntity(params);
      logger.info("Setting entity for HttpPost request");
      httpPost.setEntity(entity);

      response = httpclient.execute(httpPost);
      int status = response.getStatusLine().getStatusCode();
      if (status >= 200 && status < 300) {
          logger.info("Post call successful with status code: " + status);
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
        logger.info("Exception occurred while making Post call");
      logger.error("Exception occurred while calling Post method", ex);
      return "";
    } finally {
      if (null != response) {
        try {
            logger.info("Closing Post response object");
          response.close();
        } catch (Exception ex) {
            logger.info("Exception occurred while closing Post response object");
          logger.error("Exception occurred while closing Post response object", ex);
        }
      }
    }
  }

}
