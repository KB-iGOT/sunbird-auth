package org.sunbird.sms.netcore;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.sms.SMSConfigurationUtil;
import org.sunbird.sms.SmsConfigurationConstants;
import org.sunbird.sms.amnex.AmnexSmsProvider;
import org.sunbird.utils.JsonUtil;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;

public class NetCoreSMSProvider {
    private Logger logger = Logger.getLogger(AmnexSmsProvider.class);
    private static NetCoreSMSProvider netCoreSmsProvider = null;
    private Map<String, Object> configurations;
    private Map<String, Map<String, String>> messageTypeMap = new HashMap<String, Map<String, String>>();
    private boolean isConfigured;
    private CloseableHttpClient httpClient;

    public static NetCoreSMSProvider getInstance() {
        if (netCoreSmsProvider == null) {
            synchronized (NetCoreSMSProvider.class) {
                if (netCoreSmsProvider == null) {
                    netCoreSmsProvider = new NetCoreSMSProvider();
                    netCoreSmsProvider.configure();
                }
            }
        }
        return netCoreSmsProvider;
    }

    public void configure() {
        Properties props = new Properties();
        String httpPropPath = new File(org.sunbird.keycloak.utils.Constants.HTTP_CLIENT_CONFIGURATIONS_PATH)
                .getAbsolutePath();
        try (InputStream input = new java.io.FileInputStream(httpPropPath)) {
            props.load(input);
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
                .setConnectTimeout(connectTimeout).setSocketTimeout(socketTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout).build();
        this.httpClient = HttpClients.custom().setConnectionManager(cm)
                .setDefaultRequestConfig(requestConfig).evictExpiredConnections().build();

        String filePath = new File(KeycloakSmsAuthenticatorConstants.NETCORE_SMS_PROVIDER_CONFIGURATIONS_PATH)
                .getAbsolutePath();
        logger.info("NetCoreSMSProvider@configure : filePath - " + filePath);
        this.configurations = JsonUtil.readObjectFromJson(filePath);
        ObjectMapper mapper = new ObjectMapper();
        List<Map<String, String>> mapList = null;
        try {
            CollectionType collectionList = mapper.getTypeFactory().constructCollectionType(ArrayList.class,
                    HashMap.class);
            mapList = mapper.readValue(
                    mapper.writeValueAsString(configurations.get(SmsConfigurationConstants.NIC_OTP_MESSAGE_TYPES)),
                    collectionList);
            for (Map<String, String> map : mapList) {
                String typeName = map.get(Constants.NAME);
                if (!messageTypeMap.containsKey(typeName)) {
                    messageTypeMap.put(typeName, map);
                }
            }
            isConfigured = true;
        } catch (Exception e) {
            logger.error("Failed to configure", e);
        }
    }

    public boolean send(String mobileNumber, String otpKey, String otpExpiry, String smsType) {
        boolean retVal = false;
        if (!isConfigured) {
            logger.error("Action:: sendSmsViaNetCore - Failed to send OTP SMS, configuration is not proper.");
            return retVal;
        }

        Map<String, String> messageTypeConfig = messageTypeMap.get(smsType);
        if (messageTypeConfig == null) {
            logger.error(String.format(
                    "Action:: sendSmsViaNetCore - Failed to send OTP SMS, Message Type configuration not found for name - %s",
                    smsType));
        }

        String urlStr = (String) configurations.get(SmsConfigurationConstants.CONF_SMS_GATEWAY_URL);
        String feedId = (String) configurations.get(SmsConfigurationConstants.NETCORE_SMS_FEEDID);
        String username = (String) configurations.get(SmsConfigurationConstants.CONF_USER_NAME);
        String password = (String) configurations.get(SmsConfigurationConstants.CONF_PASSWROD);
        String shortVal = (String) configurations.get(Constants.SHORT);
        String asyncVal = (String) configurations.get(Constants.ASYNC);

        String message = SMSConfigurationUtil.getConfigString(messageTypeConfig,
                SmsConfigurationConstants.CONF_MESSAGE);

        String templateId = SMSConfigurationUtil.getConfigString(messageTypeConfig,
                SmsConfigurationConstants.AMNEX_SMS_TEMPLATE_ID);

        logger.debug(
                String.format(
                        "Action:: sendSmsViaNetCore - Sending OTP SMS to mobileNumber %s, otpKey: %s, otpExpiry: %s",
                        mobileNumber, otpKey, otpExpiry));

        // Send an SMS
        try {
            if (StringUtils.isNotBlank(urlStr) && StringUtils.isNotBlank(message)
                    && StringUtils.isNotBlank(mobileNumber) && StringUtils.isNotBlank(templateId)
                    && StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)
                    && StringUtils.isNotBlank(feedId) && StringUtils.isNotBlank(shortVal)
                    && StringUtils.isNotBlank(asyncVal)) {
                mobileNumber = removePlusFromMobileNumber(mobileNumber);
                message = updateParamValues(message, otpKey, otpExpiry);
                logger.debug("Action:: sendSmsViaNetCore - after removePlusFromMobileNumber " + mobileNumber);

                HttpPost post = new HttpPost(urlStr);
                post.setHeader("Content-Type", "application/x-www-form-urlencoded");

                List<NameValuePair> params = new ArrayList<>();
                params.add(new BasicNameValuePair(SmsConfigurationConstants.NETCORE_SMS_FEEDID, feedId));
                params.add(new BasicNameValuePair(SmsConfigurationConstants.CONF_USER_NAME, username));
                params.add(new BasicNameValuePair(SmsConfigurationConstants.CONF_PASSWROD, password));
                params.add(new BasicNameValuePair(Constants.TO, mobileNumber));
                params.add(new BasicNameValuePair(Constants.TEXT, message));
                params.add(new BasicNameValuePair(Constants.TEMPLATE_ID, templateId));
                params.add(new BasicNameValuePair(Constants.SHORT, "0"));
                params.add(new BasicNameValuePair(Constants.ASYNC, "0"));

                post.setEntity(new UrlEncodedFormEntity(params));

                long startTime = System.currentTimeMillis();
                try (CloseableHttpResponse response = this.httpClient.execute(post)) {
                    int responseCode = response.getStatusLine().getStatusCode();
                    String responseStr = EntityUtils.toString(response.getEntity());
                    if (responseCode == 200) {
                        logger.info(String.format(
                                "Action:: sendSmsViaNetCore - successfully sent OTP SMS, Mobile: %s, TimeTaken: %s",
                                mobileNumber, (System.currentTimeMillis() - startTime)));
                        retVal = true;
                    } else {
                        logger.error(String.format(
                                "Action:: sendSmsViaNetCore - Failed to send OTP SMS, Mobile: %s, ResponseCode: %s, Response Body: %s",
                                mobileNumber, responseCode, responseStr));
                    }
                } catch (Exception e) {
                    logger.error(String.format(
                            "Action:: sendSmsViaNetCore - Failed to send OTP SMS, Exception while sending SMS to mobile: %s, TimeTaken: %s, Exception: %s",
                            mobileNumber, (System.currentTimeMillis() - startTime), e.getMessage()), e);
                }
            } else {
                logger.error(
                        "Action:: sendSmsViaNetCore - Failed to send OTP SMS, Some mandatory parameters are empty!");
            }
        } catch (Exception e) {
            logger.error("Action:: sendSmsViaNetCore - Failed to send OTP SMS, Exception: ", e);
        }
        return retVal;
    }

    private String removePlusFromMobileNumber(String mobileNumber) {
        logger.debug("NetCoreSMSProvider - removePlusFromMobileNumber " + mobileNumber);

        if (mobileNumber.startsWith("+")) {
            return mobileNumber.substring(1);
        }
        return mobileNumber;
    }

    private String updateParamValues(String message, String smsOtp, String smsExpiry) {
        message = message.replace("$otpKey", smsOtp);
        return message.replace("$otpExpiry", smsExpiry);
    }
}
