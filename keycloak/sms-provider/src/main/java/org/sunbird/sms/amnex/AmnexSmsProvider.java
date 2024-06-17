package org.sunbird.sms.amnex;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.sms.SMSConfigurationUtil;
import org.sunbird.sms.SmsConfigurationConstants;
import org.sunbird.utils.JsonUtil;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class AmnexSmsProvider {
    private Logger logger = Logger.getLogger(AmnexSmsProvider.class);
    private static AmnexSmsProvider amnexSmsProvider = null;
    private Map<String, Object> configurations;
    private Map<String, Map<String, String>> messageTypeMap = new HashMap<String, Map<String, String>>();
    private boolean isConfigured;

    public static AmnexSmsProvider getInstance() {
        if (amnexSmsProvider == null) {
            synchronized (AmnexSmsProvider.class) {
                if (amnexSmsProvider == null) {
                    amnexSmsProvider = new AmnexSmsProvider();
                    amnexSmsProvider.configure();
                }
            }
        }
        return amnexSmsProvider;
    }

    public void configure() {
        String filePath = new File(KeycloakSmsAuthenticatorConstants.AMNEX_SMS_PROVIDER_CONFIGURATIONS_PATH)
                .getAbsolutePath();
        logger.info("AmnexSmsProvider@configure : filePath - " + filePath);
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
            logger.error("SMS is not configured properly. Failed to send SMS");
            return retVal;
        }

        Map<String, String> messageTypeConfig = messageTypeMap.get(smsType);
        if (messageTypeConfig == null) {
            logger.error(String.format("Failed to find SMS Message Type configuration for name - %s", smsType));
        }

        String message = SMSConfigurationUtil.getConfigString(messageTypeConfig,
                SmsConfigurationConstants.CONF_MESSAGE);

        String templateId = SMSConfigurationUtil.getConfigString(messageTypeConfig,
                SmsConfigurationConstants.AMNEX_SMS_TEMPLATE_ID);

        String campaignName = (String) configurations.get(SmsConfigurationConstants.AMNEX_SMS_CAMPAIGN_NAME);

        String authKey = (String) configurations.get(SmsConfigurationConstants.CONF_AUTH_KEY);

        String sender = (String) configurations.get(SmsConfigurationConstants.CONF_SMS_SENDER);

        String urlStr = (String) configurations.get(SmsConfigurationConstants.CONF_SMS_GATEWAY_URL);

        String route = (String) configurations.get(SmsConfigurationConstants.CONF_SMS_ROUTE);

        logger.debug(String.format("AmnexSmsProvider@Sending sms to mobileNumber %s, otpKey: %s, otpExpiry: %s",
                mobileNumber, otpKey, otpExpiry));

        // Send an SMS
        try {
            if (StringUtils.isNotBlank(campaignName) && StringUtils.isNotBlank(message)
                    && StringUtils.isNotBlank(mobileNumber) && StringUtils.isNotBlank(templateId)
                    && StringUtils.isNotBlank(authKey) && StringUtils.isNotBlank(sender)
                    && StringUtils.isNotBlank(urlStr) && StringUtils.isNotBlank(route)) {
                mobileNumber = removePlusFromMobileNumber(mobileNumber);
                message = updateParamValues(message, otpKey, otpExpiry);
                logger.debug("AmnexSmsProvider - after removePlusFromMobileNumber " + mobileNumber);

                JsonObject jMessage = new JsonObject();
                jMessage.addProperty("msgdata", message);
                jMessage.addProperty("Template_ID", templateId);
                jMessage.addProperty("coding", "1");
                jMessage.addProperty("flash_message", 1);
                jMessage.addProperty("scheduleTime", "");

                // Create the JSON object for the main payload
                JsonObject jsonInput = new JsonObject();
                jsonInput.addProperty("campaign_name", campaignName);
                jsonInput.addProperty("auth_key", authKey);
                jsonInput.addProperty("receivers", mobileNumber);
                jsonInput.addProperty("sender", sender);
                jsonInput.addProperty("route", route);
                jsonInput.add("message", jMessage);

                Gson gson = new Gson();
                String jsonInputString = gson.toJson(jsonInput);

                try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                    HttpPost post = new HttpPost(urlStr);
                    post.setHeader("Content-Type", "application/json");
                    post.setEntity(new StringEntity(jsonInputString));

                    try (CloseableHttpResponse response = httpClient.execute(post)) {
                        int responseCode = response.getStatusLine().getStatusCode();
                        logger.info("POST Response Code: " + responseCode + ", response body: " + response.getEntity());
                        if (responseCode == 200) {
                            retVal = true;
                            logger.info("POST request successful.");
                        } else {
                            logger.info("POST request failed.");
                        }
                    } catch (Exception e) {
                        logger.error("Failed to send SMS to mobile: " + mobileNumber + ", Exception: ", e);
                    }
                } catch (Exception e) {
                    logger.error("Failed to create httpClient. Exception: ", e);
                }
            } else {
                logger.error("AmnexSmsProvider - Some mandatory parameters are empty!");
            }
        } catch (Exception e) {
            logger.error(e);
        }
        return retVal;
    }

    private String removePlusFromMobileNumber(String mobileNumber) {
        logger.debug("AmnexSmsProvider - removePlusFromMobileNumber " + mobileNumber);

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
