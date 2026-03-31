package org.sunbird.sms.sinch;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.sms.SMSConfigurationUtil;
import org.sunbird.sms.SmsConfigurationConstants;
import org.sunbird.utils.JsonUtil;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;

public class SinchSMSProvider {
    private Logger logger = Logger.getLogger(SinchSMSProvider.class);
    private static SinchSMSProvider smsProvider = null;
    private Map<String, Object> configurations;
    private Map<String, Map<String, String>> messageTypeMap = new HashMap<String, Map<String, String>>();
    private boolean isConfigured;

    /** Shared HTTP connection pool – created once per JVM lifetime. */
    private static final PoolingHttpClientConnectionManager CONNECTION_MANAGER;
    private static final CloseableHttpClient HTTP_CLIENT;

    static {
        CONNECTION_MANAGER = new PoolingHttpClientConnectionManager();
        CONNECTION_MANAGER.setMaxTotal(100);
        CONNECTION_MANAGER.setDefaultMaxPerRoute(20);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(10_000)
                .setSocketTimeout(10_000)
                .setConnectionRequestTimeout(5_000)
                .build();

        HTTP_CLIENT = HttpClients.custom()
                .setConnectionManager(CONNECTION_MANAGER)
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    public static SinchSMSProvider getInstance() {
        if (smsProvider == null) {
            synchronized (SinchSMSProvider.class) {
                if (smsProvider == null) {
                    smsProvider = new SinchSMSProvider();
                    smsProvider.loadConfigurations();
                }
            }
        }
        return smsProvider;
    }

    private void loadConfigurations() {
        String filePath = new File(KeycloakSmsAuthenticatorConstants.SINCH_SMS_PROVIDER_CONFIGURATIONS_PATH)
                .getAbsolutePath();
        logger.info("Configure : filePath - " + filePath);
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
            logger.error("Action:: sendSmsViaSinch - Failed to send OTP SMS, configuration is not proper.");
            return retVal;
        }

        Map<String, String> messageTypeConfig = messageTypeMap.get(smsType);
        if (messageTypeConfig == null) {
            logger.error(String.format(
                    "Action:: sendSmsViaSinch - Failed to send OTP SMS, Message Type configuration not found for name - %s",
                    smsType));
            return retVal;
        }

        String urlStr      = (String) configurations.get(SmsConfigurationConstants.CONF_SMS_GATEWAY_URL);
        String enterpriseId    = (String) configurations.get(SmsConfigurationConstants.SINCH_ENTERPRISE_ID);
        String subEnterpriseId = (String) configurations.get(SmsConfigurationConstants.SINCH_SUB_ENTERPRISE_ID);
        String userId      = (String) configurations.get(SmsConfigurationConstants.SINCH_USER_ID);
        String password    = (String) configurations.get(SmsConfigurationConstants.SINCH_USER_PASSWOD);

        String message = SMSConfigurationUtil.getConfigString(messageTypeConfig,
                SmsConfigurationConstants.CONF_MESSAGE);

        // templateId is used as pusheid in the GET request
        String templateId = SMSConfigurationUtil.getConfigString(messageTypeConfig,
                SmsConfigurationConstants.AMNEX_SMS_TEMPLATE_ID);

        logger.debug(String.format(
                "Action:: sendSmsViaSinch - Sending OTP SMS to MobileNumber: %s, otpKey: %s, otpExpiry: %s",
                mobileNumber, otpKey, otpExpiry));

        long mStartTime = System.currentTimeMillis();
        try {
            if (StringUtils.isNotBlank(urlStr) && StringUtils.isNotBlank(message)
                    && StringUtils.isNotBlank(mobileNumber) && StringUtils.isNotBlank(templateId)
                    && StringUtils.isNotBlank(enterpriseId) && StringUtils.isNotBlank(subEnterpriseId)
                    && StringUtils.isNotBlank(userId) && StringUtils.isNotBlank(password)) {

                mobileNumber = removePlusFromMobileNumber(mobileNumber);
                message = updateParamValues(message, otpKey, otpExpiry);
                logger.debug(String.format(
                        "Action:: sendSmsViaSinch - after removePlusFromMobileNumber; Mobile: %s", mobileNumber));

                String urlEncodedMsg = URLEncoder.encode(message, StandardCharsets.UTF_8.name());

                String getUrl = urlStr
                        + "?enterpriseid=" + URLEncoder.encode(enterpriseId, StandardCharsets.UTF_8.name())
                        + "&subEnterpriseid=" + URLEncoder.encode(subEnterpriseId, StandardCharsets.UTF_8.name())
                        + "&pusheid=" + URLEncoder.encode(userId, StandardCharsets.UTF_8.name())
                        + "&pushepwd=" + URLEncoder.encode(password, StandardCharsets.UTF_8.name())
                        + "&msisdn=" + URLEncoder.encode(mobileNumber, StandardCharsets.UTF_8.name())
                        + "&sender=iGOTKB&tc=1&alert=1"
                        + "&msgtext=" + urlEncodedMsg;

                long startTime = System.currentTimeMillis();
                HttpGet get = new HttpGet(getUrl);
                try (CloseableHttpResponse response = HTTP_CLIENT.execute(get)) {
                    int responseCode = response.getStatusLine().getStatusCode();
                    String responseStr = EntityUtils.toString(response.getEntity());
                    if (responseCode == 200) {
                        logger.info(String.format(
                                "Action:: sendSmsViaSinch - successfully sent OTP SMS, MobileNumber: %s, TimeTaken: %s, ResponseCode: %s",
                                mobileNumber, (System.currentTimeMillis() - startTime), responseCode));
                        retVal = true;
                    } else {
                        logger.error(String.format(
                                "Action:: sendSmsViaSinch - Failed to send OTP SMS, MobileNumber: %s, TimeTaken: %s, ResponseCode: %s, Response Body: %s",
                                mobileNumber, (System.currentTimeMillis() - startTime), responseCode, responseStr));
                    }
                } catch (Exception e) {
                    logger.error(String.format(
                            "Action:: sendSmsViaSinch - Failed to send OTP SMS, Exception while executing GET for MobileNumber: %s, TimeTaken: %s, Exception: %s",
                            mobileNumber, (System.currentTimeMillis() - startTime), e.getMessage()), e);
                }
            } else {
                logger.error(String.format(
                        "Action:: sendSmsViaSinch - Failed to send OTP SMS, Some mandatory parameters are empty. MobileNumber: %s",
                        mobileNumber));
            }
        } catch (Exception e) {
            logger.error(String.format(
                    "Action:: sendSmsViaSinch - Failed to send OTP SMS. MobileNumber: %s, TimeTaken: %s, Exception: %s",
                    mobileNumber, (System.currentTimeMillis() - mStartTime), e.getMessage()), e);
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
