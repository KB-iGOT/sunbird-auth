package org.sunbird.sms.nic;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
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

public class NicSmsProvider {
	private Logger logger = Logger.getLogger(NicSmsProvider.class);
	private static NicSmsProvider nicSmsProvider = null;
	private Map<String, Object> configurations;
	private Map<String, Map<String, String>> messageTypeMap = new HashMap<String, Map<String, String>>();
	private boolean isConfigured;

	public static NicSmsProvider getInstance() {
		if (nicSmsProvider == null) {
			synchronized (NicSmsProvider.class) {
				if (nicSmsProvider == null) {
					nicSmsProvider = new NicSmsProvider();
					nicSmsProvider.configure();
				}
			}
		}
		return nicSmsProvider;
	}

	public void configure() {
		String filePath = new File(KeycloakSmsAuthenticatorConstants.NIC_SMS_PROVIDER_CONFIGURATIONS_PATH)
				.getAbsolutePath();
		logger.info("PasswordAndOtpAuthenticator@sendSmsCode : filePath - " + filePath);
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

	public boolean send(String phoneNumber, String smsText) {
		return false;
	}

	public boolean send(String mobileNumber, String otpKey, String otpExpiry, String smsType) {
		if (!isConfigured) {
			logger.error("SMS is not configured properly. Failed to send SMS");
			return false;
		}

		Map<String, String> messageTypeConfig = messageTypeMap.get(smsType);
		if (messageTypeConfig == null) {
			logger.error(String.format("Failed to find SMS Message Type configuration for name - %s", smsType));
		}

		String userName = SMSConfigurationUtil.getConfigString(messageTypeConfig,
				SmsConfigurationConstants.CONF_USER_NAME);

		String password = SMSConfigurationUtil.getConfigString(messageTypeConfig,
				SmsConfigurationConstants.CONF_PASSWROD);

		String message = SMSConfigurationUtil.getConfigString(messageTypeConfig,
				SmsConfigurationConstants.CONF_MESSAGE);

		String dltEntityId = SMSConfigurationUtil.getConfigString(messageTypeConfig,
				SmsConfigurationConstants.CONF_DLT_ENTITY_ID);

		String dltTemplateId = SMSConfigurationUtil.getConfigString(messageTypeConfig,
				SmsConfigurationConstants.CONF_DLT_TEMPLATE_ID);

		String country = (String) configurations.get(SmsConfigurationConstants.CONF_COUNTRY);

		String senderId = (String) configurations.get(SmsConfigurationConstants.CONF_SENDER_ID);

		String url = (String) configurations.get(SmsConfigurationConstants.CONF_SMS_GATEWAY_URL);

		logger.debug(String.format("NicSmsProvider@Sending sms to mobileNumber %s, otpKey: %s, otpExpiry: %s",
				mobileNumber, otpKey, otpExpiry));

		// Send an SMS
		CloseableHttpClient httpClient = null;
		try {
			httpClient = HttpClients.createDefault();
			String path = null;
			if (StringUtils.isNotBlank(userName) && StringUtils.isNotBlank(password)
					&& StringUtils.isNotBlank(mobileNumber) && StringUtils.isNotBlank(message)
					&& StringUtils.isNotBlank(dltEntityId) && StringUtils.isNotBlank(dltTemplateId)
					&& StringUtils.isNotBlank(country) && StringUtils.isNotBlank(otpKey)
					&& StringUtils.isNotBlank(otpExpiry) && StringUtils.isNotBlank(senderId)
					&& StringUtils.isNotBlank(url)) {
				mobileNumber = removePlusFromMobileNumber(mobileNumber);
				mobileNumber = addCountryCodeInMobileNumber(mobileNumber, country);
				message = updateParamValues(message, otpKey, otpExpiry);
				logger.debug("NicSmsProvider - after removePlusFromMobileNumber " + mobileNumber);
				path = getCompletePath(url, userName, URLEncoder.encode(password, Constants.UTF_8), mobileNumber,
						URLEncoder.encode(message, Constants.UTF_8), dltEntityId, dltTemplateId, senderId);

				logger.debug("NicSmsProvider -Executing request - " + path);

				HttpGet httpGet = new HttpGet(path);

				CloseableHttpResponse response = httpClient.execute(httpGet);
				StatusLine sl = response.getStatusLine();
				response.close();
				if (sl.getStatusCode() != 200) {
					logger.error("SMS code for " + mobileNumber + " could not be sent: " + sl.getStatusCode() + " - "
							+ sl.getReasonPhrase());
				}
				return sl.getStatusCode() == 200;
			} else {
				logger.error("NicSmsProvider - Some mandatory parameters are empty!");
			}
		} catch (IOException e) {
			logger.error(e);
		} finally {
			if (httpClient != null) {
				try {
					httpClient.close();
				} catch (IOException ignore) {
					// Ignore ...
				}
			}
		}
		return false;
	}

	private String removePlusFromMobileNumber(String mobileNumber) {
		logger.debug("NicSmsProvider - removePlusFromMobileNumber " + mobileNumber);

		if (mobileNumber.startsWith("+")) {
			return mobileNumber.substring(1);
		}
		return mobileNumber;
	}

	private String addCountryCodeInMobileNumber(String mobileNumber, String countryCode) {
		if (mobileNumber.length() == 10) {
			return countryCode + mobileNumber;
		} else if (mobileNumber.startsWith(countryCode)) {
			return mobileNumber;
		} else {
			return mobileNumber;
		}
	}

	private String getCompletePath(String gateWayUrl, String userName, String password, String mobileNumber,
			String message, String dltEntityId, String dltTemplateId, String senderId) {
		StringBuilder strBuilder = new StringBuilder(gateWayUrl);
		strBuilder.append("username=").append(userName);
		strBuilder.append("&pin=").append(password);
		strBuilder.append("&mnumber=").append(mobileNumber);
		strBuilder.append("&message=").append(message);
		strBuilder.append("&dlt_entity_id=").append(dltEntityId);
		strBuilder.append("&dlt_template_id=").append(dltTemplateId);
		strBuilder.append("&signature=").append(senderId);

		return strBuilder.toString();
	}

	private String updateParamValues(String message, String smsOtp, String smsExpiry) {
		message = message.replace("$otpKey", smsOtp);
		return message.replace("$otpExpiry", smsExpiry);
	}
}
