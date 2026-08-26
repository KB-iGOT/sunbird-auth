package org.sunbird.sms.msg91;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.HttpMethod;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.sms.SmsConfigurationConstants;
import org.sunbird.sms.provider.ISmsProvider;
import org.sunbird.utils.JsonUtil;

import com.amazonaws.util.CollectionUtils;
import com.amazonaws.util.StringUtils;

public class EnhancedMsg91SmsProvider implements ISmsProvider {

	private static Logger logger = Logger.getLogger(EnhancedMsg91SmsProvider.class);

	private static String BASE_URL = "http://api.msg91.com/";
	private static String GET_URL = "api/sendhttp.php?";
	private static String POST_URL = "api/v2/sendsms";
	private static String FLOW_URL = "api/v5/flow";

	private Map<String, String> configurations;

	@Override
	public void configure(Map<String, String> configurations) throws Exception {
		this.configurations = configurations;
		validateConfiguration();
	}

	@Override
	public boolean send(String phoneNumber, String smsText) {
		logger.info("EnhancedMsg91SmsProvider:: send... is Config available ? " + (configurations != null));
		CloseableHttpClient httpClient = HttpClients.createDefault();
		CloseableHttpResponse response = null;
		boolean retValue = false;
		String path = "";
		String httpMethod = configurations.get(SmsConfigurationConstants.CONF_SMS_METHOD_TYPE);
		try {
			switch (httpMethod) {
			case HttpMethod.GET:
				path = getCompletePath(BASE_URL + GET_URL, getConfigParam(SmsConfigurationConstants.CONF_SMS_SENDER),
						configurations.get(SmsConfigurationConstants.CONF_SMS_ROUTE), phoneNumber,
						getConfigParam(SmsConfigurationConstants.CONF_AUTH_KEY),
						configurations.get(SmsConfigurationConstants.CONF_SMS_COUNTRY),
						URLEncoder.encode(smsText, "UTF-8"));

				logger.debug("Msg91SmsProvider -Executing request - " + path);

				HttpGet httpGet = new HttpGet(path);

				response = httpClient.execute(httpGet);

				break;
			case HttpMethod.POST:
				path = BASE_URL + POST_URL;
				logger.debug("Msg91SmsProvider -Executing request - " + path);

				HttpPost httpPost = new HttpPost(path);

				// add content-type headers
				httpPost.setHeader("content-type", "application/json");

				// add authkey header
				httpPost.setHeader("authkey", getConfigParam(SmsConfigurationConstants.CONF_AUTH_KEY));

				List<String> mobileNumbers = new ArrayList<>();
				mobileNumbers.add(phoneNumber);

				// create sms
				Sms sms = new Sms(URLEncoder.encode(smsText, "UTF-8"), mobileNumbers);

				List<Sms> smsList = new ArrayList<>();
				smsList.add(sms);

				// create body
				ProviderDetails providerDetails = new ProviderDetails(
						getConfigParam(SmsConfigurationConstants.CONF_SMS_SENDER),
						configurations.get(SmsConfigurationConstants.CONF_SMS_ROUTE),
						configurations.get(SmsConfigurationConstants.CONF_SMS_COUNTRY), smsList);

				String providerDetailsString = JsonUtil.toJson(providerDetails);

				if (!StringUtils.isNullOrEmpty(providerDetailsString)) {
					logger.debug("Msg91SmsProvider - Body - " + providerDetailsString);
					HttpEntity entity = new ByteArrayEntity(providerDetailsString.getBytes("UTF-8"));
					httpPost.setEntity(entity);
					response = httpClient.execute(httpPost);
				} else {
					retValue = false;
				}
				break;
			case Constants.FLOW_API:
				logger.debug("Inside Flow API");

				path = BASE_URL + FLOW_URL;
				logger.debug("Msg91SmsProvider -Executing request - " + path);

				httpPost = new HttpPost(path);

				// add content-type headers
				httpPost.setHeader("content-type", "application/json");

				// add authkey header
				httpPost.setHeader("authkey", getConfigParam(SmsConfigurationConstants.CONF_AUTH_KEY));
				
				phoneNumber = updateCountryCodeIfZero(phoneNumber, configurations.get(SmsConfigurationConstants.CONF_SMS_COUNTRY));

				Map<String, String> recipient = new HashMap<String, String>();
				recipient.put(Constants.MOBILES, phoneNumber);
				recipient.put(Constants.OTP, smsText);

				Map<String, Object> request = new HashMap<String, Object>();
				request.put(Constants.FLOW_ID, getConfigParam(SmsConfigurationConstants.CONF_SMS_FLOW_ID));
				request.put(Constants.SENDER, getConfigParam(SmsConfigurationConstants.CONF_SMS_SENDER));
				request.put(Constants.RECIPIENTS, Arrays.asList(recipient));

				HttpEntity entity = new StringEntity(JsonUtil.toJson(request));
				httpPost.setEntity(entity);
				response = httpClient.execute(httpPost);
				break;
			default:
				logger.error("Invalid SMS Method Type.");
				return false;
			}

			StatusLine sl = response.getStatusLine();
			response.close();
			if (sl.getStatusCode() != 200) {
				logger.error("SMS code for " + phoneNumber + " could not be sent: " + sl.getStatusCode() + " - "
						+ sl.getReasonPhrase());
			}
			retValue = sl.getStatusCode() == 200;
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
		return retValue;
	}

	private void validateConfiguration() throws Exception {
		// For GET & POST - sender, smsRoute, authKey, country
		// For Flow - sender, flowId, authKey, country
		String httpMethod = configurations.get(SmsConfigurationConstants.CONF_SMS_METHOD_TYPE);

		List<String> mandatoryConfig = Arrays.asList(SmsConfigurationConstants.CONF_AUTH_KEY,
				SmsConfigurationConstants.CONF_SMS_SENDER, SmsConfigurationConstants.CONF_SMS_COUNTRY);

		StringBuilder strBuilder = new StringBuilder("Mandatory Parameter(s) is missing. Params : [");
		List<String> errList = new ArrayList<String>();

		for (String param : mandatoryConfig) {
			if (StringUtils.isNullOrEmpty(configurations.get(param))) {
				errList.add(param);
			}
		}
		if (StringUtils.isNullOrEmpty(httpMethod)) {
			errList.add(SmsConfigurationConstants.CONF_SMS_METHOD_TYPE);
		} else {
			switch (httpMethod) {
			case HttpMethod.GET:
			case HttpMethod.POST:
				if (StringUtils.isNullOrEmpty(configurations.get(SmsConfigurationConstants.CONF_SMS_ROUTE))) {
					errList.add(SmsConfigurationConstants.CONF_SMS_ROUTE);
				}
				break;

			case Constants.FLOW_API:
				if (StringUtils.isNullOrEmpty(configurations.get(SmsConfigurationConstants.CONF_SMS_FLOW_ID))) {
					errList.add(SmsConfigurationConstants.CONF_SMS_FLOW_ID);
				}
				break;
			}
		}
		if (!CollectionUtils.isNullOrEmpty(errList)) {
			strBuilder.append(errList.toString()).append("]");
			logger.error(strBuilder.toString());
			throw new Exception(strBuilder.toString());
		}
		logger.info("EnhancedMsg91SmsProvider:: config validation successful.");
	}

	private String getConfigParam(String param) {
		return configurations.get(param);
	}

	private String getCompletePath(String gateWayUrl, String sender, String smsRoute, String mobileNumber,
			String authKey, String country, String smsText) {
		String completeUrl = gateWayUrl + "sender=" + sender + "&route=" + smsRoute + "&mobiles=" + mobileNumber
				+ "&authkey=" + authKey + "&country=" + country + "&message=" + smsText;
		return completeUrl;
	}

	private String updateCountryCodeIfZero(String mobileNumber, String countryCode) {
		if (mobileNumber.startsWith(KeycloakSmsAuthenticatorConstants.DEFAULT_COUNTRY_CODE)) {
			mobileNumber = KeycloakSmsAuthenticatorConstants.COUNTRY_CODE + mobileNumber.substring(1);
		} else if (!mobileNumber.startsWith(countryCode)) {
			mobileNumber = countryCode + mobileNumber;
		}

		return mobileNumber;
	}
}
