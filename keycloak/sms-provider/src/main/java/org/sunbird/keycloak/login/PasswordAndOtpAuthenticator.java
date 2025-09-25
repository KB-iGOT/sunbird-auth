package org.sunbird.keycloak.login;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorUtil;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.keycloak.utils.HttpClient;
import org.sunbird.keycloak.utils.SunbirdModelUtils;
import org.sunbird.sms.SmsConfigurationConstants;
import org.sunbird.sms.amnex.AmnexSmsProvider;
import org.sunbird.sms.netcore.NetCoreSMSProvider;
import org.sunbird.sms.nic.NicSmsProvider;

import com.amazonaws.util.CollectionUtils;

public class PasswordAndOtpAuthenticator extends AbstractUsernameFormAuthenticator {

	Logger logger = Logger.getLogger(PasswordAndOtpAuthenticator.class);
	private static final SecureRandom random = new SecureRandom();

	private enum CODE_STATUS {
		VALID, INVALID, EXPIRED
	}

	/**
	 * This page is called when UI calls
	 * "/realms/sunbird/protocol/openid-connect/auth" API.
	 */
	@Override
	public void authenticate(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::authenticate called");
		String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        if (StringUtils.isBlank(secretKey)) {
			// Generate the secret key
			secretKey = generateSecretKey();
			logger.info("Generated new secret key.");
		}
		String flagPage = getValue(context, Constants.FLAG_PAGE);
		logger.debug("OtpSmsFormAuthenticator::authenticate:: " + flagPage + ", keyValue: " + secretKey);
		logger.info("Redirect URI: " + context.getAuthenticationSession().getRedirectUri());
		// Store the secret key as an authentication session note
		context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, secretKey);

		LoginFormsProvider formsProvider = context.form();
        logger.info("Setting secret key in form attribute");
		formsProvider.setAttribute(Constants.SECRET_KEY, secretKey);
		if(context.getAuthenticationSession().getRedirectUri().contains(Constants.EC_LOGIN)){
			logger.info("loading ec login page");
			context.challenge(formsProvider.createForm(Constants.EC_LOGIN_PAGE));
		}else{
			logger.info("loading login page");
		    context.challenge(formsProvider.createForm(Constants.LOGIN_PAGE));
		}
	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	/**
	 * This method is called when UI calls
	 * "/realms/sunbird/login-actions/authenticate" API
	 */
	@Override
	public void action(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::action called");
		MultivaluedMap<String, String> qParamMap = context.getHttpRequest().getUri().getQueryParameters(false);
        logger.info("Query Param Map: " + qParamMap);
		Iterator<Entry<String, List<String>>> itr = qParamMap.entrySet().iterator();
        logger.info("Iterating through query parameters:");
		while (itr.hasNext()) {
			Entry<String, List<String>> entry = itr.next();
			logger.debug(String.format("		query: key: %s, value: %s", entry.getKey(), entry.getValue()));
            logger.info(String.format("		query: key: %s, value: %s", entry.getKey(), entry.getValue()));
		}

		String flagPage = getValue(context, Constants.FLAG_PAGE);
		logger.info("OtpSmsFormAuthenticator::action:: " + flagPage);
		switch (flagPage) {
			case Constants.FLAG_OTP_PAGE:
				authenticateOtp(context);
				break;
			case Constants.FLAG_OTP_RESEND_PAGE:
				resendOtp(context);
				break;
			case Constants.FLAG_LOGIN_PAGE:
				sendOtp(context, qParamMap.getFirst(Constants.REDIRECT_URI_KEY));
				break;
			case Constants.FLAG_LOGIN_WITH_PASS:
				if (!validateForm(context, context.getHttpRequest().getDecodedFormParameters())) {
					goErrorPage(context, "Invalid credentials!");
				} else {
					logger.info("Validation of username + password is successful... setting redirect_uri with "
							+ qParamMap.getFirst(Constants.REDIRECT_URI_KEY));
					context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI,
							qParamMap.getFirst(Constants.REDIRECT_URI_KEY));
					context.success();
				}
				break;
			default:
				authenticate(context);
				break;
		}
	}

	private String getValue(AuthenticationFlowContext context, String key) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.info("Form Data: " + formData);
		String value = formData.getFirst(key);
		if (null == value) {
			value = "";
		}
		return value;
	}

	private void authenticateOtp(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::authenticateOtp called");
		CODE_STATUS status = validateCode(context);
		if (status == CODE_STATUS.VALID) {
			logger.info("Validation of username + password is successful... ");
			context.getAuthenticationSession().removeAuthNote(Constants.SESSION_OTP_CODE);
			context.success();
		} else if (status == CODE_STATUS.EXPIRED) {
            logger.info("OTP code is expired.");
			goErrorPage(context, Constants.PAGE_INPUT_OTP, Constants.OTP_EXPIRED);
		} else {
            logger.info("Invalid OTP entered.");
			goErrorPage(context, Constants.PAGE_INPUT_OTP, Constants.INVALID_OTP_ENTERED);
		}
	}

	private void goErrorPage(AuthenticationFlowContext context, String message) {
        logger.info("OtpSmsFormAuthenticator::goErrorPage called");
		String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
		if (StringUtils.isBlank(secretKey)) {
			// Generate the secret key
			secretKey = generateSecretKey();
			logger.info("Generated new secret key.");
		}
		
		logger.debug("OtpSmsFormAuthenticator::goErrorPage: message: " + message + ", keyValue: " + secretKey);
        logger.info("Redirect URI: " + context.getAuthenticationSession().getRedirectUri());
		// Store the secret key as an authentication session note
		context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, secretKey);
		LoginFormsProvider formsProvider = context.form();
		formsProvider.setAttribute(Constants.SECRET_KEY, secretKey);
		String error = context.getEvent().getEvent().getError();
		String errMsg = "Internal Server Error!";
        logger.info("Error from event: " + error);
		switch (error) {
			case Errors.INVALID_USER_CREDENTIALS:
                logger.info("Invalid user credentials.");
				errMsg = "Invalid credentials!";
				Response invalidCredsRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, invalidCredsRes);
				break;
			case Errors.USER_NOT_FOUND:
                logger.info("User not found.");
				errMsg = "Invalid user details.";
				Response invalidUserRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
				context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, invalidUserRes);
				break;
			case Errors.USER_DISABLED:
                logger.info("User account is disabled.");
				errMsg = "User account is disabled.";
				Response userDisabledRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
				context.failureChallenge(AuthenticationFlowError.USER_DISABLED, userDisabledRes);
				break;
			case Errors.USER_TEMPORARILY_DISABLED:
                logger.info("User account is disabled temporarily.");
				errMsg = "User account is disabled temporarily.";
				Response tempDisabledRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
				context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, tempDisabledRes);
				break;
			case Errors.DIFFERENT_USER_AUTHENTICATED:
                logger.info("Different user authenticated in the same session.");
				errMsg = "Authentication Error! Please enter your credentials again.";
				Response diffUsersFoundRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
				context.failureChallenge(AuthenticationFlowError.USER_CONFLICT, diffUsersFoundRes);
				break;
			case Errors.EMAIL_IN_USE:
			case Errors.USERNAME_IN_USE:
			default:
                logger.info("Internal server error.");
				Response internalErrorRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, internalErrorRes);
				break;
		}
		context.getEvent().error(errMsg);
		context.clearUser();
	}

	private void goErrorPage(AuthenticationFlowContext context, String page, String message) {
		logger.info("OtpSmsFormAuthenticator::goErrorPage: message: " + message + ", page: " + page);
		Response challenge = context.form().setError(message).createForm(page);
		context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
	}

	private void goPage(AuthenticationFlowContext context, String page) {
        logger.info("OtpSmsFormAuthenticator::goPage called");
		context.challenge(context.form().createForm(page));
	}

	private void goPage(AuthenticationFlowContext context, String page, String errorMsg,
			Map<String, String> attributes) {
        logger.info("OtpSmsFormAuthenticator::goPage called");
		LoginFormsProvider resForm = context.form();
		for (Entry<String, String> entry : attributes.entrySet()) {
			resForm.setAttribute(entry.getKey(), entry.getValue());
		}
        logger.info("Setting secret key in form attribute");
		if (StringUtils.isNotBlank(errorMsg)) {
			resForm.setError(errorMsg);
		}
        logger.info("Rendering page: " + page);
		context.challenge(resForm.createForm(page));
	}

	protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("OtpSmsFormAuthenticator::validateForm called");
		return validateUserAndPassword(context, formData);
	}

	private String getEmailOrMobileNumber(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::getEmailOrMobileNumber called");
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.info("Form Data: " + formData);
		String emailOrMobile = formData.getFirst(Constants.ATTR_USER_EMAIL_OR_PHONE);
        logger.info("Email or Mobile entered: " + emailOrMobile);
		if (null == emailOrMobile) {
			return "";
		}
        logger.info("Returning email or mobile: " + emailOrMobile);
		return emailOrMobile;
	}

	private UserModel getUserByMobileNumber(AuthenticationFlowContext context, String mobilePhone) {
        logger.info("OtpSmsFormAuthenticator::getUserByMobileNumber called");
		UserModel user = null;
		try {
			user = SunbirdModelUtils.getUserByNameEmailOrPhone(context, mobilePhone);
            logger.info("User found with given email or mobile: " + (user != null ? user.getId() : "null"));
		} catch (ModelDuplicateException mde) {
			ServicesLogger.LOGGER.modelDuplicateException(mde);
			// Could happen during federation import
			if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                logger.info("Duplicate email found.");
				setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
						AuthenticationFlowError.USER_CONFLICT);
			} else if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.USERNAME)) {
                logger.info("Duplicate username found.");
				setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
						AuthenticationFlowError.USER_CONFLICT);
			} else if (mde.getDuplicateFieldName() != null
					&& mde.getDuplicateFieldName().equals(KeycloakSmsAuthenticatorConstants.ATTR_MOBILE)) {
                logger.info("Duplicate mobile number found.");
				setDuplicateUserChallenge(context, Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE,
						Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE, AuthenticationFlowError.USER_CONFLICT);
			}

			return null;
		}

		if (invalidUser(context, user)) {
            logger.info("Invalid user.");
			return null;
		}
		return user;
	}

	private void sendOtp(AuthenticationFlowContext context, String redirectUri) {
        logger.info("OtpSmsFormAuthenticator::sendOtp called");
		String emailOrMobile = getEmailOrMobileNumber(context);
        logger.info("Email or Mobile to send OTP: " + emailOrMobile);
		UserModel user = getUserByMobileNumber(context, emailOrMobile);
        logger.info("User fetched for sending OTP: " + (user != null ? user.getId() : "null"));
		if (null == user) {
            logger.info("No user found with given email or mobile.");
			goErrorPage(context, "Oops, Member not found.");
			return;
		}

		if (context.getUser() != null) {
			// Let's compare both the user's are same ?
			if (!user.getId().equalsIgnoreCase(context.getUser().getId())) {
                logger.info("Different user found in the same session.");
				logger.error(String.format(
						"Received different user details for saved session. Saved userId: %s, New userId: %s. Returning error...",
						context.getUser().getId(), user.getId()));
				context.getEvent().getEvent().setError(Errors.DIFFERENT_USER_AUTHENTICATED);
				goErrorPage(context, "Authentication Error! Please enter your credentials again.");
				return;		
			}
		}
        logger.info("Proceeding to generate and send OTP to user: " + user.getId());
		// Generate Random Digit
		Map<String, String> attributes = generateOTP(context);
        logger.info("Generated OTP and attributes for user: " + user.getId());

		// Send the key into the User Mobile Phone
		if (sendOtpByEmailOrSms(context, emailOrMobile, attributes.get(Constants.SESSION_OTP_CODE))) {
            logger.info("OTP sent successfully to user: " + user.getId());
			//SMS is sent successfully, let's save the details in session and return the necessary page.			
			context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE, attributes.get(Constants.SESSION_OTP_CODE));
			context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_EXPIRE_TIME, attributes.get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL));
			context.getAuthenticationSession().setAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER, emailOrMobile);
			context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI, redirectUri);

			logger.info("Saving user details in session with userId: " + user.getId());
			context.setUser(user);
			goPage(context, Constants.PAGE_INPUT_OTP, StringUtils.EMPTY, attributes);
		} else {
			goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
		}
	}

	private void resendOtp(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::resendOtp called");
		String mobileNumber = context.getAuthenticationSession()
				.getAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER);
		// Generate Random Digit
		Map<String, String> attributes = generateOTP(context);
        logger.info("Generated new OTP for mobile number: " + mobileNumber);

		// Put the data into session, to be compared
		context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE,
				attributes.get(Constants.SESSION_OTP_CODE));
        logger.info("Updated session with new OTP for mobile number: " + mobileNumber);
		// Send the key into the User Mobile Phone
		if (sendOtpByEmailOrSms(context, mobileNumber, attributes.get(Constants.SESSION_OTP_CODE))) {
            logger.info("OTP resent successfully to mobile number: " + mobileNumber);
			goPage(context, Constants.PAGE_INPUT_OTP);
		} else {
			goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
		}
	}

	private boolean sendOtpByEmailOrSms(AuthenticationFlowContext context, String mobileNumber, String otp) {
        logger.info("OtpSmsFormAuthenticator::sendOtpByEmailOrSms called");
		boolean retValue = false;
		String userNameType = isEmailOrMobileNumber(mobileNumber);
        logger.info("Determined userNameType as: " + userNameType + " for value: " + mobileNumber);
		switch (userNameType) {
			case Constants.PHONE:
                logger.info("Sending OTP via SMS to mobile number: " + mobileNumber);
				AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
				String smsProvider = null;
				if (configModel.getConfig() != null) {
					smsProvider = configModel.getConfig().get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_PROVIDER);
                    logger.info("SMS Provider from config: " + smsProvider);
				}
				logger.info("SMS for OTP initiated with provider : " + smsProvider);
				if (Constants.MSG91_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Sending OTP via MSG91 to mobile number: " + mobileNumber);
					retValue = KeycloakSmsAuthenticatorUtil.send(mobileNumber, otp);
				} else if (Constants.Free2SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Sending OTP via Free2SMS to mobile number: " + mobileNumber);
					retValue = sendSmsViaFast2Sms(mobileNumber, otp);
				} else if (Constants.NIC_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Sending OTP via NIC to mobile number: " + mobileNumber);
					long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
							KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
					retValue = sendSmsViaNIC(mobileNumber, otp, String.valueOf(ttl / 60));
				} else if (Constants.AMNEX_SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Sending OTP via Amnex to mobile number: " + mobileNumber);
					long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
							KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
					retValue = sendSmsViaAmnex(mobileNumber, otp, String.valueOf(ttl / 60));
				} else if (Constants.NETCORE_SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Sending OTP via NetCore to mobile number: " + mobileNumber);
					long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
							KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
					retValue = sendSmsViaNetCore(mobileNumber, otp, String.valueOf(ttl / 60));
				} else {
                    logger.info("SMS Provider is not configured properly.");
					logger.error(String.format(
							"SMS Provider is not configured property. current value: %s. Execpected value: NIC / MSG91",
							smsProvider));
				}
				break;
			case Constants.EMAIL:
                logger.info("Sending OTP via Email to email address: " + mobileNumber);
				retValue = sendEmailViaSunbird(context, mobileNumber, otp);
				break;
			default:
				logger.error("Failed to identify given key is email or mobile.");
				break;
		}
		logger.info("Email/SMS for OTP send successfully ? " + retValue);
		return retValue;
	}

	private boolean sendSmsViaNIC(String mobileNumber, String otp, String expiryTime) {
        logger.info("OtpSmsFormAuthenticator::sendSmsViaNIC called");
		boolean retValue = NicSmsProvider.getInstance().send(mobileNumber, otp, expiryTime,
				SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
        logger.info("SMS via NIC send successfully ? " + retValue);
		return retValue;
	}

	private boolean sendSmsViaFast2Sms(String mobileNumber, String otp) {
        logger.info("OtpSmsFormAuthenticator::sendSmsViaFast2Sms called");
		List<String> acceptedNumbers = new ArrayList<String>();
		if (StringUtils.isNotBlank(System.getenv(Constants.SMS_OTP_NUMBERS))) {
            logger.info("Accepted numbers for Fast2SMS: " + System.getenv(Constants.SMS_OTP_NUMBERS));
			acceptedNumbers = Arrays.asList(System.getenv(Constants.SMS_OTP_NUMBERS).split(",", -1));
		}
		if (!acceptedNumbers.contains(mobileNumber)) {
            logger.info("Mobile number: " + mobileNumber + " is not in accepted list for Fast2SMS.");
			return false;
		}

		try {
			// Construct data
			StringBuilder strUrl = new StringBuilder(System.getenv(Constants.FAST2SMS_API_URL));
			strUrl.append("?authorization=").append(System.getenv(Constants.FAST2SMS_API_KEY));
			strUrl.append("&route=v3");
			strUrl.append("&sender_id=FTWSMS");
			strUrl.append("&message=Your%20OTP%20login%20into%20iGOT%20System%20is%20:%20" + otp);
			strUrl.append("&language=english&flash=0");
			strUrl.append("&numbers=").append(mobileNumber);
            logger.info("Constructed Fast2SMS URL: " + strUrl.toString());

			// Send SMS
			HttpURLConnection conn = (HttpURLConnection) new URL(strUrl.toString()).openConnection();
			conn.setDoOutput(true);
			conn.setRequestMethod("GET");
            logger.info("Sending request to Fast2SMS.");
			final BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			final StringBuffer stringBuffer = new StringBuffer();
			String line;
			while ((line = rd.readLine()) != null) {
				stringBuffer.append(line);
			}
			rd.close();

			logger.info(stringBuffer.toString());
			return true;
		} catch (Exception e) {
			System.out.println("Error SMS " + e);
			logger.error(e);
		}
		return false;
	}

	private Map<String, String> generateOTP(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::generateOTP called");
		// The mobile number is configured --> send an SMS
		long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_LENGTH, 6L);
        logger.info("Number of digits for OTP: " + nrOfDigits);

		// Get TTL from config. Default 5 minutes in seconds
		long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
        logger.info("TTL for OTP in seconds: " + ttl);

		String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);
        logger.info("Generated OTP code: " + code);

		Long expireTime = (new Date()).getTime() + (ttl * 1000);
        logger.info("OTP expire time (epoch ms): " + expireTime);
		Map<String, String> attributes = new HashMap<String, String>();
        logger.info("Storing OTP and expire time in attributes map.");
		attributes.put(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, String.valueOf(expireTime));
		attributes.put(Constants.SESSION_OTP_CODE, code);
        logger.info("Calling storeSMSCodeInDB to save OTP in DB.");
		return attributes;
	}

	private boolean sendEmailViaSunbird(AuthenticationFlowContext context, String userEmail, String smsCode) {
        logger.info("OtpSmsFormAuthenticator::sendEmailViaSunbird called");

		Map<String, Object> otpResponse = new HashMap<String, Object>();

		otpResponse.put(Constants.RECIPIENT_EMAILS, Arrays.asList(userEmail));
		otpResponse.put(Constants.SUBJECT, System.getenv(Constants.LOGIN_OTP_MAIL_SUBJECT));
		otpResponse.put(Constants.REALM_NAME, context.getRealm().getDisplayName());
		otpResponse.put(Constants.EMAIL_TEMPLATE_TYPE, System.getenv(Constants.LOGIN_OTP_EMAIL_TEMPLATE));
		otpResponse.put(Constants.BODY, Constants.BODY);
		otpResponse.put(Constants.OTP, smsCode);
        logger.info("Prepared OTP email payload for user: " + userEmail);

		long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
        logger.info("TTL for OTP in seconds: " + ttl);
		otpResponse.put(Constants.TTL, ttl / 60);

		Map<String, Object> request = new HashMap<>();
		request.put(Constants.REQUEST, otpResponse);

		HttpResponse response = null;
		try {
			response = HttpClient.post(request,
					(System.getenv(Constants.SUNBIRD_LMS_BASE_URL) + Constants.SEND_NOTIFICATION_URI),
					System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION));
            logger.info("Sent OTP email request to Sunbird Notification service.");
			if (response.getStatusLine() != null) {
				int statusCode = response.getStatusLine().getStatusCode();
				if (statusCode == 200) {
                    logger.info("OTP email sent successfully to user: " + userEmail);
					return true;
				} else {
                    logger.info("Failed to send OTP email to user: " + userEmail + ". StatusCode: " + statusCode);
					logger.error(
							String.format("Failed to send email for OTP Login. Received StatusCode: %s", statusCode));
				}
			}
		} catch (Exception e) {
			logger.error("Failed to send Email Notification for OTP Login. Exception: ", e);
		}
		return false;
	}

	private String isEmailOrMobileNumber(String emailOrMobile) {
		String numberRegex = "\\d+";
		String emailRegex = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
				+ "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
        logger.info("OtpSmsFormAuthenticator::isEmailOrMobileNumber called for value: " + emailOrMobile);
		if (emailOrMobile.matches(numberRegex) && 10 == emailOrMobile.length()) {
            logger.info("Value is identified as PHONE.");
			return Constants.PHONE;
		} else if (emailOrMobile.matches(emailRegex)) {
            logger.info("Value is identified as EMAIL.");
			return Constants.EMAIL;
		}
		return StringUtils.EMPTY;
	}

	protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::validateCode called");
		CODE_STATUS result = CODE_STATUS.INVALID;

		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.info("Form Data: " + formData);
		String enteredCode = formData.getFirst(KeycloakSmsAuthenticatorConstants.ANSW_SMS_CODE);
        logger.info("Entered OTP code: " + enteredCode);

		String storedCode = context.getAuthenticationSession().getAuthNote(Constants.SESSION_OTP_CODE);
        logger.info("Stored OTP code from session: " + storedCode);
		if (storedCode != null && enteredCode != null) {
            logger.info("Comparing entered OTP with stored OTP.");
			result = storedCode.equalsIgnoreCase(enteredCode) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            logger.info("OTP comparison result: " + result);
		}

		String storedExpiryValue = context.getAuthenticationSession().getAuthNote(Constants.SESSION_OTP_EXPIRE_TIME);
        logger.info("Stored OTP expiry time from session: " + storedExpiryValue);
		if (result == CODE_STATUS.VALID && StringUtils.isNotBlank(storedExpiryValue)) {
            logger.info("Validating OTP expiry time.");
			Long currentTime = (new Date()).getTime();
			Long storedExpiryTime = Long.parseLong(storedExpiryValue);
			logger.info(String.format("CurrentTime: %s, StoredExpiryTime: %s", currentTime, storedExpiryTime));
			result = storedExpiryTime >= currentTime ? CODE_STATUS.VALID : CODE_STATUS.EXPIRED;
            logger.info("OTP expiry validation result: " + result);
		}
		return result;
	}

	private void storeSMSCodeInDB(AuthenticationFlowContext context, String code, Long expiringAt) {
        logger.info("OtpSmsFormAuthenticator::storeSMSCodeInDB called");
		logger.debug("KeycloakSmsAuthenticator@storeSMSCode called");

		UserCredentialModel credentials = new UserCredentialModel();
		credentials.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
		credentials.setValue(code);
		credentials.setNote(Constants.TTL, String.valueOf(expiringAt));
        logger.info("Storing OTP code in DB for user: " + context.getUser().getId());

		context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(),
				credentials);

		credentials = new UserCredentialModel();
		credentials.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
		credentials.setValue((expiringAt).toString());
		context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(),
				credentials);
        logger.info("Stored OTP code and expiry time in DB for user: " + context.getUser().getId());
	}

	private CODE_STATUS validateCodeUsingDB(AuthenticationFlowContext context) {
        logger.info("OtpSmsFormAuthenticator::validateCodeUsingDB called");
		CODE_STATUS result = CODE_STATUS.INVALID;

		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.info("Form Data: " + formData);
		String enteredCode = formData.getFirst(KeycloakSmsAuthenticatorConstants.ANSW_SMS_CODE);
        logger.info("Entered OTP code: " + enteredCode);
		KeycloakSession session = context.getSession();

		List<?> codeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(),
				context.getUser(), KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
        logger.info("Fetched stored OTP codes from DB for user: " + context.getUser().getId());

		if (!CollectionUtils.isNullOrEmpty(codeCreds)) {
            logger.info("Stored OTP code found in DB, validating...");
			CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);
            logger.info("Expected OTP code from DB: " + expectedCode.getValue());
			result = enteredCode.equals(expectedCode.getValue()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            logger.info("OTP code validation result: " + result);
		}

		if (result == CODE_STATUS.VALID) {
            logger.info("Validating OTP expiry time from DB.");
			List<?> timeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(),
					context.getUser(), KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
            logger.info("Fetched stored OTP expiry time from DB for user: " + context.getUser().getId());
			if (!CollectionUtils.isNullOrEmpty(timeCreds)) {
                logger.info("Stored OTP expiry time found in DB, validating...");
				CredentialModel expTimeString = (CredentialModel) timeCreds.get(0);
				Long currentTime = (new Date()).getTime();
				Long expiringAt = Long.parseLong(expTimeString.getValue());

				logger.info(String.format("CurrentTime: %s, ExpiringAt: %s, isExpired ?? %s", currentTime, expiringAt,
						(currentTime >= expiringAt)));
				// result = currentTime <= expiringAt ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
			}
		}

		if (result == CODE_STATUS.VALID) {
            logger.info("OTP validated successfully, removing OTP and expiry time from DB for user: " + context.getUser().getId());
			session.userCredentialManager().removeStoredCredential(context.getRealm(), context.getUser(),
					KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
			session.userCredentialManager().removeStoredCredential(context.getRealm(), context.getUser(),
					KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
            logger.info("Removed OTP and expiry time from DB for user: " + context.getUser().getId());
		}
		return result;
	}

	private boolean sendSmsViaAmnex(String mobileNumber, String otp, String expiryTime) {
        logger.info("OtpSmsFormAuthenticator::sendSmsViaAmnex called");
		boolean retValue = AmnexSmsProvider.getInstance().send(mobileNumber, otp, expiryTime,
				SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
        logger.info("SMS via Amnex send successfully ? " + retValue);
		return retValue;
	}

	private boolean sendSmsViaNetCore(String mobileNumber, String otp, String expiryTime) {
		mobileNumber = "91" + mobileNumber;
        logger.info("OtpSmsFormAuthenticator::sendSmsViaNetCore called for mobile number: " + mobileNumber);
		boolean retValue = NetCoreSMSProvider.getInstance().send(mobileNumber, otp, expiryTime,
				SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
        logger.info("SMS via NetCore send successfully ? " + retValue);
		return retValue;
	}

	private String generateSecretKey() {
		// Convert current time to a formatted string (e.g., YYYYMMDDHHMMSS)
        logger.info("OtpSmsFormAuthenticator::generateSecretKey called");
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
		String timeComponent = dateFormat.format(new Date(System.currentTimeMillis()));

		// Generate a random number between 0 and 9999
		int randomComponent = random.nextInt(10000);

		// Combine the time component and the random component
		String secretKey = timeComponent + String.format("%04d", randomComponent);
        logger.info("Generated secret key before truncation/padding: " + secretKey);

		// Truncate or pad the secret key to ensure it's exactly 16 digits
		return secretKey.length() > 16 ? secretKey.substring(0, 16) : secretKey;
	}

	public boolean validateUserAndPassword(AuthenticationFlowContext context,
			MultivaluedMap<String, String> inputData) {
        logger.info("OtpSmsFormAuthenticator::validateUserAndPassword called");
		String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        logger.info("Username entered: " + username);
		if (username == null) {
            logger.info("Username is null.");
			context.getEvent().error(Errors.USER_NOT_FOUND);
			Response challengeResponse = challenge(context, Messages.INVALID_USER);
			context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
			return false;
		}

		// remove leading and trailing whitespace
		username = username.trim();
        logger.info("Trimmed username: " + username);

		context.getEvent().detail(Details.USERNAME, username);
		context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

		UserModel user = null;
		try {
			user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
            logger.info("User fetched for username: " + username + " is " + (user != null ? user.getId() : "null"));
		} catch (ModelDuplicateException mde) {
            logger.info("ModelDuplicateException caught while fetching user for username: " + username);
			ServicesLogger.LOGGER.modelDuplicateException(mde);

			// Could happen during federation import
			if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                logger.info("Duplicate email found.");
				context.getEvent().getEvent().setError(Errors.EMAIL_IN_USE);
				//setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
				//		AuthenticationFlowError.INVALID_USER);
			} else {
                logger.info("Duplicate username found.");
				context.getEvent().getEvent().setError(Errors.USERNAME_IN_USE);
				//setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
				//		AuthenticationFlowError.INVALID_USER);
			}

			return false;
		}

		if (user == null) {
            logger.info("No user found with given username: " + username);
			context.getEvent().getEvent().setError(Errors.USER_NOT_FOUND);
			return false;
		}

		if (!user.isEnabled()) {
            logger.info("User account is disabled for user: " + user.getId());
			context.getEvent().getEvent().setError(Errors.USER_DISABLED);
			return false;
		}

		if (context.getRealm().isBruteForceProtected()) {
            logger.info("Realm has brute force protection enabled, checking if user is temporarily disabled.");
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                logger.info("User account is temporarily disabled due to brute force protection for user: " + user.getId());
				context.getEvent().getEvent().setError(Errors.USER_TEMPORARILY_DISABLED);
				return false;
			}
		}
		
		if (!validatePassword(context, user, inputData)) {
            logger.info("Password validation failed for user: " + user.getId());
			context.getEvent().getEvent().setError(Errors.INVALID_USER_CREDENTIALS);
			return false;
		}

		String rememberMe = inputData.getFirst("rememberMe");
        logger.info("Remember Me value: " + rememberMe);
		boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
		if (remember) {
            logger.info("Setting Remember Me for user: " + user.getId());
			context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
			context.getEvent().detail(Details.REMEMBER_ME, "true");
		} else {
            logger.info("Not setting Remember Me for user: " + user.getId());
			context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
		}
		context.setUser(user);
		return true;
	}

	public boolean validatePassword(AuthenticationFlowContext context, UserModel user,
			MultivaluedMap<String, String> inputData) {
        logger.info("OtpSmsFormAuthenticator::validatePassword called for user: " + user.getId());
		String encryptedPassword = inputData.getFirst(CredentialRepresentation.PASSWORD);
		String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
		String iv = inputData.getFirst(Constants.IV);
		// Decrypt the password
		String decryptedPassword = decryptPassword(encryptedPassword, secretKey, iv);

		List<CredentialInput> credentials = new LinkedList<>();
		credentials.add(UserCredentialModel.password(decryptedPassword));

		if (decryptedPassword != null && !decryptedPassword.isEmpty()
				&& context.getSession().userCredentialManager().isValid(context.getRealm(), user, credentials)) {
            logger.info("Password validated successfully for user: " + user.getId());
			return true;
		} else {
            logger.info("Password validation failed for user: " + user.getId());
			return false;
		}
	}

	private String decryptPassword(String encryptedPassword, String secretKey, String iv) {
		try {
            logger.info("OtpSmsFormAuthenticator::decryptPassword called");
			byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
			byte[] ivBytes = Base64.getDecoder().decode(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            logger.info("Decrypting password using AES/CBC/PKCS5Padding");

			byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            logger.info("Password decrypted successfully.");
			return new String(decryptedBytes, "UTF-8");
		} catch (Exception e) {
            logger.info("Exception caught while decrypting password.");
			logger.error("PasswordAndOtpAuthenticator:: Exception while decrypting password. Exception: ", e);
			throw new RuntimeException("Error while decrypting password", e);
		}
	}
}
