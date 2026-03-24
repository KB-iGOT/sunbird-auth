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
		String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
		if (StringUtils.isBlank(secretKey)) {
			// Generate the secret key
			secretKey = generateSecretKey();
		}

		// Store the secret key as an authentication session note
		context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, secretKey);

		LoginFormsProvider formsProvider = context.form();
		formsProvider.setAttribute(Constants.SECRET_KEY, secretKey);
		if (context.getAuthenticationSession().getRedirectUri().contains(Constants.EC_LOGIN)) {
			context.getAuthenticationSession().setAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE, Constants.EC_LOGIN_PAGE);
			context.challenge(formsProvider.createForm(Constants.EC_LOGIN_PAGE));
		} else {
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
		MultivaluedMap<String, String> qParamMap = context.getHttpRequest().getUri().getQueryParameters(false);
		Iterator<Entry<String, List<String>>> itr = qParamMap.entrySet().iterator();
		while (itr.hasNext()) {
			Entry<String, List<String>> entry = itr.next();
			logger.debug(String.format("		query: key: %s, value: %s", entry.getKey(), entry.getValue()));
		}

		String flagPage = getValue(context, Constants.FLAG_PAGE);
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
				boolean isSuccess = validateForm(context, context.getHttpRequest().getDecodedFormParameters());
				if (!isSuccess) {
					goErrorPage(context, "Invalid credentials!");
				} else {
					context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI,
							qParamMap.getFirst(Constants.REDIRECT_URI_KEY));
					context.success();
				}
				logger.info(String.format(
						"Action:: validateForm - Validation of username + password is completed for userId: %s, isSuccess: %s",
						context.getUser().getId(), isSuccess));
				break;
			default:
				authenticate(context);
				break;
		}
	}

	private String getValue(AuthenticationFlowContext context, String key) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		String value = formData.getFirst(key);
		if (null == value) {
			value = "";
		}
		return value;
	}

	private void authenticateOtp(AuthenticationFlowContext context) {
		CODE_STATUS status = validateCode(context);
		if (status == CODE_STATUS.VALID) {
			context.getAuthenticationSession().removeAuthNote(Constants.SESSION_OTP_CODE);
			context.success();
		} else if (status == CODE_STATUS.EXPIRED) {
			// OTP expired - clear session data and redirect to login page
			context.getAuthenticationSession().removeAuthNote(Constants.SESSION_OTP_CODE);
			context.getAuthenticationSession().removeAuthNote(Constants.SESSION_OTP_EXPIRE_TIME);
			context.getAuthenticationSession().removeAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER);
			context.getEvent().getEvent().setError(Constants.OTP_EXPIRED);
			goErrorPage(context, Constants.OTP_EXPIRED);
		} else {
			goErrorPage(context, Constants.PAGE_INPUT_OTP, Constants.INVALID_OTP_ENTERED);
		}
		logger.info(String.format(
				"Action:: authenticateOtp - completed for userId: %s, status: %s",
				context.getUser().getId(), status.name()));
	}

	private void goErrorPage(AuthenticationFlowContext context, String message) {
		logger.debug("OtpSmsFormAuthenticator::goErrorPage: message: " + message);

		LoginFormsProvider formsProvider = getLoginFormsProviderWithSecretKey(context);

		// Set the default error page
		String errorPage = Constants.LOGIN_PAGE;

		// Check if authNote is blank or equals EC_LOGIN, then set error page to EC_LOGIN_PAGE
		if (StringUtils.isNotBlank(context.getAuthenticationSession().getAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE)) &&
		        (Constants.EC_LOGIN_PAGE.equals(context.getAuthenticationSession().getAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE)))) {
			errorPage = Constants.EC_LOGIN_PAGE;
		}

		String error = context.getEvent().getEvent().getError();
		String errMsg = "Internal Server Error!";

		// Handle null error case - use empty string to trigger default case
		if (error == null) {
			logger.warn("Error code is null, will use default error handling");
			error = "";
		}

		switch (error) {
			case Errors.INVALID_USER_CREDENTIALS:
				errMsg = "Invalid credentials!";
				Response invalidCredsRes = formsProvider.setError(errMsg).createForm(errorPage);
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, invalidCredsRes);
				break;
			case Errors.USER_NOT_FOUND:
				errMsg = "Invalid user details.";
				Response invalidUserRes = formsProvider.setError(errMsg).createForm(errorPage);
				context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, invalidUserRes);
				break;
			case Errors.USER_DISABLED:
				errMsg = "User account is disabled.";
				Response userDisabledRes = formsProvider.setError(errMsg).createForm(errorPage);
				context.failureChallenge(AuthenticationFlowError.USER_DISABLED, userDisabledRes);
				break;
			case Errors.USER_TEMPORARILY_DISABLED:
				errMsg = "User account is disabled temporarily.";
				Response tempDisabledRes = formsProvider.setError(errMsg).createForm(errorPage);
				context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, tempDisabledRes);
				break;
			case Errors.DIFFERENT_USER_AUTHENTICATED:
				errMsg = "Authentication Error! Please enter your credentials again.";
				Response diffUsersFoundRes = formsProvider.setError(errMsg).createForm(errorPage);
				context.failureChallenge(AuthenticationFlowError.USER_CONFLICT, diffUsersFoundRes);
				break;
			case Constants.OTP_EXPIRED:
				errMsg = "OTP has expired. Please request for a new OTP.";
				Response otpExpiredRes = formsProvider.setError(errMsg).createForm(errorPage);
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, otpExpiredRes);
				break;
			case Errors.EMAIL_IN_USE:
			case Errors.USERNAME_IN_USE:
			default:
				Response internalErrorRes = formsProvider.setError(errMsg).createForm(errorPage);
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, internalErrorRes);
				break;
		}
		context.getEvent().error(errMsg);
		context.clearUser();
	}

	private void goErrorPage(AuthenticationFlowContext context, String page, String message) {
		logger.info("OtpSmsFormAuthenticator::goErrorPage: message: " + message + ", page: " + page);
		LoginFormsProvider formsProvider = getLoginFormsProviderWithSecretKey(context);
		Response challenge = formsProvider.setError(message).createForm(page);
		context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
	}

	private void goPage(AuthenticationFlowContext context, String page) {
		LoginFormsProvider formsProvider = getLoginFormsProviderWithSecretKey(context);
		context.challenge(formsProvider.createForm(page));
	}

	private void goPage(AuthenticationFlowContext context, String page, String errorMsg,
			Map<String, String> attributes) {
		LoginFormsProvider resForm = getLoginFormsProviderWithSecretKey(context);
		for (Entry<String, String> entry : attributes.entrySet()) {
			resForm.setAttribute(entry.getKey(), entry.getValue());
		}
		if (StringUtils.isNotBlank(errorMsg)) {
			resForm.setError(errorMsg);
		}
		context.challenge(resForm.createForm(page));
	}

	protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
		return validateUserAndPassword(context, formData);
	}

	private String getEmailOrMobileNumber(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		String emailOrMobile = formData.getFirst(Constants.ATTR_USER_EMAIL_OR_PHONE);
		if (null == emailOrMobile) {
			return "";
		}
		return emailOrMobile;
	}

	private UserModel getUserByMobileNumber(AuthenticationFlowContext context, String mobilePhone) {
		// Ensure secretKey is set before any error handling that might render a form
		ensureSecretKey(context);

		UserModel user = null;
		try {
			user = SunbirdModelUtils.getUserByNameEmailOrPhone(context, mobilePhone);
		} catch (ModelDuplicateException mde) {
			ServicesLogger.LOGGER.modelDuplicateException(mde);
			// Could happen during federation import
			if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
				setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
						AuthenticationFlowError.USER_CONFLICT);
			} else if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.USERNAME)) {
				setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
						AuthenticationFlowError.USER_CONFLICT);
			} else if (mde.getDuplicateFieldName() != null
					&& mde.getDuplicateFieldName().equals(KeycloakSmsAuthenticatorConstants.ATTR_MOBILE)) {
				setDuplicateUserChallenge(context, Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE,
						Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE, AuthenticationFlowError.USER_CONFLICT);
			}

			return null;
		}

		// Check if user is null - invalidUser() can render forms, so secretKey must be set
		if (user == null) {
			logger.warn("User not found for mobile/email: " + mobilePhone);
			return null;
		}

		if (invalidUser(context, user)) {
			return null;
		}
		return user;
	}

	private void sendOtp(AuthenticationFlowContext context, String redirectUri) {
		String emailOrMobile = getEmailOrMobileNumber(context);
		UserModel user = getUserByMobileNumber(context, emailOrMobile);
		if (null == user) {
			context.getEvent().getEvent().setError(Errors.USER_NOT_FOUND);
			goErrorPage(context, "Oops, Member not found.");
			logger.error("Action:: sendOtp - User not found for mobile/email: " + emailOrMobile);
			return;
		}

		if (context.getUser() != null) {
			// Let's compare both the user's are same ?
			if (!user.getId().equalsIgnoreCase(context.getUser().getId())) {
				logger.error(String.format(
						"Received different user details for saved session. Saved userId: %s, New userId: %s. Returning error...",
						context.getUser().getId(), user.getId()));
				context.getEvent().getEvent().setError(Errors.DIFFERENT_USER_AUTHENTICATED);
				goErrorPage(context, "Authentication Error! Please enter your credentials again.");
				return;		
			}
		}

		// Generate Random Digit
		Map<String, String> attributes = generateOTP(context);

		// Send the key into the User Mobile Phone
		boolean isSuccess = sendOtpByEmailOrSms(context, emailOrMobile, attributes.get(Constants.SESSION_OTP_CODE));
		if (isSuccess) {
			// SMS is sent successfully, let's save the details in session and return the
			// necessary page.
			context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE,
					attributes.get(Constants.SESSION_OTP_CODE));
			context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_EXPIRE_TIME,
					attributes.get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL));
			context.getAuthenticationSession().setAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER, emailOrMobile);
			context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI, redirectUri);

			context.setUser(user);
			goPage(context, Constants.PAGE_INPUT_OTP, StringUtils.EMPTY, attributes);
		} else {
			context.getEvent().getEvent().setError("SMS_SEND_FAILED");
			goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
		}
		logger.info(String.format(
				"Action:: sendOtp - completed for userId: %s, status: %s",
				context.getUser().getId(), isSuccess));
	}

	private void resendOtp(AuthenticationFlowContext context) {
		String mobileNumber = context.getAuthenticationSession()
				.getAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER);
		// Generate Random Digit
		Map<String, String> attributes = generateOTP(context);

		// Put the data into session, to be compared
		context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE,
				attributes.get(Constants.SESSION_OTP_CODE));
		// Send the key into the User Mobile Phone
		boolean isSuccess = sendOtpByEmailOrSms(context, mobileNumber, attributes.get(Constants.SESSION_OTP_CODE));
		if (isSuccess) {
			goPage(context, Constants.PAGE_INPUT_OTP);
		} else {
			context.getEvent().getEvent().setError("SMS_SEND_FAILED");
			goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
		}
		logger.info(String.format(
				"Action:: resendOtp - completed for userId: %s, status: %s",
				context.getUser().getId(), isSuccess));
	}

	private boolean sendOtpByEmailOrSms(AuthenticationFlowContext context, String mobileNumber, String otp) {
		boolean retValue = false;
		String userNameType = isEmailOrMobileNumber(mobileNumber);
		switch (userNameType) {
			case Constants.PHONE:
				AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
				String smsProvider = null;
				if (configModel.getConfig() != null) {
					smsProvider = configModel.getConfig().get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_PROVIDER);
				}
				if (Constants.MSG91_PROVIDER.equalsIgnoreCase(smsProvider)) {
					retValue = KeycloakSmsAuthenticatorUtil.send(mobileNumber, otp);
				} else if (Constants.Free2SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
					retValue = sendSmsViaFast2Sms(mobileNumber, otp);
				} else if (Constants.NIC_PROVIDER.equalsIgnoreCase(smsProvider)) {
					long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
							KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
					retValue = sendSmsViaNIC(mobileNumber, otp, String.valueOf(ttl / 60));
				} else if (Constants.AMNEX_SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
					long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
							KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
					retValue = sendSmsViaAmnex(mobileNumber, otp, String.valueOf(ttl / 60));
				} else if (Constants.NETCORE_SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
					long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
							KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
					retValue = sendSmsViaNetCore(context.getUser().getId(), mobileNumber, otp, String.valueOf(ttl / 60));
				} else {
					logger.error(String.format(
							"SMS Provider is not configured property. current value: %s. Execpected value: NIC / MSG91",
							smsProvider));
				}
				break;
			case Constants.EMAIL:
				retValue = sendEmailViaSunbird(context, mobileNumber, otp);
				break;
			default:
				logger.error("Failed to identify given key is email or mobile.");
				break;
		}
		return retValue;
	}

	private boolean sendSmsViaNIC(String mobileNumber, String otp, String expiryTime) {
		boolean retValue = NicSmsProvider.getInstance().send(mobileNumber, otp, expiryTime,
				SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
		return retValue;
	}

	private boolean sendSmsViaFast2Sms(String mobileNumber, String otp) {
		List<String> acceptedNumbers = new ArrayList<String>();
		if (StringUtils.isNotBlank(System.getenv(Constants.SMS_OTP_NUMBERS))) {
			acceptedNumbers = Arrays.asList(System.getenv(Constants.SMS_OTP_NUMBERS).split(",", -1));
		}
		if (!acceptedNumbers.contains(mobileNumber)) {
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

			// Send SMS
			HttpURLConnection conn = (HttpURLConnection) new URL(strUrl.toString()).openConnection();
			conn.setDoOutput(true);
			conn.setRequestMethod("GET");
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
			logger.error(e);
		}
		return false;
	}

	private Map<String, String> generateOTP(AuthenticationFlowContext context) {
		// The mobile number is configured --> send an SMS
		long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_LENGTH, 6L);

		// Get TTL from config. Default 5 minutes in seconds
		long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);

		String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);

		Long expireTime = (new Date()).getTime() + (ttl * 1000);
		Map<String, String> attributes = new HashMap<String, String>();
		attributes.put(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, String.valueOf(expireTime));
		attributes.put(Constants.SESSION_OTP_CODE, code);
		return attributes;
	}

	private boolean sendEmailViaSunbird(AuthenticationFlowContext context, String userEmail, String smsCode) {

		Map<String, Object> otpResponse = new HashMap<String, Object>();

		otpResponse.put(Constants.RECIPIENT_EMAILS, Arrays.asList(userEmail));
		otpResponse.put(Constants.SUBJECT, System.getenv(Constants.LOGIN_OTP_MAIL_SUBJECT));
		otpResponse.put(Constants.REALM_NAME, context.getRealm().getDisplayName());
		otpResponse.put(Constants.EMAIL_TEMPLATE_TYPE, System.getenv(Constants.LOGIN_OTP_EMAIL_TEMPLATE));
		otpResponse.put(Constants.BODY, Constants.BODY);
		otpResponse.put(Constants.OTP, smsCode);

		long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
		otpResponse.put(Constants.TTL, ttl / 60);

		Map<String, Object> request = new HashMap<>();
		request.put(Constants.REQUEST, otpResponse);

		HttpResponse response = null;
		long startTime = System.currentTimeMillis();
		try {
			response = HttpClient.post(request,
					(System.getenv(Constants.SUNBIRD_LMS_BASE_URL) + Constants.SEND_NOTIFICATION_URI),
					System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION));
			if (response.getStatusLine() != null) {
				int statusCode = response.getStatusLine().getStatusCode();
				if (statusCode == 200) {
					logger.info(String.format(
							"Action:: sendEmailViaSunbird - successfully sent OTP Email; UserId: %s, UserEmail: %s; TimeTaken: %s",
							context.getUser().getId(), userEmail, (System.currentTimeMillis() - startTime)));
					return true;
				} else {
					logger.info(String.format(
							"Action:: sendEmailViaSunbird - Failed to send OTP Email; UserId: %s, UserEmail: %s; TimeTaken: %s, StatusCode: %s",
							context.getUser().getId(), userEmail, (System.currentTimeMillis() - startTime),statusCode));
				}
			}
		} catch (Exception e) {
			logger.info(String.format(
							"Action:: sendEmailViaSunbird - Failed to send OTP Email; UserId: %s, UserEmail: %s; TimeTaken: %s, Exception: %s",
							context.getUser().getId(), userEmail, (System.currentTimeMillis() - startTime), e));
		}
		return false;
	}

	private String isEmailOrMobileNumber(String emailOrMobile) {
		String numberRegex = "\\d+";
		String emailRegex = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
				+ "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
		if (emailOrMobile.matches(numberRegex) && 10 == emailOrMobile.length()) {
			return Constants.PHONE;
		} else if (emailOrMobile.matches(emailRegex)) {
			return Constants.EMAIL;
		}
		return StringUtils.EMPTY;
	}

	protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
		CODE_STATUS result = CODE_STATUS.INVALID;

		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		String enteredCode = formData.getFirst(KeycloakSmsAuthenticatorConstants.ANSW_SMS_CODE);

		String storedCode = context.getAuthenticationSession().getAuthNote(Constants.SESSION_OTP_CODE);
		if (storedCode != null && enteredCode != null) {
			result = storedCode.equalsIgnoreCase(enteredCode) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
		}

		String storedExpiryValue = context.getAuthenticationSession().getAuthNote(Constants.SESSION_OTP_EXPIRE_TIME);
		if (result == CODE_STATUS.VALID && StringUtils.isNotBlank(storedExpiryValue)) {
			Long currentTime = (new Date()).getTime();
			Long storedExpiryTime = Long.parseLong(storedExpiryValue);
			logger.info(String.format("CurrentTime: %s, StoredExpiryTime: %s", currentTime, storedExpiryTime));
			result = storedExpiryTime >= currentTime ? CODE_STATUS.VALID : CODE_STATUS.EXPIRED;
		}
		return result;
	}

	private void storeSMSCodeInDB(AuthenticationFlowContext context, String code, Long expiringAt) {
		logger.debug("KeycloakSmsAuthenticator@storeSMSCode called");

		UserCredentialModel credentials = new UserCredentialModel();
		credentials.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
		credentials.setValue(code);
		credentials.setNote(Constants.TTL, String.valueOf(expiringAt));

		context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(),
				credentials);

		credentials = new UserCredentialModel();
		credentials.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
		credentials.setValue((expiringAt).toString());
		context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(),
				credentials);
	}

	private CODE_STATUS validateCodeUsingDB(AuthenticationFlowContext context) {
		CODE_STATUS result = CODE_STATUS.INVALID;

		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		String enteredCode = formData.getFirst(KeycloakSmsAuthenticatorConstants.ANSW_SMS_CODE);
		KeycloakSession session = context.getSession();

		List<?> codeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(),
				context.getUser(), KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);

		if (!CollectionUtils.isNullOrEmpty(codeCreds)) {
			CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);
			result = enteredCode.equals(expectedCode.getValue()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
		}

		if (result == CODE_STATUS.VALID) {
			List<?> timeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(),
					context.getUser(), KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
			if (!CollectionUtils.isNullOrEmpty(timeCreds)) {
				CredentialModel expTimeString = (CredentialModel) timeCreds.get(0);
				Long currentTime = (new Date()).getTime();
				Long expiringAt = Long.parseLong(expTimeString.getValue());

				logger.info(String.format("CurrentTime: %s, ExpiringAt: %s, isExpired ?? %s", currentTime, expiringAt,
						(currentTime >= expiringAt)));
				// result = currentTime <= expiringAt ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
			}
		}

		if (result == CODE_STATUS.VALID) {
			session.userCredentialManager().removeStoredCredential(context.getRealm(), context.getUser(),
					KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
			session.userCredentialManager().removeStoredCredential(context.getRealm(), context.getUser(),
					KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
		}
		return result;
	}

	private boolean sendSmsViaAmnex(String mobileNumber, String otp, String expiryTime) {
		boolean retValue = AmnexSmsProvider.getInstance().send(mobileNumber, otp, expiryTime,
				SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
		return retValue;
	}

	private boolean sendSmsViaNetCore(String userId, String mobileNumber, String otp, String expiryTime) {
		mobileNumber = "91" + mobileNumber;
		boolean retValue = NetCoreSMSProvider.getInstance().send(userId, mobileNumber, otp, expiryTime,
				SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
		return retValue;
	}

	private String generateSecretKey() {
		// Convert current time to a formatted string (e.g., YYYYMMDDHHMMSS)
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
		String timeComponent = dateFormat.format(new Date(System.currentTimeMillis()));

		// Generate a random number between 0 and 9999
		int randomComponent = random.nextInt(10000);

		// Combine the time component and the random component
		String secretKey = timeComponent + String.format("%04d", randomComponent);

		// Truncate or pad the secret key to ensure it's exactly 16 digits
		return secretKey.length() > 16 ? secretKey.substring(0, 16) : secretKey;
	}

	public boolean validateUserAndPassword(AuthenticationFlowContext context,
			MultivaluedMap<String, String> inputData) {
		// Ensure secretKey is set before any validation that might render an error form
		ensureSecretKey(context);

		String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
		if (username == null) {
			context.getEvent().error(Errors.USER_NOT_FOUND);
			Response challengeResponse = challenge(context, Messages.INVALID_USER);
			context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
			return false;
		}

		// remove leading and trailing whitespace
		username = username.trim();

		context.getEvent().detail(Details.USERNAME, username);
		context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

		UserModel user = null;
		try {
			user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
		} catch (ModelDuplicateException mde) {
			ServicesLogger.LOGGER.modelDuplicateException(mde);

			// Could happen during federation import
			if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
				context.getEvent().getEvent().setError(Errors.EMAIL_IN_USE);
				//setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
				//		AuthenticationFlowError.INVALID_USER);
			} else {
				context.getEvent().getEvent().setError(Errors.USERNAME_IN_USE);
				//setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
				//		AuthenticationFlowError.INVALID_USER);
			}

			return false;
		}

		if (user == null) {
			context.getEvent().getEvent().setError(Errors.USER_NOT_FOUND);
			return false;
		}

		if (!user.isEnabled()) {
			context.getEvent().getEvent().setError(Errors.USER_DISABLED);
			return false;
		}

		if (context.getRealm().isBruteForceProtected()) {
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
				context.getEvent().getEvent().setError(Errors.USER_TEMPORARILY_DISABLED);
				return false;
			}
		}
		
		if (!validatePassword(context, user, inputData)) {
			context.getEvent().getEvent().setError(Errors.INVALID_USER_CREDENTIALS);
			return false;
		}

		String rememberMe = inputData.getFirst("rememberMe");
		boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
		if (remember) {
			context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
			context.getEvent().detail(Details.REMEMBER_ME, "true");
		} else {
			context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
		}
		context.setUser(user);
		return true;
	}

	public boolean validatePassword(AuthenticationFlowContext context, UserModel user,
			MultivaluedMap<String, String> inputData) {
		String encryptedPassword = inputData.getFirst(CredentialRepresentation.PASSWORD);
		String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
		String iv = inputData.getFirst(Constants.IV);
		// Decrypt the password
		String decryptedPassword = decryptPassword(encryptedPassword, secretKey, iv);

		List<CredentialInput> credentials = new LinkedList<>();
		credentials.add(UserCredentialModel.password(decryptedPassword));

		if (decryptedPassword != null && !decryptedPassword.isEmpty()
				&& context.getSession().userCredentialManager().isValid(context.getRealm(), user, credentials)) {
			return true;
		} else {
			return false;
		}
	}

	private String decryptPassword(String encryptedPassword, String secretKey, String iv) {
		try {
			byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
			byte[] ivBytes = Base64.getDecoder().decode(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

			byte[] decryptedBytes = cipher.doFinal(decodedBytes);
			return new String(decryptedBytes, "UTF-8");
		} catch (Exception e) {
			logger.error("PasswordAndOtpAuthenticator:: Exception while decrypting password. Exception: ", e);
			throw new RuntimeException("Error while decrypting password", e);
		}
	}

	/**
	 * Ensures secretKey exists in the authentication session. Generates a new one if missing.
	 * This prevents NullPointerException in FreeMarker templates when forms are rendered.
	 *
	 * @param context The authentication flow context
	 */
	private void ensureSecretKey(AuthenticationFlowContext context) {
		if (StringUtils.isBlank(context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY))) {
			context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, generateSecretKey());
			logger.info("Generated new secret key.");
		}
	}

	/**
	 * Ensures secretKey is available in the authentication session and returns a LoginFormsProvider
	 * with the secretKey attribute set. This prevents NullPointerException in FreeMarker templates.
	 *
	 * @param context The authentication flow context
	 * @return LoginFormsProvider with secretKey attribute set
	 */
	private LoginFormsProvider getLoginFormsProviderWithSecretKey(AuthenticationFlowContext context) {
		ensureSecretKey(context);
		LoginFormsProvider formsProvider = context.form();
		formsProvider.setAttribute(Constants.SECRET_KEY, 
			context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY)
		);
		return formsProvider;
	}
}
