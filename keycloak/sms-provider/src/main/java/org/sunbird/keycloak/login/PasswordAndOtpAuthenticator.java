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
        logger.info("OtpSmsFormAuthenticator@authenticate - started");
        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        logger.infof("Fetched secretKey from authentication session: %s", secretKey);
        if (StringUtils.isBlank(secretKey)) {
            logger.info("Secret key is blank → generating new secret key");
            secretKey = generateSecretKey();
            logger.infof("Generated new secret key: %s", secretKey);
        }
        String flagPage = getValue(context, Constants.FLAG_PAGE);
        logger.infof("FlagPage value: %s, using secretKey=%s", flagPage, secretKey);
        // Store the secret key as an authentication session note
        context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, secretKey);
        logger.info("Stored secretKey in authentication session");
        LoginFormsProvider formsProvider = context.form();
        formsProvider.setAttribute(Constants.SECRET_KEY, secretKey);
        logger.info("Set secretKey as attribute in LoginFormsProvider");
        String redirectUri = context.getAuthenticationSession().getRedirectUri();
        logger.infof("AuthenticationSession redirectUri: %s", redirectUri);
        if (redirectUri != null && redirectUri.contains(Constants.EC_LOGIN)) {
            logger.info("RedirectUri contains EC_LOGIN → loading EC login page");
            context.challenge(formsProvider.createForm(Constants.EC_LOGIN_PAGE));
            logger.info("EC login page challenge issued");
        } else {
            logger.info("RedirectUri does not contain EC_LOGIN → loading default login page");
            context.challenge(formsProvider.createForm(Constants.LOGIN_PAGE));
            logger.info("Default login page challenge issued");
        }
        logger.info("OtpSmsFormAuthenticator@authenticate - completed");
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
        logger.info("OtpSmsFormAuthenticator@action - started");

        MultivaluedMap<String, String> qParamMap = context.getHttpRequest().getUri().getQueryParameters(false);
        logger.infof("Fetched query parameters, size=%d", qParamMap.size());

        Iterator<Entry<String, List<String>>> itr = qParamMap.entrySet().iterator();
        while (itr.hasNext()) {
            Entry<String, List<String>> entry = itr.next();
            logger.infof("Query param → key=%s, value=%s", entry.getKey(), entry.getValue());
        }

        String flagPage = getValue(context, Constants.FLAG_PAGE);
        logger.infof("FlagPage value resolved: %s", flagPage);

        switch (flagPage) {
            case Constants.FLAG_OTP_PAGE:
                logger.info("FlagPage=FLAG_OTP_PAGE → calling authenticateOtp()");
                authenticateOtp(context);
                logger.info("authenticateOtp() completed");
                break;

            case Constants.FLAG_OTP_RESEND_PAGE:
                logger.info("FlagPage=FLAG_OTP_RESEND_PAGE → calling resendOtp()");
                resendOtp(context);
                logger.info("resendOtp() completed");
                break;

            case Constants.FLAG_LOGIN_PAGE:
                String redirectUri = qParamMap.getFirst(Constants.REDIRECT_URI_KEY);
                logger.infof("FlagPage=FLAG_LOGIN_PAGE → calling sendOtp() with redirectUri=%s", redirectUri);
                sendOtp(context, redirectUri);
                logger.info("sendOtp() completed");
                break;

            case Constants.FLAG_LOGIN_WITH_PASS:
                logger.info("FlagPage=FLAG_LOGIN_WITH_PASS → validating username + password form");
                MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();
                logger.infof("Decoded form parameters: %s", formParams);

                if (!validateForm(context, formParams)) {
                    logger.info("Form validation failed → calling goErrorPage()");
                    goErrorPage(context, "Invalid credentials!");
                    logger.info("goErrorPage() completed");
                } else {
                    String redirect = qParamMap.getFirst(Constants.REDIRECT_URI_KEY);
                    logger.infof("Form validation succeeded → setting redirect_uri=%s", redirect);
                    context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI, redirect);
                    context.success();
                    logger.info("context.success() called for FLAG_LOGIN_WITH_PASS");
                }
                break;

            default:
                logger.infof("FlagPage=%s (unrecognized) → calling authenticate()", flagPage);
                authenticate(context);
                logger.info("authenticate() completed");
                break;
        }

        logger.info("OtpSmsFormAuthenticator@action - completed");
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
        logger.info("authenticateOtp() - started");

        CODE_STATUS status = validateCode(context);
        logger.infof("validateCode() returned status: %s", status);

        if (status == CODE_STATUS.VALID) {
            logger.info("OTP validation successful → removing SESSION_OTP_CODE note");
            context.getAuthenticationSession().removeAuthNote(Constants.SESSION_OTP_CODE);

            context.success();
            logger.info("context.success() called → OTP authentication completed successfully");
        } else if (status == CODE_STATUS.EXPIRED) {
            logger.info("OTP validation failed → status=EXPIRED, redirecting to error page");
            goErrorPage(context, Constants.PAGE_INPUT_OTP, Constants.OTP_EXPIRED);
            logger.info("goErrorPage() called for EXPIRED OTP");
        } else {
            logger.info("OTP validation failed → status=INVALID, redirecting to error page");
            goErrorPage(context, Constants.PAGE_INPUT_OTP, Constants.INVALID_OTP_ENTERED);
            logger.info("goErrorPage() called for INVALID OTP");
        }

        logger.info("authenticateOtp() - completed");
    }

    private void goErrorPage(AuthenticationFlowContext context, String message) {
        logger.info("goErrorPage() - started");
        logger.infof("Input message parameter: %s", message);

        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        logger.infof("Fetched secretKey from session: %s", secretKey);

        if (StringUtils.isBlank(secretKey)) {
            logger.info("Secret key is blank → generating new secret key");
            secretKey = generateSecretKey();
            logger.infof("Generated new secret key: %s", secretKey);
        }

        logger.infof("goErrorPage() continuing with message=%s, keyValue=%s", message, secretKey);

        // Store the secret key as an authentication session note
        context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, secretKey);
        logger.info("Stored secretKey into authentication session");

        LoginFormsProvider formsProvider = context.form();
        formsProvider.setAttribute(Constants.SECRET_KEY, secretKey);
        logger.info("Set secretKey as attribute in LoginFormsProvider");

        String error = context.getEvent().getEvent().getError();
        logger.infof("Fetched error code from event: %s", error);

        String errMsg = "Internal Server Error!";
        switch (error) {
            case Errors.INVALID_USER_CREDENTIALS:
                errMsg = "Invalid credentials!";
                logger.info("Error=INVALID_USER_CREDENTIALS → preparing failureChallenge");
                Response invalidCredsRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, invalidCredsRes);
                logger.info("failureChallenge(INVALID_CREDENTIALS) issued");
                break;

            case Errors.USER_NOT_FOUND:
                errMsg = "Invalid user details.";
                logger.info("Error=USER_NOT_FOUND → preparing failureChallenge");
                Response invalidUserRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, invalidUserRes);
                logger.info("failureChallenge(UNKNOWN_USER) issued");
                break;

            case Errors.USER_DISABLED:
                errMsg = "User account is disabled.";
                logger.info("Error=USER_DISABLED → preparing failureChallenge");
                Response userDisabledRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.USER_DISABLED, userDisabledRes);
                logger.info("failureChallenge(USER_DISABLED) issued");
                break;

            case Errors.USER_TEMPORARILY_DISABLED:
                errMsg = "User account is disabled temporarily.";
                logger.info("Error=USER_TEMPORARILY_DISABLED → preparing failureChallenge");
                Response tempDisabledRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, tempDisabledRes);
                logger.info("failureChallenge(USER_TEMPORARILY_DISABLED) issued");
                break;

            case Errors.DIFFERENT_USER_AUTHENTICATED:
                errMsg = "Authentication Error! Please enter your credentials again.";
                logger.info("Error=DIFFERENT_USER_AUTHENTICATED → preparing failureChallenge");
                Response diffUsersFoundRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.USER_CONFLICT, diffUsersFoundRes);
                logger.info("failureChallenge(USER_CONFLICT) issued");
                break;

            case Errors.EMAIL_IN_USE:
            case Errors.USERNAME_IN_USE:
            default:
                logger.info("Error=EMAIL_IN_USE or USERNAME_IN_USE or other → preparing failureChallenge");
                Response internalErrorRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, internalErrorRes);
                logger.info("failureChallenge(INTERNAL_ERROR) issued");
                break;
        }

        logger.infof("Final error message stored in event: %s", errMsg);
        context.getEvent().error(errMsg);

        context.clearUser();
        logger.info("Cleared user from authentication context");

        logger.info("goErrorPage() - completed");
    }


    private void goErrorPage(AuthenticationFlowContext context, String page, String message) {
        logger.info("goErrorPage() - started");
        logger.infof("Input params → page=%s, message=%s", page, message);

        Response challenge = context.form().setError(message).createForm(page);
        logger.info("Created challenge response with error message set");

        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        logger.info("Issued failureChallenge with INVALID_CREDENTIALS");

        logger.info("goErrorPage() - completed");
    }


    private void goPage(AuthenticationFlowContext context, String page) {
        logger.info("goPage() - started");
        logger.infof("Input param → page=%s", page);

        Response challenge = context.form().createForm(page);
        logger.info("Created challenge response for page");

        context.challenge(challenge);
        logger.infof("Issued challenge for page=%s", page);

        logger.info("goPage() - completed");
    }


	private void goPage(AuthenticationFlowContext context, String page, String errorMsg,
			Map<String, String> attributes) {
		LoginFormsProvider resForm = context.form();
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
        logger.info("getEmailOrMobileNumber() - started");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("Decoded form parameters: %s", formData);

        String emailOrMobile = formData.getFirst(Constants.ATTR_USER_EMAIL_OR_PHONE);
        logger.infof("Extracted value for ATTR_USER_EMAIL_OR_PHONE: %s", emailOrMobile);

        if (emailOrMobile == null) {
            logger.info("emailOrMobile is null → returning empty string");
            return "";
        }

        logger.infof("Returning emailOrMobile=%s", emailOrMobile);
        logger.info("getEmailOrMobileNumber() - completed");
        return emailOrMobile;
    }


    private UserModel getUserByMobileNumber(AuthenticationFlowContext context, String mobilePhone) {
        logger.info("getUserByMobileNumber() - started");
        logger.infof("Input param → mobilePhone=%s", mobilePhone);

        UserModel user = null;
        try {
            logger.info("Attempting to fetch user by name/email/phone");
            user = SunbirdModelUtils.getUserByNameEmailOrPhone(context, mobilePhone);
            logger.infof("User lookup result: %s",
                    (user != null ? user.getUsername() : "null (no user found)"));
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);
            logger.error("ModelDuplicateException occurred while fetching user", mde);

            String duplicateField = mde.getDuplicateFieldName();
            logger.infof("Duplicate field detected: %s", duplicateField);

            if (duplicateField != null && duplicateField.equals(UserModel.EMAIL)) {
                logger.info("Handling duplicate EMAIL conflict");
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
                        AuthenticationFlowError.USER_CONFLICT);
            } else if (duplicateField != null && duplicateField.equals(UserModel.USERNAME)) {
                logger.info("Handling duplicate USERNAME conflict");
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
                        AuthenticationFlowError.USER_CONFLICT);
            } else if (duplicateField != null
                    && duplicateField.equals(KeycloakSmsAuthenticatorConstants.ATTR_MOBILE)) {
                logger.info("Handling duplicate MOBILE conflict");
                setDuplicateUserChallenge(context, Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE,
                        Constants.MULTIPLE_USER_ASSOCIATED_WITH_PHONE, AuthenticationFlowError.USER_CONFLICT);
            }

            logger.info("Returning null due to ModelDuplicateException");
            return null;
        }

        if (invalidUser(context, user)) {
            logger.info("User is invalid as per invalidUser() check → returning null");
            return null;
        }

        logger.infof("Returning user=%s", user != null ? user.getUsername() : "null");
        logger.info("getUserByMobileNumber() - completed");
        return user;
    }

    private void sendOtp(AuthenticationFlowContext context, String redirectUri) {
        logger.info("sendOtp() - started");
        logger.infof("Input param → redirectUri=%s", redirectUri);

        String emailOrMobile = getEmailOrMobileNumber(context);
        logger.infof("Extracted emailOrMobile=%s", emailOrMobile);

        UserModel user = getUserByMobileNumber(context, emailOrMobile);
        logger.infof("User lookup result → %s", (user != null ? user.getUsername() : "null"));

        if (user == null) {
            logger.info("User not found → going to error page");
            goErrorPage(context, "Oops, Member not found.");
            logger.info("sendOtp() - exiting (user not found)");
            return;
        }

        if (context.getUser() != null) {
            logger.infof("Session already has userId=%s → validating against looked-up userId=%s",
                    context.getUser().getId(), user.getId());
            if (!user.getId().equalsIgnoreCase(context.getUser().getId())) {
                logger.errorf("User mismatch detected. Saved userId=%s, New userId=%s",
                        context.getUser().getId(), user.getId());
                context.getEvent().getEvent().setError(Errors.DIFFERENT_USER_AUTHENTICATED);
                goErrorPage(context, "Authentication Error! Please enter your credentials again.");
                logger.info("sendOtp() - exiting (different user conflict)");
                return;
            }
        }

        logger.info("Generating OTP attributes");
        Map<String, String> attributes = generateOTP(context);
        logger.infof("Generated OTP attributes: %s", attributes);

        String otpCode = attributes.get(Constants.SESSION_OTP_CODE);
        logger.infof("Attempting to send OTP via SMS/Email to %s", emailOrMobile);

        if (sendOtpByEmailOrSms(context, emailOrMobile, otpCode)) {
            logger.info("OTP sent successfully → storing details in authentication session");

            context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE, otpCode);
            context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_EXPIRE_TIME,
                    attributes.get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL));
            context.getAuthenticationSession().setAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER, emailOrMobile);
            context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI, redirectUri);

            logger.infof("Saving user details in session with userId=%s", user.getId());
            context.setUser(user);

            logger.info("Redirecting to OTP input page with attributes");
            goPage(context, Constants.PAGE_INPUT_OTP, StringUtils.EMPTY, attributes);
        } else {
            logger.error("Failed to send OTP → going to error page");
            goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
        }

        logger.info("sendOtp() - completed");
    }


    private void resendOtp(AuthenticationFlowContext context) {
        logger.info("resendOtp() - started");

        String mobileNumber = context.getAuthenticationSession()
                .getAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER);
        logger.infof("Fetched mobileNumber from session: %s", mobileNumber);

        logger.info("Generating new OTP attributes");
        Map<String, String> attributes = generateOTP(context);
        logger.infof("Generated OTP attributes: %s", attributes);

        String otpCode = attributes.get(Constants.SESSION_OTP_CODE);
        context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE, otpCode);
        logger.infof("Stored new OTP code in authentication session: %s", otpCode);

        logger.infof("Attempting to resend OTP to %s", mobileNumber);
        if (sendOtpByEmailOrSms(context, mobileNumber, otpCode)) {
            logger.info("OTP resent successfully → redirecting to OTP input page");
            goPage(context, Constants.PAGE_INPUT_OTP);
        } else {
            logger.error("Failed to resend OTP → going to error page");
            goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
        }

        logger.info("resendOtp() - completed");
    }


    private boolean sendOtpByEmailOrSms(AuthenticationFlowContext context, String mobileNumber, String otp) {
        logger.info("sendOtpByEmailOrSms() - started");
        logger.infof("Input params → mobileNumber=%s, otp=%s", mobileNumber, otp);

        boolean retValue = false;
        String userNameType = isEmailOrMobileNumber(mobileNumber);
        logger.infof("Determined userNameType=%s", userNameType);

        switch (userNameType) {
            case Constants.PHONE:
                logger.info("Handling case: PHONE");

                AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
                String smsProvider = null;
                if (configModel != null && configModel.getConfig() != null) {
                    smsProvider = configModel.getConfig().get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_PROVIDER);
                }
                logger.infof("SMS for OTP initiated with provider=%s", smsProvider);

                if (Constants.MSG91_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Using MSG91 provider to send OTP");
                    retValue = KeycloakSmsAuthenticatorUtil.send(mobileNumber, otp);
                } else if (Constants.Free2SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Using Free2SMS provider to send OTP");
                    retValue = sendSmsViaFast2Sms(mobileNumber, otp);
                } else if (Constants.NIC_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Using NIC provider to send OTP");
                    long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
                            KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
                    logger.infof("NIC provider TTL=%d seconds", ttl);
                    retValue = sendSmsViaNIC(mobileNumber, otp, String.valueOf(ttl / 60));
                } else if (Constants.AMNEX_SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Using Amnex provider to send OTP");
                    long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
                            KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
                    logger.infof("Amnex provider TTL=%d seconds", ttl);
                    retValue = sendSmsViaAmnex(mobileNumber, otp, String.valueOf(ttl / 60));
                } else if (Constants.NETCORE_SMS_PROVIDER.equalsIgnoreCase(smsProvider)) {
                    logger.info("Using NetCore provider to send OTP");
                    long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
                            KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, 5 * 60L);
                    logger.infof("NetCore provider TTL=%d seconds", ttl);
                    retValue = sendSmsViaNetCore(mobileNumber, otp, String.valueOf(ttl / 60));
                } else {
                    logger.errorf("SMS Provider not configured properly. Current value=%s. Expected value: NIC / MSG91 / others", smsProvider);
                }
                break;

            case Constants.EMAIL:
                logger.info("Handling case: EMAIL");
                retValue = sendEmailViaSunbird(context, mobileNumber, otp);
                break;

            default:
                logger.error("Failed to identify whether given key is email or mobile");
                break;
        }

        logger.infof("sendOtpByEmailOrSms() - completed, retValue=%s", retValue);
        return retValue;
    }


    private boolean sendSmsViaNIC(String mobileNumber, String otp, String expiryTime) {
        logger.info("sendSmsViaNIC() - started");
        logger.infof("Input params → mobileNumber=%s, expiryTime=%s", mobileNumber, expiryTime);

        boolean retValue = NicSmsProvider.getInstance()
                .send(mobileNumber, otp, expiryTime, SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
        logger.infof("NIC SMS send invoked → result=%s", retValue);

        logger.info("sendSmsViaNIC() - completed");
        return retValue;
    }


    private boolean sendSmsViaFast2Sms(String mobileNumber, String otp) {
        logger.info("sendSmsViaFast2Sms() - started");
        logger.infof("Input params → mobileNumber=%s, otp=%s", mobileNumber, otp);

        List<String> acceptedNumbers = new ArrayList<>();
        String allowedNumbers = System.getenv(Constants.SMS_OTP_NUMBERS);
        if (StringUtils.isNotBlank(allowedNumbers)) {
            acceptedNumbers = Arrays.asList(allowedNumbers.split(",", -1));
            logger.infof("Loaded acceptedNumbers from env: %s", acceptedNumbers);
        } else {
            logger.info("No acceptedNumbers configured in env");
        }

        if (!acceptedNumbers.contains(mobileNumber)) {
            logger.warnf("Mobile number %s is not in acceptedNumbers → returning false", mobileNumber);
            return false;
        }

        try {
            logger.info("Constructing Fast2SMS API request URL");
            StringBuilder strUrl = new StringBuilder(System.getenv(Constants.FAST2SMS_API_URL));
            strUrl.append("?authorization=").append(System.getenv(Constants.FAST2SMS_API_KEY));
            strUrl.append("&route=v3");
            strUrl.append("&sender_id=FTWSMS");
            strUrl.append("&message=Your%20OTP%20login%20into%20iGOT%20System%20is%20:%20").append(otp);
            strUrl.append("&language=english&flash=0");
            strUrl.append("&numbers=").append(mobileNumber);

            logger.infof("Constructed Fast2SMS request URL: %s", strUrl);

            logger.info("Opening HTTP connection to Fast2SMS API");
            HttpURLConnection conn = (HttpURLConnection) new URL(strUrl.toString()).openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");

            logger.info("Reading response from Fast2SMS API");
            final BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            final StringBuffer stringBuffer = new StringBuffer();
            String line;
            while ((line = rd.readLine()) != null) {
                stringBuffer.append(line);
            }
            rd.close();

            logger.infof("Fast2SMS response: %s", stringBuffer.toString());
            logger.info("sendSmsViaFast2Sms() - completed successfully");
            return true;
        } catch (Exception e) {
            logger.error("Exception while sending SMS via Fast2SMS", e);
        }

        logger.info("sendSmsViaFast2Sms() - completed with failure");
        return false;
    }

    private Map<String, String> generateOTP(AuthenticationFlowContext context) {
        logger.info("generateOTP() - started");

        long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(
                context.getAuthenticatorConfig(),
                KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_LENGTH,
                6L
        );
        logger.infof("Configured OTP length (nrOfDigits) = %d", nrOfDigits);

        long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(
                context.getAuthenticatorConfig(),
                KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL,
                5 * 60L
        );
        logger.infof("Configured OTP TTL = %d seconds", ttl);

        String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);
        logger.infof("Generated OTP code = %s", code);

        Long expireTime = (new Date()).getTime() + (ttl * 1000);
        logger.infof("Calculated OTP expiryTime (epoch ms) = %d", expireTime);

        Map<String, String> attributes = new HashMap<>();
        attributes.put(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, String.valueOf(expireTime));
        attributes.put(Constants.SESSION_OTP_CODE, code);
        logger.infof("OTP attributes prepared: %s", attributes);

        logger.info("generateOTP() - completed");
        return attributes;
    }


    private Map<String, String> generateOTP(AuthenticationFlowContext context) {
        logger.info("generateOTP() - started");

        // Step 1: Fetch OTP length
        long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(
                context.getAuthenticatorConfig(),
                KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_LENGTH,
                6L
        );
        logger.infof("Step 1: OTP length configured = %d", nrOfDigits);

        // Step 2: Fetch OTP TTL
        long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(
                context.getAuthenticatorConfig(),
                KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL,
                5 * 60L
        );
        logger.infof("Step 2: OTP TTL configured = %d seconds", ttl);

        // Step 3: Generate OTP
        String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);
        logger.infof("Step 3: Generated OTP (masked) = ****%s",
                (code != null && code.length() > 2 ? code.substring(code.length() - 2) : code));

        // Step 4: Calculate expiry time
        Long expireTime = (new Date()).getTime() + (ttl * 1000);
        logger.infof("Step 4: Calculated expiry time (epoch ms) = %d", expireTime);

        // Step 5: Prepare attributes map
        Map<String, String> attributes = new HashMap<>();
        attributes.put(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL, String.valueOf(expireTime));
        attributes.put(Constants.SESSION_OTP_CODE, code);
        logger.infof("Step 5: OTP attributes map prepared with keys=%s", attributes.keySet());

        logger.info("generateOTP() - completed");
        return attributes;
    }

    private String isEmailOrMobileNumber(String emailOrMobile) {
        logger.info("isEmailOrMobileNumber() - started");
        logger.infof("Input param → emailOrMobile=%s", emailOrMobile);

        String numberRegex = "\\d+";
        String emailRegex = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
                + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
        logger.info("Defined regex patterns for number and email");

        if (emailOrMobile.matches(numberRegex) && emailOrMobile.length() == 10) {
            logger.info("Input matches numberRegex and length=10 → identified as PHONE");
            return Constants.PHONE;
        } else if (emailOrMobile.matches(emailRegex)) {
            logger.info("Input matches emailRegex → identified as EMAIL");
            return Constants.EMAIL;
        }

        logger.info("Input did not match numberRegex or emailRegex → returning EMPTY");
        logger.info("isEmailOrMobileNumber() - completed");
        return StringUtils.EMPTY;
    }


    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        logger.info("validateCode() - started");

        CODE_STATUS result = CODE_STATUS.INVALID;
        logger.infof("Initial result set to %s", result);

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("Decoded form parameters: %s", formData);

        String enteredCode = formData.getFirst(KeycloakSmsAuthenticatorConstants.ANSW_SMS_CODE);
        logger.infof("Entered OTP code (masked) = ****%s",
                (enteredCode != null && enteredCode.length() > 2 ? enteredCode.substring(enteredCode.length() - 2) : enteredCode));

        String storedCode = context.getAuthenticationSession().getAuthNote(Constants.SESSION_OTP_CODE);
        logger.infof("Stored OTP code (masked) = ****%s",
                (storedCode != null && storedCode.length() > 2 ? storedCode.substring(storedCode.length() - 2) : storedCode));

        if (storedCode != null && enteredCode != null) {
            result = storedCode.equalsIgnoreCase(enteredCode) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            logger.infof("OTP comparison result = %s", result);
        } else {
            logger.info("Either storedCode or enteredCode is null → keeping result as INVALID");
        }

        String storedExpiryValue = context.getAuthenticationSession().getAuthNote(Constants.SESSION_OTP_EXPIRE_TIME);
        logger.infof("Fetched storedExpiryValue = %s", storedExpiryValue);

        if (result == CODE_STATUS.VALID && StringUtils.isNotBlank(storedExpiryValue)) {
            Long currentTime = (new Date()).getTime();
            Long storedExpiryTime = Long.parseLong(storedExpiryValue);
            logger.infof("CurrentTime=%d, StoredExpiryTime=%d", currentTime, storedExpiryTime);

            result = storedExpiryTime >= currentTime ? CODE_STATUS.VALID : CODE_STATUS.EXPIRED;
            logger.infof("Expiry check updated result = %s", result);
        } else {
            logger.info("Expiry validation skipped (either result != VALID or storedExpiryValue is blank)");
        }

        logger.infof("validateCode() - completed with final result=%s", result);
        return result;
    }


    private void storeSMSCodeInDB(AuthenticationFlowContext context, String code, Long expiringAt) {
        logger.info("storeSMSCodeInDB() - started");
        logger.infof("Input params → code(masked)=****%s, expiringAt=%d",
                (code != null && code.length() > 2 ? code.substring(code.length() - 2) : code),
                expiringAt);

        logger.info("Creating UserCredentialModel for SMS code");
        UserCredentialModel credentials = new UserCredentialModel();
        credentials.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
        credentials.setValue(code);
        credentials.setNote(Constants.TTL, String.valueOf(expiringAt));
        logger.info("Prepared credentials for SMS code with TTL note");

        logger.info("Updating credential manager with SMS code credential");
        context.getSession().userCredentialManager().updateCredential(
                context.getRealm(),
                context.getUser(),
                credentials
        );
        logger.info("SMS code credential stored successfully");

        logger.info("Creating UserCredentialModel for SMS expiry time");
        credentials = new UserCredentialModel();
        credentials.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
        credentials.setValue(expiringAt.toString());

        logger.info("Updating credential manager with SMS expiry credential");
        context.getSession().userCredentialManager().updateCredential(
                context.getRealm(),
                context.getUser(),
                credentials
        );
        logger.info("SMS expiry time credential stored successfully");

        logger.info("storeSMSCodeInDB() - completed");
    }


    private CODE_STATUS validateCodeUsingDB(AuthenticationFlowContext context) {
        logger.info("validateCodeUsingDB() - started");

        CODE_STATUS result = CODE_STATUS.INVALID;
        logger.infof("Initial result set to %s", result);

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(KeycloakSmsAuthenticatorConstants.ANSW_SMS_CODE);
        logger.infof("Entered OTP (masked)=****%s",
                (enteredCode != null && enteredCode.length() > 2 ? enteredCode.substring(enteredCode.length() - 2) : enteredCode));

        KeycloakSession session = context.getSession();
        logger.info("Fetched KeycloakSession from context");

        logger.info("Fetching stored OTP code credentials from DB");
        List<?> codeCreds = session.userCredentialManager().getStoredCredentialsByType(
                context.getRealm(),
                context.getUser(),
                KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE
        );
        logger.infof("Retrieved codeCreds size=%d", (codeCreds != null ? codeCreds.size() : 0));

        if (!CollectionUtils.isNullOrEmpty(codeCreds)) {
            CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);
            logger.infof("Stored OTP (masked)=****%s",
                    (expectedCode.getValue() != null && expectedCode.getValue().length() > 2
                            ? expectedCode.getValue().substring(expectedCode.getValue().length() - 2)
                            : expectedCode.getValue()));

            result = enteredCode.equals(expectedCode.getValue()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            logger.infof("OTP validation result=%s", result);
        } else {
            logger.info("No stored OTP code credentials found");
        }

        if (result == CODE_STATUS.VALID) {
            logger.info("Fetching stored OTP expiry credentials from DB");
            List<?> timeCreds = session.userCredentialManager().getStoredCredentialsByType(
                    context.getRealm(),
                    context.getUser(),
                    KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME
            );
            logger.infof("Retrieved timeCreds size=%d", (timeCreds != null ? timeCreds.size() : 0));

            if (!CollectionUtils.isNullOrEmpty(timeCreds)) {
                CredentialModel expTimeString = (CredentialModel) timeCreds.get(0);
                Long currentTime = (new Date()).getTime();
                Long expiringAt = Long.parseLong(expTimeString.getValue());

                logger.infof("CurrentTime=%d, ExpiringAt=%d, isExpired=%s",
                        currentTime, expiringAt, (currentTime >= expiringAt));
                // Note: Expiry validation logic currently commented out
            } else {
                logger.info("No stored OTP expiry credentials found");
            }
        }

        if (result == CODE_STATUS.VALID) {
            logger.info("Removing stored OTP code and expiry credentials from DB");
            session.userCredentialManager().removeStoredCredential(
                    context.getRealm(),
                    context.getUser(),
                    KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE
            );
            session.userCredentialManager().removeStoredCredential(
                    context.getRealm(),
                    context.getUser(),
                    KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME
            );
            logger.info("Stored credentials successfully removed after validation");
        }

        logger.infof("validateCodeUsingDB() - completed with result=%s", result);
        return result;
    }


    private boolean sendSmsViaAmnex(String mobileNumber, String otp, String expiryTime) {
        logger.info("sendSmsViaAmnex() - started");
        logger.infof("Input params → mobileNumber=%s, expiryTime=%s, otp(masked)=****%s",
                mobileNumber,
                expiryTime,
                (otp != null && otp.length() > 2 ? otp.substring(otp.length() - 2) : otp));

        logger.info("Invoking AmnexSmsProvider to send OTP");
        boolean retValue = AmnexSmsProvider.getInstance().send(
                mobileNumber,
                otp,
                expiryTime,
                SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE
        );
        logger.infof("AmnexSmsProvider.send() returned result=%s", retValue);

        logger.info("sendSmsViaAmnex() - completed");
        return retValue;
    }


    private boolean sendSmsViaNetCore(String mobileNumber, String otp, String expiryTime) {
        logger.info("sendSmsViaNetCore() - started");
        logger.infof("Input params → mobileNumber=%s, expiryTime=%s, otp(masked)=****%s",
                mobileNumber,
                expiryTime,
                (otp != null && otp.length() > 2 ? otp.substring(otp.length() - 2) : otp));

        mobileNumber = "91" + mobileNumber;
        logger.infof("Updated mobileNumber with country code prefix: %s", mobileNumber);

        logger.info("Invoking NetCoreSMSProvider to send OTP");
        boolean retValue = NetCoreSMSProvider.getInstance().send(
                mobileNumber,
                otp,
                expiryTime,
                SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE
        );
        logger.infof("NetCoreSMSProvider.send() returned result=%s", retValue);

        logger.info("sendSmsViaNetCore() - completed");
        return retValue;
    }


    private String generateSecretKey() {
        logger.info("generateSecretKey() - started");

        // Step 1: Get current time as formatted string
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        String timeComponent = dateFormat.format(new Date(System.currentTimeMillis()));
        logger.infof("Step 1: Generated timeComponent = %s", timeComponent);

        // Step 2: Generate random number (0–9999)
        int randomComponent = random.nextInt(10000);
        logger.infof("Step 2: Generated randomComponent = %04d", randomComponent);

        // Step 3: Combine time + random
        String secretKey = timeComponent + String.format("%04d", randomComponent);
        logger.infof("Step 3: Combined raw secretKey = %s", secretKey);

        // Step 4: Ensure 16 digits
        String finalKey = secretKey.length() > 16 ? secretKey.substring(0, 16) : secretKey;
        logger.infof("Step 4: Final secretKey (16 digits) = %s", finalKey);

        logger.info("generateSecretKey() - completed");
        return finalKey;
    }


    public boolean validateUserAndPassword(AuthenticationFlowContext context,
                                           MultivaluedMap<String, String> inputData) {
        logger.info("validateUserAndPassword() - started");

        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        logger.infof("Fetched username input = %s", username);

        if (username == null) {
            logger.warn("Username is null → returning failure");
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, Messages.INVALID_USER);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }

        // remove leading and trailing whitespace
        username = username.trim();
        logger.infof("Trimmed username = %s", username);

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession()
                .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);
        logger.info("Stored attempted username in authentication session");

        UserModel user = null;
        try {
            logger.info("Attempting to find user by name or email...");
            user = KeycloakModelUtils.findUserByNameOrEmail(
                    context.getSession(), context.getRealm(), username);
            logger.infof("User lookup result: %s", (user != null ? user.getUsername() : "null"));
        } catch (ModelDuplicateException mde) {
            logger.error("ModelDuplicateException occurred while finding user", mde);

            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                logger.warn("Duplicate user found with EMAIL");
                context.getEvent().getEvent().setError(Errors.EMAIL_IN_USE);
            } else {
                logger.warn("Duplicate user found with USERNAME");
                context.getEvent().getEvent().setError(Errors.USERNAME_IN_USE);
            }
            return false;
        }

        if (user == null) {
            logger.warn("User not found → returning failure");
            context.getEvent().getEvent().setError(Errors.USER_NOT_FOUND);
            return false;
        }

        if (!user.isEnabled()) {
            logger.warnf("User '%s' is disabled → returning failure", user.getUsername());
            context.getEvent().getEvent().setError(Errors.USER_DISABLED);
            return false;
        }

        if (context.getRealm().isBruteForceProtected()) {
            logger.info("Realm has brute force protection enabled");
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                logger.warnf("User '%s' is temporarily disabled due to brute force protection", user.getUsername());
                context.getEvent().getEvent().setError(Errors.USER_TEMPORARILY_DISABLED);
                return false;
            }
        }

        logger.info("Validating user password...");
        if (!validatePassword(context, user, inputData)) {
            logger.warnf("Password validation failed for user '%s'", user.getUsername());
            context.getEvent().getEvent().setError(Errors.INVALID_USER_CREDENTIALS);
            return false;
        }

        String rememberMe = inputData.getFirst("rememberMe");
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        logger.infof("RememberMe flag = %s", remember);

        if (remember) {
            logger.info("Setting REMEMBER_ME = true in session and event details");
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            logger.info("Removing REMEMBER_ME flag from session");
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }

        context.setUser(user);
        logger.infof("User '%s' successfully authenticated", user.getUsername());

        logger.info("validateUserAndPassword() - completed successfully");
        return true;
    }


    public boolean validatePassword(AuthenticationFlowContext context, UserModel user,
                                    MultivaluedMap<String, String> inputData) {
        logger.info("validatePassword() - started");
        logger.infof("Validating password for userId=%s", (user != null ? user.getId() : "null"));

        String encryptedPassword = inputData.getFirst(CredentialRepresentation.PASSWORD);
        logger.infof("Fetched encryptedPassword (length=%d)", (encryptedPassword != null ? encryptedPassword.length() : 0));

        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        logger.infof("Retrieved secretKey (masked) = %s",
                (secretKey != null && secretKey.length() > 4 ? secretKey.substring(0, 4) + "****" : secretKey));

        String iv = inputData.getFirst(Constants.IV);
        logger.infof("Fetched IV (length=%d)", (iv != null ? iv.length() : 0));

        // Decrypt the password
        logger.info("Decrypting password...");
        String decryptedPassword = decryptPassword(encryptedPassword, secretKey, iv);
        logger.infof("Decryption result → decryptedPassword (length=%d, masked=*****)",
                (decryptedPassword != null ? decryptedPassword.length() : 0));

        List<CredentialInput> credentials = new LinkedList<>();
        credentials.add(UserCredentialModel.password(decryptedPassword));
        logger.info("Prepared CredentialInput list for validation");

        boolean isValid = (decryptedPassword != null && !decryptedPassword.isEmpty()
                && context.getSession().userCredentialManager().isValid(context.getRealm(), user, credentials));

        if (isValid) {
            logger.infof("Password validation successful for userId=%s", user.getId());
        } else {
            logger.warnf("Password validation failed for userId=%s", user.getId());
        }

        logger.info("validatePassword() - completed");
        return isValid;
    }


    private String decryptPassword(String encryptedPassword, String secretKey, String iv) {
        logger.info("decryptPassword() - started");

        try {
            logger.infof("Input params → encryptedPassword length=%d, secretKey(masked)=%s, iv length=%d",
                    (encryptedPassword != null ? encryptedPassword.length() : 0),
                    (secretKey != null && secretKey.length() > 4 ? secretKey.substring(0, 4) + "****" : secretKey),
                    (iv != null ? iv.length() : 0));

            // Step 1: Decode Base64 encrypted password
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
            logger.infof("Step 1: Decoded encryptedPassword into %d bytes", decodedBytes.length);

            // Step 2: Decode Base64 IV
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            logger.infof("Step 2: Decoded IV into %d bytes", ivBytes.length);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // Step 3: Initialize Cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            logger.info("Step 3: Cipher initialized for AES/CBC/PKCS5Padding");

            // Step 4: Perform decryption
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            logger.infof("Step 4: Decryption produced %d bytes", decryptedBytes.length);

            String decryptedPassword = new String(decryptedBytes, "UTF-8");
            logger.infof("Step 5: Successfully decrypted password (length=%d, masked=*****)",
                    decryptedPassword.length());

            logger.info("decryptPassword() - completed successfully");
            return decryptedPassword;
        } catch (Exception e) {
            logger.error("decryptPassword() - Exception occurred while decrypting password", e);
            throw new RuntimeException("Error while decrypting password", e);
        }
    }

}
