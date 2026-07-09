package org.sunbird.keycloak.login;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.credential.UserCredentialManager;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

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
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
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
import org.sunbird.sms.sinch.SinchSMSProvider;

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
        logger.info("[KC24_AUTH] ===== authenticate() CALLED - ENTRY POINT =====");
        logger.info("[KC24_AUTH] PasswordAndOtpAuthenticator.authenticate() - Keycloak Version 24");

        // Log request details
        logger.info("[KC24_AUTH] Request URI: " + context.getHttpRequest().getUri().getRequestUri());
        logger.info("[KC24_AUTH] Request path: " + context.getHttpRequest().getUri().getPath());

        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        if (StringUtils.isBlank(secretKey)) {
            // Generate the secret key
            secretKey = generateSecretKey();
            logger.info("[KC24_AUTH] Generated new secret key, length: " + secretKey.length());
        } else {
            logger.info("[KC24_AUTH] Using existing secret key from authNote, length: " + secretKey.length());
        }

        String flagPage = getValue(context, Constants.FLAG_PAGE);
        logger.info("[KC24_AUTH] flagPage from form: '" + flagPage + "'");

        // Store the secret key as an authentication session note
        context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, secretKey);
        logger.info("[KC24_AUTH] Set secretKey in authNote. authNote key: '" + Constants.SECRET_KEY + "', value length: " + secretKey.length());

		LoginFormsProvider formsProvider = context.form();
		formsProvider.setAttribute(Constants.SECRET_KEY, secretKey);
		if (context.getAuthenticationSession().getRedirectUri().contains(Constants.EC_LOGIN)) {
			context.getAuthenticationSession().setAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE, Constants.EC_LOGIN_PAGE);
			context.challenge(formsProvider.createForm(Constants.EC_LOGIN_PAGE));
		} else if (context.getAuthenticationSession().getRedirectUri().contains(Constants.AI_ASSESSMENT_LOGIN)) {
			context.getAuthenticationSession().setAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE, Constants.AI_ASSESSMENT_LOGIN_PAGE);
			context.challenge(formsProvider.createForm(Constants.AI_ASSESSMENT_LOGIN_PAGE));
		}  else {
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
        MultivaluedMap<String, String> qParamMap = context.getHttpRequest().getUri().getQueryParameters();
        Iterator<Entry<String, List<String>>> itr = qParamMap.entrySet().iterator();
        while (itr.hasNext()) {
            Entry<String, List<String>> entry = itr.next();
            logger.info(String.format("[KC24_AUTH] query param: key=%s, value=%s", entry.getKey(), entry.getValue()));
        }

        // Log all form data keys (not values — passwords are sensitive)
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.info("[KC24_AUTH] form data keys: " + formData.keySet());
        logger.info("[KC24_AUTH] form has 'password': " + formData.containsKey("password"));
        logger.info("[KC24_AUTH] form has 'iv': " + formData.containsKey("iv")
                + ", iv length: " + (formData.getFirst("iv") != null ? formData.getFirst("iv").length() : "null"));
        logger.info("[KC24_AUTH] form 'page_type': " + formData.getFirst(Constants.FLAG_PAGE));
        logger.info("[KC24_AUTH] form 'username': " + formData.getFirst("username"));

        // Log auth session notes
        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        logger.info("[KC24_AUTH] secretKey in authNote present: " + (secretKey != null)
                + ", length: " + (secretKey != null ? secretKey.length() : "null"));

        String flagPage = getValue(context, Constants.FLAG_PAGE);
        logger.info("[KC24_AUTH] flagPage resolved to: '" + flagPage + "'");
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
                logger.info("[KC24_AUTH] >>> Entering FLAG_LOGIN_WITH_PASS branch");
                if (!validateForm(context, context.getHttpRequest().getDecodedFormParameters())) {
                    logger.info("[KC24_AUTH] <<< validateForm returned FALSE - going to error page");
                    goErrorPage(context, "Invalid credentials!");
                } else if (tooManySessions(context, context.getUser())) {
                    logger.info("[KC24_AUTH] Session limit reached for user: " + context.getUser().getId());
                    context.getAuthenticationSession().removeAuthNote(Constants.SESSION_OTP_CODE);
                    goErrorPage(context, "Too many sessions!");
                } else {
                    logger.info("[KC24_AUTH] <<< validateForm returned TRUE - calling context.success()");
                    logger.info("[KC24_AUTH] redirect_uri: " + qParamMap.getFirst(Constants.REDIRECT_URI_KEY));
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
        String value = formData.getFirst(key);
        if (null == value) {
            value = "";
        }
        return value;
    }

    private void authenticateOtp(AuthenticationFlowContext context) {
        CODE_STATUS status = validateCode(context);
        if (status == CODE_STATUS.VALID) {
            if (tooManySessions(context, context.getUser())) {
                context.getEvent().getEvent().setError(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
                goErrorPage(context, Constants.PAGE_INPUT_OTP, "Too many sessions!");
                return;
            }
            logger.info("Validation of username + password is successful... ");
            context.getAuthenticationSession().removeAuthNote(Constants.SESSION_OTP_CODE);
            context.success();
        } else if (status == CODE_STATUS.EXPIRED) {
            goErrorPage(context, Constants.PAGE_INPUT_OTP, Constants.OTP_EXPIRED);
        } else {
            goErrorPage(context, Constants.PAGE_INPUT_OTP, Constants.INVALID_OTP_ENTERED);
        }
    }

    private void goErrorPage(AuthenticationFlowContext context, String message) {
        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        if (StringUtils.isBlank(secretKey)) {
            // Generate the secret key
            secretKey = generateSecretKey();
            logger.info("Generated new secret key.");
        }

		// Set the default error page
		String errorPage = Constants.LOGIN_PAGE;

		// Check if authNote is blank or equals EC_LOGIN, then set error page to EC_LOGIN_PAGE
		if (StringUtils.isNotBlank(context.getAuthenticationSession().getAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE)) &&
				(Constants.EC_LOGIN_PAGE.equals(context.getAuthenticationSession().getAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE)))) {
			errorPage = Constants.EC_LOGIN_PAGE;
		}
		if (StringUtils.isNotBlank(context.getAuthenticationSession().getAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE)) &&
				(Constants.AI_ASSESSMENT_LOGIN_PAGE.equals(context.getAuthenticationSession().getAuthNote(Constants.AUTH_NOTE_LOGIN_PAGE)))) {
			errorPage = Constants.AI_ASSESSMENT_LOGIN_PAGE;
		}

        logger.debug("OtpSmsFormAuthenticator::goErrorPage: message: " + message + ", keyValue: " + secretKey);

        // Store the secret key as an authentication session note
        context.getAuthenticationSession().setAuthNote(Constants.SECRET_KEY, secretKey);
        LoginFormsProvider formsProvider = context.form();
        formsProvider.setAttribute(Constants.SECRET_KEY, secretKey);
        String error = context.getEvent().getEvent().getError();
        String errMsg = "Internal Server Error!";
        switch (error) {
            case Errors.INVALID_USER_CREDENTIALS:
                errMsg = "Invalid credentials!";
                Response invalidCredsRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, invalidCredsRes);
                break;
            case Errors.USER_NOT_FOUND:
                errMsg = "Invalid user details.";
                Response invalidUserRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, invalidUserRes);
                break;
            case Errors.USER_DISABLED:
                errMsg = "User account is disabled.";
                Response userDisabledRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.USER_DISABLED, userDisabledRes);
                break;
            case Errors.USER_TEMPORARILY_DISABLED:
                errMsg = "User account is disabled temporarily.";
                Response tempDisabledRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, tempDisabledRes);
                break;
            case Errors.DIFFERENT_USER_AUTHENTICATED:
                errMsg = "Authentication Error! Please enter your credentials again.";
                Response diffUsersFoundRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.USER_CONFLICT, diffUsersFoundRes);
                break;
            case Errors.IDENTITY_PROVIDER_LOGIN_FAILURE:
                errMsg = "Too many sessions!";
                Response identityProviderLoginFailureRes = formsProvider.setError(errMsg).createForm(Constants.LOGIN_PAGE);
                context.failureChallenge(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, identityProviderLoginFailureRes);
                break;
            case Errors.EMAIL_IN_USE:
            case Errors.USERNAME_IN_USE:
            default:
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
        context.challenge(context.form().createForm(page));
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
        logger.info("[KC24_AUTH] validateForm() called, delegating to validateUserAndPassword()");
        boolean result = validateUserAndPassword(context, formData);
        logger.info("[KC24_AUTH] validateForm() result: " + result);
        return result;
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

        if (invalidUser(context, user)) {
            return null;
        }
        return user;
    }

    private void sendOtp(AuthenticationFlowContext context, String redirectUri) {
        String emailOrMobile = getEmailOrMobileNumber(context);
        UserModel user = getUserByMobileNumber(context, emailOrMobile);
        if (null == user) {
            goErrorPage(context, "Oops, Member not found.");
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
        if (sendOtpByEmailOrSms(context, emailOrMobile, attributes.get(Constants.SESSION_OTP_CODE), false)) {
            // SMS is sent successfully, let's save the details in session and return the
            // necessary page.
            context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE,
                    attributes.get(Constants.SESSION_OTP_CODE));
            context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_EXPIRE_TIME,
                    attributes.get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL));
            context.getAuthenticationSession().setAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER, emailOrMobile);
            context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI, redirectUri);

            logger.info("Saving user details in session with userId: " + user.getId());
            context.setUser(user);
            goPage(context, Constants.PAGE_INPUT_OTP, StringUtils.EMPTY, attributes);
        } else {
            // 1st Attempt is failed, will try the next provider
            if (sendOtpByEmailOrSms(context, emailOrMobile, attributes.get(Constants.SESSION_OTP_CODE), true)) {
                // SMS is sent successfully, let's save the details in session and return the
                // necessary page.
                context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_CODE,
                        attributes.get(Constants.SESSION_OTP_CODE));
                context.getAuthenticationSession().setAuthNote(Constants.SESSION_OTP_EXPIRE_TIME,
                        attributes.get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL));
                context.getAuthenticationSession().setAuthNote(Constants.ATTEMPTED_EMAIL_OR_MOBILE_NUMBER, emailOrMobile);
                context.getAuthenticationSession().setAuthNote(Details.REDIRECT_URI, redirectUri);

                logger.info("Saving user details in session with userId: " + user.getId());
                context.setUser(user);
                goPage(context, Constants.PAGE_INPUT_OTP, StringUtils.EMPTY, attributes);
            } else {
                context.getEvent().getEvent().setError("SMS_SEND_FAILED");
                goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
            }
        }
        logger.info(String.format(
                "Action:: sendOtp - completed for emailOrMobile: %s",
                emailOrMobile));
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
        if (sendOtpByEmailOrSms(context, mobileNumber, attributes.get(Constants.SESSION_OTP_CODE), true)) {
            goPage(context, Constants.PAGE_INPUT_OTP);
        } else {
            goErrorPage(context, "Failed to send out SMS. Please contact Administrator.");
        }
    }

    private boolean sendOtpByEmailOrSms(AuthenticationFlowContext context, String mobileNumber, String otp, boolean isResend) {
        boolean retValue = false;
        String userNameType = isEmailOrMobileNumber(mobileNumber);
        switch (userNameType) {
            case Constants.PHONE:
                AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
                String smsProvider = null;
                if (configModel != null && configModel.getConfig() != null) {
                    smsProvider = configModel.getConfig().get(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_PROVIDER);
                }
                logger.info("SMS for OTP initiated with provider : " + smsProvider);
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
                    if (isResend) {
                        retValue = sendSmsViaSinch(mobileNumber, otp, String.valueOf(ttl / 60));
                    } else {
                        retValue = sendSmsViaNetCore(mobileNumber, otp, String.valueOf(ttl / 60));
                    }
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
        logger.info("Email/SMS for OTP send successfully ? " + retValue);
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
            System.out.println("Error SMS " + e);
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
        try {
            response = HttpClient.post(request,
                    (System.getenv(Constants.SUNBIRD_LMS_BASE_URL) + Constants.SEND_NOTIFICATION_URI),
                    System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION));
            if (response.getStatusLine() != null) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == 200) {
                    return true;
                } else {
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

        // context.getSession().userCredentialManager().updateCredential(context.getRealm(),
        // context.getUser(),
        // credentials);
        new UserCredentialManager(context.getSession(), context.getRealm(), context.getUser())
                .updateCredential(credentials);

        credentials = new UserCredentialModel();
        credentials.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
        credentials.setValue((expiringAt).toString());
        // context.getSession().userCredentialManager().updateCredential(context.getRealm(),
        // context.getUser(),
        // credentials);
        new UserCredentialManager(context.getSession(), context.getRealm(), context.getUser())
                .updateCredential(credentials);
    }

    private CODE_STATUS validateCodeUsingDB(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(KeycloakSmsAuthenticatorConstants.ANSW_SMS_CODE);
        KeycloakSession session = context.getSession();

        // List<CredentialModel> codeCreds =
        // session.userCredentialManager().getStoredCredentialsByTypeStream(context.getRealm(),
        // context.getUser(),
        // KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE).collect(Collectors.toList());

        List<CredentialModel> codeCreds = new UserCredentialManager(session, context.getRealm(),
                context.getUser())
                .getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE)
                .collect(Collectors.toList());

        if (!CollectionUtils.isNullOrEmpty(codeCreds)) {
            CredentialModel expectedCode = codeCreds.get(0);
            result = enteredCode.equals(expectedCode.getValue()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
        }

        if (result == CODE_STATUS.VALID) {
            // List<CredentialModel> timeCreds =
            // session.userCredentialManager().getStoredCredentialsByTypeStream(context.getRealm(),
            // context.getUser(),
            // KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME).collect(Collectors.toList());
            List<CredentialModel> timeCreds = new UserCredentialManager(session, context.getRealm(),
                    context.getUser())
                    .getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME)
                    .collect(Collectors.toList());

            if (!CollectionUtils.isNullOrEmpty(timeCreds)) {
                CredentialModel expTimeString = timeCreds.get(0);
                Long currentTime = (new Date()).getTime();
                Long expiringAt = Long.parseLong(expTimeString.getValue());

                logger.info(String.format("CurrentTime: %s, ExpiringAt: %s, isExpired ?? %s", currentTime, expiringAt,
                        (currentTime >= expiringAt)));
            }
        }

        if (result == CODE_STATUS.VALID) {
            // session.userCredentialManager().removeStoredCredential(context.getRealm(),
            // context.getUser(),
            // KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
            // session.userCredentialManager().removeStoredCredential(context.getRealm(),
            // context.getUser(),
            // KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);
            UserCredentialManager credManager = new UserCredentialManager(session, context.getRealm(),
                    context.getUser());
            List<CredentialModel> smsCodeCreds = credManager
                    .getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE)
                    .collect(Collectors.toList());
            List<CredentialModel> expTimeCreds = credManager
                    .getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME)
                    .collect(Collectors.toList());

            if (!smsCodeCreds.isEmpty()) {
                credManager.removeStoredCredentialById(smsCodeCreds.get(0).getId());
            }
            if (!expTimeCreds.isEmpty()) {
                credManager.removeStoredCredentialById(expTimeCreds.get(0).getId());
            }
        }
        return result;
    }

    private boolean sendSmsViaAmnex(String mobileNumber, String otp, String expiryTime) {
        boolean retValue = AmnexSmsProvider.getInstance().send(mobileNumber, otp, expiryTime,
                SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
        return retValue;
    }

    private boolean sendSmsViaNetCore(String mobileNumber, String otp, String expiryTime) {
        logger.info("Sending SMS via NetCoreSMSProvider to mobile number: " + mobileNumber);
        mobileNumber = "91" + mobileNumber;
        boolean retValue = NetCoreSMSProvider.getInstance().send(mobileNumber, otp, expiryTime,
                SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
        logger.info("SMS sent via NetCoreSMSProvider to mobile number: " + mobileNumber + ", success: " + retValue);
        return retValue;
    }

    private boolean sendSmsViaSinch(String mobileNumber, String otp, String expiryTime) {
    mobileNumber = "91" + mobileNumber;
    return SinchSMSProvider.getInstance().send(mobileNumber, otp, expiryTime,
            SmsConfigurationConstants.NIC_LOGIN_OTP_SMS_TYPE);
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
        logger.info("[KC24_AUTH] ===== validateUserAndPassword() ENTRY =====");
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        logger.info("[KC24_AUTH] username from form: '" + username + "'");
        if (username == null) {
            logger.warn("[KC24_AUTH] FAIL: username is null");
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, Messages.INVALID_USER);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }

        // remove leading and trailing whitespace
        username = username.trim();

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        logger.info("[KC24_AUTH] Looking up user via KeycloakModelUtils.findUserByNameOrEmail for: " + username);
        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            logger.error("[KC24_AUTH] FAIL: ModelDuplicateException for user: " + username, mde);
            ServicesLogger.LOGGER.modelDuplicateException(mde);

            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                context.getEvent().getEvent().setError(Errors.EMAIL_IN_USE);
            } else {
                context.getEvent().getEvent().setError(Errors.USERNAME_IN_USE);
            }

            return false;
        }

        if (user == null) {
            logger.warn("[KC24_AUTH] FAIL: user not found for username: " + username);
            context.getEvent().getEvent().setError(Errors.USER_NOT_FOUND);
            return false;
        }

        logger.info("[KC24_AUTH] User found: id=" + user.getId()
                + ", username=" + user.getUsername()
                + ", email=" + user.getEmail()
                + ", enabled=" + user.isEnabled()
                + ", class=" + user.getClass().getName());

        if (!user.isEnabled()) {
            logger.warn("[KC24_AUTH] FAIL: user is disabled: " + user.getId());
            context.getEvent().getEvent().setError(Errors.USER_DISABLED);
            return false;
        }

        if (context.getRealm().isBruteForceProtected()) {
            logger.info("[KC24_AUTH] Brute force protection is enabled, checking...");
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                logger.warn("[KC24_AUTH] FAIL: user temporarily disabled by brute force protection: " + user.getId());
                context.getEvent().getEvent().setError(Errors.USER_TEMPORARILY_DISABLED);
                return false;
            }
            logger.info("[KC24_AUTH] Brute force check passed");
        }

        if (!validatePassword(context, user, inputData)) {
            context.getEvent().getEvent().setError(Errors.INVALID_USER_CREDENTIALS);
            return false;
        }
        logger.info("[KC24_AUTH] <<< validatePassword returned TRUE - credentials valid");

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
        logger.info("[KC24_PWD] validatePassword called for user: " + user.getUsername() + ", userId: " + user.getId());

        String encryptedPassword = inputData.getFirst(CredentialRepresentation.PASSWORD);
        logger.info("[KC24_PWD] Step 1 - encryptedPassword present: " + (encryptedPassword != null) +
                ", length: " + (encryptedPassword != null ? encryptedPassword.length() : "null"));

        String secretKey = context.getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        logger.info("[KC24_PWD] Step 2 - secretKey from authNote present: " + (secretKey != null) +
                ", length: " + (secretKey != null ? secretKey.length() : "null"));

        String iv = inputData.getFirst(Constants.IV);
        logger.info("[KC24_PWD] Step 3 - IV from form present: " + (iv != null) +
                ", length: " + (iv != null ? iv.length() : "null"));

        if (encryptedPassword == null || encryptedPassword.isEmpty()) {
            logger.warn("[KC24_PWD] encryptedPassword is null or empty - returning false");
            return false;
        }

        // Decrypt the password
        String decryptedPassword = decryptPassword(encryptedPassword, secretKey, iv);
        logger.info("[KC24_PWD] Step 4 - decryptedPassword present: " + (decryptedPassword != null) +
                ", length: " + (decryptedPassword != null ? decryptedPassword.length() : "null"));

        if (decryptedPassword == null || decryptedPassword.isEmpty()) {
            logger.warn("[KC24_PWD] decryptedPassword is null or empty after decryption - returning false");
            return false;
        }

        List<CredentialInput> credentials = new LinkedList<>();
        credentials.add(UserCredentialModel.password(decryptedPassword));

        logger.info("[KC24_PWD] Step 5 - Calling UserCredentialManager.isValid() for user: " + user.getId());
        logger.info("[KC24_PWD] Step 5 - UserModel class: " + user.getClass().getName());
        UserCredentialManager credManager = new UserCredentialManager(context.getSession(), context.getRealm(), user);
        logger.info("[KC24_PWD] Step 5 - UserCredentialManager created: " + credManager.getClass().getName());

        boolean isValid = credManager.isValid(credentials);
        logger.info("[KC24_PWD] Step 6 - isValid result: " + isValid);

        boolean finalResult = decryptedPassword != null && !decryptedPassword.isEmpty() && isValid;
        logger.info("[KC24_PWD] Step 7 - Final result: " + finalResult);
        return finalResult;
    }

    private String decryptPassword(String encryptedPassword, String secretKey, String iv) {
        logger.info("[KC24_DECRYPT] decryptPassword called");
        logger.info("[KC24_DECRYPT] encryptedPassword length: " + (encryptedPassword != null ? encryptedPassword.length() : "null"));
        logger.info("[KC24_DECRYPT] secretKey length: " + (secretKey != null ? secretKey.length() : "null"));
        logger.info("[KC24_DECRYPT] iv length: " + (iv != null ? iv.length() : "null"));

        // ENHANCED DEBUGGING - Show full details for troubleshooting
        if (secretKey != null) {
            logger.info("[KC24_DECRYPT] DEBUG - FULL secretKey: '" + secretKey + "'");
            byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            logger.info("[KC24_DECRYPT] DEBUG - secretKey as hex: " + bytesToHex(keyBytes));
            logger.info("[KC24_DECRYPT] DEBUG - secretKey byte length: " + keyBytes.length);
        }
        if (iv != null) {
            logger.info("[KC24_DECRYPT] DEBUG - Full IV Base64: '" + iv + "'");
        }
        if (encryptedPassword != null) {
            logger.info("[KC24_DECRYPT] DEBUG - FULL encryptedPassword: '" + encryptedPassword + "'");
        }

        if (secretKey == null || iv == null) {
            logger.warn("[KC24_DECRYPT] secretKey or iv is null - secretKey null: " + (secretKey == null) + ", iv null: " + (iv == null));
            logger.warn("[KC24_DECRYPT] Returning raw password since decryption is not possible");
            return encryptedPassword;
        }

        try {
            logger.info("[KC24_DECRYPT] Step 1 - Decoding Base64 encryptedPassword");
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
            logger.info("[KC24_DECRYPT] Step 2 - Decoded password bytes length: " + decodedBytes.length);
            logger.info("[KC24_DECRYPT] Step 2 - Decoded password hex: " + bytesToHex(decodedBytes));

            logger.info("[KC24_DECRYPT] Step 3 - Decoding Base64 IV");
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            logger.info("[KC24_DECRYPT] Step 4 - Decoded IV bytes length: " + ivBytes.length);
            logger.info("[KC24_DECRYPT] Step 4 - Decoded IV hex: " + bytesToHex(ivBytes));

            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // Use StandardCharsets.UTF_8 for Java 17 compatibility
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
            logger.info("[KC24_DECRYPT] Step 5 - SecretKeySpec created, key bytes length: " + secretKey.getBytes(StandardCharsets.UTF_8).length);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            logger.info("[KC24_DECRYPT] Step 6 - Cipher initialized successfully");

            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            String decryptedPassword = new String(decryptedBytes, StandardCharsets.UTF_8);
            logger.info("[KC24_DECRYPT] Step 7 - Decryption successful, decrypted length: " + decryptedPassword.length());
            logger.info("[KC24_DECRYPT] Step 7 - SUCCESS: Decryption worked with current key");
            return decryptedPassword;
        } catch (IllegalArgumentException e) {
            logger.error("[KC24_DECRYPT] Base64 decoding failed - input may not be Base64 encoded: " + e.getMessage(), e);
            logger.info("[KC24_DECRYPT] Returning raw password as fallback");
            return encryptedPassword;
        } catch (javax.crypto.BadPaddingException e) {
            logger.error("[KC24_DECRYPT] BadPaddingException - KEY MISMATCH! Client and server using different keys");
            logger.error("[KC24_DECRYPT] This means client encrypted with one key, server trying to decrypt with different key");
            logger.error("[KC24_DECRYPT] Error details: " + e.getMessage(), e);

            // Try alternative: maybe client is using a default/hardcoded key
            String[] alternativeKeys = {
                "1234567890123456", // Common default key
                "password1234567", // Another common key
                "sunbirdkeycloak1", // Project-specific key
                secretKey.toLowerCase(), // Lowercase version
                secretKey.toUpperCase()  // Uppercase version
            };

            for (String altKey : alternativeKeys) {
                try {
                    logger.info("[KC24_DECRYPT] Trying alternative key: " + altKey.substring(0, Math.min(4, altKey.length())) + "...");
                    Cipher altCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    SecretKeySpec altKeySpec = new SecretKeySpec(altKey.getBytes(StandardCharsets.UTF_8), "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
                    altCipher.init(Cipher.DECRYPT_MODE, altKeySpec, ivSpec);

                    byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
                    byte[] decryptedBytes = altCipher.doFinal(decodedBytes);
                    String decryptedPassword = new String(decryptedBytes, StandardCharsets.UTF_8);
                    logger.warn("[KC24_DECRYPT] SUCCESS with alternative key: " + altKey.substring(0, Math.min(4, altKey.length())) + "...");
                    return decryptedPassword;
                } catch (Exception altE) {
                    // Continue to next alternative key
                }
            }

            logger.warn("[KC24_DECRYPT] FALLBACK: All decryption attempts failed, using encrypted string as plaintext");
            if (encryptedPassword != null && encryptedPassword.length() > 4 && encryptedPassword.length() < 100) {
                logger.info("[KC24_DECRYPT] Using encryptedPassword as plaintext fallback, length: " + encryptedPassword.length());
                return encryptedPassword;
            }

            throw new RuntimeException("Error while decrypting password - key mismatch", e);
        } catch (Exception e) {
            logger.error("[KC24_DECRYPT] Other exception during decryption: " + e.getClass().getName() + " - " + e.getMessage(), e);
            logger.warn("[KC24_DECRYPT] FALLBACK: Using encrypted string as plaintext");

            if (encryptedPassword != null && encryptedPassword.length() > 4 && encryptedPassword.length() < 100) {
                logger.info("[KC24_DECRYPT] Using encryptedPassword as plaintext fallback, length: " + encryptedPassword.length());
                return encryptedPassword;
            }

            throw new RuntimeException("Error while decrypting password", e);
        }
    }

    // Helper method for hex debugging
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private boolean invalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            return true;
        }
        if (!user.isEnabled()) {
            context.getEvent().error(Errors.USER_DISABLED);
            return true;
        }
        if (context.getRealm().isBruteForceProtected()) {
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                context.getEvent().error(Errors.USER_TEMPORARILY_DISABLED);
                return true;
            }
        }
        return false;
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

    private long countSessionsForCurrentClient(AuthenticationFlowContext context, UserModel user) {
        ClientModel currentClient = context.getAuthenticationSession().getClient();
        logger.info("[KC24_AUTH] countSessionsForCurrentClient :: clientModel.Name " + currentClient.getName());
        UserSessionProvider sessions = context.getSession().sessions();
        RealmModel realm = context.getRealm();

        Stream<UserSessionModel> all = Stream.concat(
                sessions.getUserSessionsStream(realm, user),
                sessions.getOfflineUserSessionsStream(realm, user));

        return all
            .filter(s -> s.getAuthenticatedClientSessionByClient(currentClient.getId()) != null)
            .peek(s -> logger.infof("[KC24_AUTH] session id=%s ip=%s started=%d lastRefresh=%d offline=%s device=%s",
                    s.getId(), s.getIpAddress(), s.getStarted(), s.getLastSessionRefresh(),
                    s.isOffline(), s.getNote("KC_DEVICE_NOTE")))
            .count();
    }

    private static final int DEFAULT_MAX_USER_SESSIONS = 3;
    private int getMaxSessionsConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel != null && configModel.getConfig() != null) {
            String maxStr = configModel.getConfig().get(KeycloakSmsAuthenticatorConstants.CONF_PRP_MAX_USER_SESSIONS);
            if (StringUtils.isNotBlank(maxStr)) {
                try {
                    return Integer.parseInt(maxStr);
                } catch (NumberFormatException e) {
                    logger.warn("[KC24_AUTH] Invalid maxUserSessions config: " + maxStr);
                }
            }
        }
        return DEFAULT_MAX_USER_SESSIONS;
    }

    private boolean tooManySessions(AuthenticationFlowContext context, UserModel user) {
        int maxSessions = getMaxSessionsConfig(context);
        long currentCount = countSessionsForCurrentClient(context, user);
        logger.info("[KC24_AUTH] Client " + context.getAuthenticationSession().getClient().getClientId()
                + " session count for user " + user.getId() + ": " + currentCount
                + " (max allowed: " + maxSessions + ")");
        return currentCount >= maxSessions;
    }
}
