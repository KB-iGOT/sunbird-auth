package org.sunbird.keycloak.utils;

public class Constants {

	private Constants() {
	}

	public static final String MULTIPLE_USER_ASSOCIATED_WITH_PHONE = "Multiple users are associated with this phone.";
	public static final String MULTIPLE_USER_ASSOCIATED_WITH_EMAIL = "Multiple users are associated with this email.";
	public static final String MULTIPLE_USER_ASSOCIATED_WITH_USERNAME = "Multiple users are associated with this username.";
	public static final String REDIRECT_URI = "redirectUri";
	public static final String CLIENT_ID = "clientId";
	public static final String REQUIRED_ACTION = "requiredAction";
	public static final String USERNAME = "userName";
	public static final String EXPIRATION_IN_SECS = "expirationInSecs";
	public static final String IS_AUTH_REQUIRED = "isAuthRequired";
	public static final String KEY = "key";
	public static final String LINK = "link";
	public static final String BEARER = "Bearer";
	public static final String ADMIN = "admin";
	public static final int DEFAULT_LINK_EXPIRATION_IN_SECS = 7200;
	public static final String UPDATE_PASSWORD = "UPDATE_PASSWORD";
	public static final String VERIFY_EMAIL = "VERIFY_EMAIL";

	public static final String ERROR_NOT_ENABLED = " not enabled";
	public static final String ERROR_NOT_AUTHORIZED = "Not Authorized.";
	public static final String ERROR_USER_IS_DISABLED = "User is disabled.";
	public static final String ERROR_CREATE_LINK = "Failed to create link";
	public static final String ERROR_REALM_ADMIN_ROLE_ACCESS = "Does not have realm admin role.";
	public static final String ERROR_INVALID_PARAMETER_VALUE = "Invalid value {0} for parameter {1}.";
	public static final String ERROR_MANDATORY_PARAM_MISSING = "Mandatory parameter {0} is missing.";
	public static final String OTP = "otp";
	public static final String EMAIL = "email";
	public static final String TTL = "ttl";
	public static final String SUNBIRD_LMS_AUTHORIZATION = "sunbird_authorization";

	public static final String MAIL_SUBJECT = "Reset password";
	public static final String SUBJECT = "subject";
	public static final String EMAIL_TEMPLATE_TYPE = "emailTemplateType";
	public static final String REALM_NAME = "realmName";
	public static final String SEND_NOTIFICATION_URI = "/user/v1/notification/email";
	public static final String SUNBIRD_LMS_BASE_URL = "sunbird_lms_base_url";
	public static final String BODY = "body";
	public static final String RECIPIENT_EMAILS = "recipientEmails";
	public static final String FORGOT_PASSWORD_EMAIL_TEMPLATE = "forgotPasswordWithOTP";
	public static final String REQUEST = "request";
	public static final String FIRST_NAME = "firstname";
	public static final String ID = "id";
	public static final String PHONE = "phone";
	public static final String SUNBIRD_CASSANDRA_IP = "sunbird_cassandra_host";
	public static final String SUNBIRD_CASSANDRA_PORT = "sunbird_cassandra_port";
	public static final String LAST_NAME = "lastname";
	public static final String SEND_OTP_VIA_SMS = "sunbird_send_otp_vis_sms";

	public static final String HTTP_AUTH_HOST = "http://localhost:8090";
	public static final String ATTR_PHONE_NUMBER_ADMIN = "mobile_number";
	public static final String ATTR_PHONE_NUMBER = "phoneNumber";
	public static final String ATTR_OTP_CODE = "user.attributes.otp";
	public static final String ATTR_OTP_USER = "smsCode";
	public static final String ATTR_USER_NAME = "username";
	public static final String ATTR_PASSWORD = "password";
	public static final String FLAG_LOGIN_PAGE = "login_page";
	public static final String FLAG_OTP_PAGE = "sms_otp_page";
	public static final String FLAG_OTP_RESEND_PAGE = "sms_otp_resend_page";
	public static final String FLAG_PAGE = "page_type";
	public static final String FLAG_LOGIN_WITH_PASS = "login_with_pass";

	public static final String SESSION_OTP_CODE = "smsCode";
	public static final String SESSION_OTP_EXPIRE_TIME = "smsCodeExpireTime";

	public static final String PAGE_INPUT_OTP = "sms-input-otp.ftl";
	public static final String LOGIN_PAGE = "login.ftl";

	public static final String USER_CRED_MDL_PASSWORD = "password";

	public static final String NUMERIC = "0123456789";
	public static final String REDIRECT_URI_KEY = "redirect_uri";
	public static final String FAST2SMS_API_KEY = "fast2sms_api_key";
	public static final String FAST2SMS_API_URL = "fast2sms_api_url";
	public static final String SMS_OTP_NUMBERS = "sms_allowed_numbers";

	public static final String INVALID_OTP_ENTERED = "Invalid OTP. Please enter a valid OTP.";
	public static final String OTP_EXPIRED = "OTP is expired. Please try again.";
	public static final String FLOW_API = "FLOW";
	public static final String MOBILES = "mobiles";
	public static final String FLOW_ID = "flow_id";
	public static final String SENDER = "sender";
	public static final String RECIPIENTS = "recipients";
	public static final String ATTEMPTED_EMAIL_OR_MOBILE_NUMBER = "attempted_email_or_mobile";

	public static final String MSG91_PROVIDER = "MSG91";
	public static final String Free2SMS_PROVIDER = "Free2SMS";
	public static final String NIC_PROVIDER = "NIC";
	public static final String ATTR_USER_EMAIL_OR_PHONE = "emailOrPhone";
	public static final String LOGIN_OTP_EMAIL_TEMPLATE = "sunbird_login_otp_template";
	public static final String LOGIN_OTP_MAIL_SUBJECT = "sunbird_login_otp_email_subject";
	
	public static final String NAME = "name";
	public static final String UTF_8 = "UTF-8";
	public static final String AMNEX_SMS_PROVIDER = "AMNEX";
	public static final String NETCORE_SMS_PROVIDER = "NetCore";
	public static final String TO = "to";
	public static final String TEXT = "text";
	public static final String TEMPLATE_ID = "templateid";
	public static final String SHORT = "short";
	public static final String ASYNC = "async";
	public static final String SECRET_KEY = "secretKey";
	public static final String IV = "iv";
}
