package org.sunbird.keycloak.saml;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.sunbird.keycloak.storage.spi.UserSearchService;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.keycloak.utils.HttpClientUtil;

/**
 * First Broker Login authenticator.
 *
 * <p>Runs once, during the "First Broker Login" flow, right after Keycloak has created the brokered
 * user from the incoming SAML assertion. It provisions the corresponding user in the Sunbird
 * learner service via the V5 create API so the user has a real iGOT/Sunbird account and can land on
 * the portal home page after SSO.
 *
 * <p>Because this authenticator is bound to the First Broker Login flow it only executes on the
 * user's first federated login; a search-before-create guard makes it idempotent even if the flow
 * is retried.
 *
 * <p>Both email and phone are mandatory in the assertion and must be unique across the learner
 * service. Email is checked first: if it already exists the user was provisioned earlier and the
 * create is skipped. Only then is the phone checked, so a hit there necessarily belongs to a
 * different account and the login is blocked - the learner service enforces phone uniqueness, so
 * the create would fail regardless and letting the login through would leave the user without an
 * account.
 */
public class CreateLearnerUserAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(CreateLearnerUserAuthenticator.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("[SAML-SBI-TEST] CreateLearnerUserAuthenticator.authenticate() invoked - entering SAML first-broker-login post-processing.");
        UserModel user = context.getUser();
        if (user == null) {
            user = context.getAuthenticationSession().getAuthenticatedUser();
        }

        if (user == null) {
            logger.warn(
                    "CreateLearnerUserAuthenticator: no authenticated user in context; skipping learner user creation.");
            logger.info("[SAML-SBI-TEST] No authenticated user found on context or auth session; treating as success and skipping provisioning.");
            context.success();
            return;
        }

        logger.info("[SAML-SBI-TEST] Brokered user resolved from SAML assertion. username=" + user.getUsername()
                + ", id=" + user.getId());

        String email = user.getEmail();
        logger.info("[SAML-SBI-TEST] user.getEmail() from assertion = " + email);
        if (StringUtils.isBlank(email)) {
            email = user.getFirstAttribute(Constants.SAML_EMAIL);
            logger.info("[SAML-SBI-TEST] email blank on user model, falling back to samlEmail attribute = " + email);
        }

        if (StringUtils.isBlank(email)) {
            logger.error(
                    "CreateLearnerUserAuthenticator: brokered user has no email attribute; cannot create learner user. username="
                            + user.getUsername());
            logger.info("[SAML-SBI-TEST] Aborting: no email resolvable from SAML assertion for username=" + user.getUsername());
            handleFailure(context, Constants.ERROR_MISSING_EMAIL);
            return;
        }

        String phone = extractPhone(user);
        logger.info("[SAML-SBI-TEST] Extracted/normalized phone from SAML assertion = " + phone);
        if (StringUtils.isBlank(phone)) {
            logger.error(
                    "CreateLearnerUserAuthenticator: brokered user has no phone attribute; cannot create learner user. username="
                            + user.getUsername());
            logger.info("[SAML-SBI-TEST] Aborting: no phone resolvable from SAML assertion for username=" + user.getUsername());
            handleFailure(context, Constants.ERROR_MISSING_PHONE);
            return;
        }

        if (!isValidPhone(phone)) {
            logger.error(
                    "CreateLearnerUserAuthenticator: phone from SAML assertion is not a valid 10-digit number; cannot create learner user. username="
                            + user.getUsername());
            logger.info("[SAML-SBI-TEST] Aborting: phone failed 10-digit validation, phone=" + phone);
            handleFailure(context, Constants.ERROR_INVALID_PHONE);
            return;
        }

        try {
            boolean emailExists = learnerUserExists(Constants.EMAIL, email.toLowerCase());
            logger.info("[SAML-SBI-TEST] learnerUserExists(email=" + email + ") = " + emailExists);
            if (emailExists) {
                logger.info(
                        "CreateLearnerUserAuthenticator: learner user already exists for email=" + email
                                + "; skipping create.");
                logger.info("[SAML-SBI-TEST] Existing learner user found for email; calling context.success() without create.");
                context.success();
                return;
            }

            // Email is new, so any phone match here belongs to a different account.
            boolean phoneExists = learnerUserExists(Constants.PHONE, phone);
            logger.info("[SAML-SBI-TEST] learnerUserExists(phone=" + phone + ") = " + phoneExists);
            if (phoneExists) {
                logger.error(
                        "CreateLearnerUserAuthenticator: phone is already registered to another learner user; aborting create for email="
                                + email);
                // Always blocking: the learner service rejects duplicate phones, so allowing the
                // login would strand the user without an account.
                logger.info("[SAML-SBI-TEST] Aborting: phone already registered to a different account; calling handleDuplicatePhone().");
                handleDuplicatePhone(context);
                return;
            }

            logger.info("[SAML-SBI-TEST] No existing learner user for email or phone; calling createLearnerUser().");
            boolean created = createLearnerUser(user, email, phone);
            logger.info("[SAML-SBI-TEST] createLearnerUser() returned = " + created);
            if (created) {
                logger.info("CreateLearnerUserAuthenticator: learner user created for email=" + email);
                logger.info("[SAML-SBI-TEST] Learner user created successfully; calling context.success().");
                context.success();
            } else {
                logger.error(
                        "CreateLearnerUserAuthenticator: learner user creation failed for email=" + email);
                logger.info("[SAML-SBI-TEST] createLearnerUser() returned false; calling handleFailure().");
                handleFailure(context, "Failed to create learner-service user.");
            }
        } catch (Exception ex) {
            logger.error(
                    "CreateLearnerUserAuthenticator: exception while provisioning learner user for email="
                            + email,
                    ex);
            logger.info("[SAML-SBI-TEST] Exception during provisioning, class=" + ex.getClass().getName()
                    + ", message=" + ex.getMessage());
            handleFailure(context, "Internal error while creating learner-service user.");
        }
    }

    /**
     * Read the phone number mapped from the SAML assertion, stripping formatting characters and any
     * country-code prefix so the value can be validated as a plain 10-digit national number.
     */
    private String extractPhone(UserModel user) {
        String phoneAttr = System.getenv(Constants.SAML_PHONE_ATTRIBUTE);
        if (StringUtils.isBlank(phoneAttr)) {
            phoneAttr = Constants.DEFAULT_PHONE_ATTRIBUTE;
        }
        return normalizePhone(user.getFirstAttribute(phoneAttr));
    }

    /** Drop spaces, dashes and brackets; then drop a leading +<cc> or 0 trunk prefix. */
    static String normalizePhone(String phone) {
        if (StringUtils.isBlank(phone)) {
            return StringUtils.EMPTY;
        }
        String digits = phone.trim().replaceAll("[\\s\\-()]", "");
        if (digits.startsWith("+")) {
            digits = digits.substring(1);
        }
        digits = digits.replaceFirst("^0+", "");
        // A national number is 10 digits. Strip a leading country code only when what
        // remains is a plausible one (1-3 digits), so genuinely malformed values stay
        // malformed and fail validation instead of being silently truncated.
        if (digits.length() > 10 && digits.length() <= 13 && digits.matches("\\d+")) {
            digits = digits.substring(digits.length() - 10);
        }
        return digits;
    }

    /** The learner service stores plain 10-digit mobile numbers. */
    static boolean isValidPhone(String phone) {
        return StringUtils.isNotBlank(phone) && phone.matches(Constants.PHONE_REGEX);
    }

    /**
     * Returns true if a learner user already holds this email or phone.
     *
     * <p>Delegates to the shared {@link UserSearchService#getUserByKey} lookup, which hits
     * {@code /private/user/v1/lookup} - the authoritative {@code user_lookup} uniqueness table that
     * the create API enforces against, so the two can never disagree. The value is sent in plain
     * text; the learner service encrypts it server-side before the lookup.
     *
     * @param field {@code email} or {@code phone}
     */
    private boolean learnerUserExists(String field, String value) {
        boolean exists = !UserSearchService.getUserByKey(field, value).isEmpty();
        logger.info("[SAML-SBI-TEST] learnerUserExists() lookup field=" + field + ", value=" + value + ", exists=" + exists);
        return exists;
    }

    /** Call the V5 create API to provision the learner-service user. */
    private boolean createLearnerUser(UserModel user, String email, String phone) {
        // The create API takes only firstName, lastName, channel, phone and email; everything else
        // (verification flags, roles, profileDetails) is set by the learner service itself.
        Map<String, Object> request = new LinkedHashMap<>();

        // firstName is mandatory on the create API; lastName is optional in the assertion.
        request.put(Constants.FIRST_NAME_KEY, buildFirstName(user));
        String lastName = StringUtils.trimToEmpty(user.getLastName());
        if (StringUtils.isNotBlank(lastName)) {
            request.put(Constants.LAST_NAME_KEY, lastName);
        }

        // All first-broker-login users are provisioned into the iGOT custodian org, so the channel
        // is the custodian channel rather than anything carried in the assertion.
        String channel = config(Constants.CUSTODIAN_CHANNEL, Constants.DEFAULT_CUSTODIAN_CHANNEL);
        if (StringUtils.isNotBlank(channel)) {
            request.put(Constants.CHANNEL, channel);
        } else {
            logger.warn(
                    "CreateLearnerUserAuthenticator: "
                            + Constants.CUSTODIAN_CHANNEL
                            + " is not set, so no channel can be sent; the learner service will fall"
                            + " back to its own custodian org. email=" + email);
        }
        request.put(Constants.EMAIL, email);
        request.put(Constants.EMAIL_VERIFIED, true);
        request.put(Constants.PHONE, phone);
        request.put(Constants.PHONE_VERIFIED, true);

        Map<String, Object> body = new HashMap<>();
        body.put(Constants.REQUEST, request);
        logger.info("CreateLearnerUserAuthenticator: sending create request for user: " + body.toString());
        logger.info("[SAML-SBI-TEST] createLearnerUser() POSTing to " + System.getenv(Constants.SUNBIRD_LMS_BASE_URL)
                + Constants.CREATE_USER_URI + ", body=" + body);
        String url = System.getenv(Constants.SUNBIRD_USER_SERVICE_BASE_URL) + Constants.CREATE_USER_URI;
        logger.info("[SAML-SBI-TEST] createLearnerUser() POSTing to " + url);
        String response = HttpClientUtil.post(
                url,
                writeJson(body), buildHeaders());
        logger.info("[SAML-SBI-TEST] createLearnerUser() raw response = " + response);
        if (StringUtils.isBlank(response)) {
            logger.info("[SAML-SBI-TEST] createLearnerUser() response blank; returning false.");
            return false;
        }

        try {
            Map<String, Object> json =
                    MAPPER.readValue(response, new TypeReference<Map<String, Object>>() {});
            String status = stringValue(asMap(json.get(Constants.PARAMS)).get(Constants.STATUS));
            String responseCode = stringValue(json.get(Constants.RESPONSE_CODE));
            boolean success = Constants.SUCCESS.equalsIgnoreCase(status) || Constants.OK.equalsIgnoreCase(responseCode);
            logger.info("[SAML-SBI-TEST] createLearnerUser() parsed status=" + status + ", responseCode=" + responseCode
                    + ", success=" + success);
            return success;
        } catch (Exception ex) {
            logger.warn("CreateLearnerUserAuthenticator: unable to parse create response: " + response, ex);
            logger.info("[SAML-SBI-TEST] createLearnerUser() failed to parse response, returning false.");
            return false;
        }
    }

    private String buildFirstName(UserModel user) {
        String first = StringUtils.trimToEmpty(user.getFirstName());
        if (StringUtils.isBlank(first)) {
            first = StringUtils.trimToEmpty(user.getUsername());
        }
        return first;
    }

    /** Read an env-var-backed config value, falling back to the supplied default. */
    private String config(String envVar, String defaultValue) {
        String value = StringUtils.trimToEmpty(System.getenv(envVar));
        return StringUtils.isNotBlank(value) ? value : StringUtils.trimToEmpty(defaultValue);
    }

    /** Nested object accessor that yields an empty map rather than null for a missing branch. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : Collections.emptyMap();
    }

    private static String stringValue(Object value) {
        return value == null ? StringUtils.EMPTY : String.valueOf(value);
    }

    private static String writeJson(Object body) {
        try {
            return MAPPER.writeValueAsString(body);
        } catch (Exception ex) {
            logger.error("CreateLearnerUserAuthenticator: failed to serialize request body.", ex);
            return "{}";
        }
    }

    /**
     * Headers for the create call.
     *
     * <p>{@code sunbird_authorization} holds a bare token; the {@code Bearer} prefix is added here,
     * matching {@link HttpClient} and {@link org.sunbird.keycloak.storage.spi.UserSearchService}.
     */
    private Map<String, String> buildHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON);
        String auth = System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION);
        if (StringUtils.isNotBlank(auth)) {
            headers.put(Constants.AUTHORIZATION, Constants.BEARER + " " + auth);
        } else {
            logger.warn(
                    "CreateLearnerUserAuthenticator: "
                            + Constants.SUNBIRD_LMS_AUTHORIZATION
                            + " is not set; the create call will be sent unauthenticated.");
        }
        return headers;
    }

    /**
     * A duplicate phone always blocks the login, regardless of {@code
     * sunbird_saml_fail_on_create_error}: the learner service will never accept the create, so
     * proceeding would land the user on a portal with no account behind it.
     */
    private void handleDuplicatePhone(AuthenticationFlowContext context) {
        logger.info("[SAML-SBI-TEST] handleDuplicatePhone() invoked - blocking login with INVALID_USER error page.");
        Response errorPage =
                context.form()
                        .setError(Constants.ERROR_PHONE_ALREADY_REGISTERED)
                        .createErrorPage(Response.Status.BAD_REQUEST);
        context.failure(AuthenticationFlowError.INVALID_USER, errorPage);
    }

    private void handleFailure(AuthenticationFlowContext context, String message) {
        boolean failOnError =
                Boolean.parseBoolean(System.getenv(Constants.SAML_FAIL_ON_CREATE_ERROR));
        logger.info("[SAML-SBI-TEST] handleFailure() invoked, message=" + message + ", failOnError=" + failOnError);
        if (failOnError) {
            Response errorPage =
                    context.form().setError(message).createErrorPage(Response.Status.BAD_REQUEST);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
        } else {
            logger.warn(
                    "CreateLearnerUserAuthenticator: continuing login despite provisioning issue: " + message);
            logger.info("[SAML-SBI-TEST] failOnError is false; calling context.success() despite issue.");
            context.success();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No user interaction; nothing to do.
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions.
    }

    @Override
    public void close() {
        // No resources to release.
    }
}
