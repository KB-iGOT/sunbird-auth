package org.sunbird.keycloak.saml;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
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
        UserModel user = context.getUser();
        if (user == null) {
            user = context.getAuthenticationSession().getAuthenticatedUser();
        }

        if (user == null) {
            logger.warn(
                    "CreateLearnerUserAuthenticator: no authenticated user in context; skipping learner user creation.");
            context.success();
            return;
        }

        String email = user.getEmail();
        if (StringUtils.isBlank(email)) {
            email = user.getFirstAttribute(Constants.SAML_EMAIL);
        }

        if (StringUtils.isBlank(email)) {
            logger.error(
                    "CreateLearnerUserAuthenticator: brokered user has no email attribute; cannot create learner user. username="
                            + user.getUsername());
            handleFailure(context, Constants.ERROR_MISSING_EMAIL);
            return;
        }

        String phone = extractPhone(user);
        if (StringUtils.isBlank(phone)) {
            logger.error(
                    "CreateLearnerUserAuthenticator: brokered user has no phone attribute; cannot create learner user. username="
                            + user.getUsername());
            handleFailure(context, Constants.ERROR_MISSING_PHONE);
            return;
        }

        if (!isValidPhone(phone)) {
            logger.error(
                    "CreateLearnerUserAuthenticator: phone from SAML assertion is not a valid 10-digit number; cannot create learner user. username="
                            + user.getUsername());
            handleFailure(context, Constants.ERROR_INVALID_PHONE);
            return;
        }

        try {
            if (learnerUserExists(Constants.EMAIL, email.toLowerCase())) {
                logger.info(
                        "CreateLearnerUserAuthenticator: learner user already exists for email=" + email
                                + "; skipping create.");
                context.success();
                return;
            }

            // Email is new, so any phone match here belongs to a different account.
            if (learnerUserExists(Constants.PHONE, phone)) {
                logger.error(
                        "CreateLearnerUserAuthenticator: phone is already registered to another learner user; aborting create for email="
                                + email);
                // Always blocking: the learner service rejects duplicate phones, so allowing the
                // login would strand the user without an account.
                handleDuplicatePhone(context);
                return;
            }

            boolean created = createLearnerUser(user, email, phone);
            if (created) {
                logger.info("CreateLearnerUserAuthenticator: learner user created for email=" + email);
                context.success();
            } else {
                logger.error(
                        "CreateLearnerUserAuthenticator: learner user creation failed for email=" + email);
                handleFailure(context, "Failed to create learner-service user.");
            }
        } catch (Exception ex) {
            logger.error(
                    "CreateLearnerUserAuthenticator: exception while provisioning learner user for email="
                            + email,
                    ex);
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
        return !UserSearchService.getUserByKey(field, value).isEmpty();
    }

    /** Call the V5 create API to provision the learner-service user. */
    private boolean createLearnerUser(UserModel user, String email, String phone) {
        String createUrl = System.getenv(Constants.SAML_CREATE_USER_URL);
        logger.info("CreateLearnerUserAuthenticator: using create URL: " + createUrl);
        if (StringUtils.isBlank(createUrl)) {
            logger.error(
                    "CreateLearnerUserAuthenticator: "
                            + Constants.SAML_CREATE_USER_URL
                            + " env var is not set; cannot create learner user.");
            return false;
        }

        Map<String, Object> request = new LinkedHashMap<>();
        request.put(Constants.EMAIL, email);
        request.put(Constants.EMAIL_VERIFIED, true);
        request.put(Constants.PHONE, phone);
        request.put(Constants.PHONE_VERIFIED, true);

        // firstName is mandatory on the create API; lastName is optional in the assertion.
        request.put(Constants.API_FIRST_NAME, buildFirstName(user));
        String lastName = StringUtils.trimToEmpty(user.getLastName());
        if (StringUtils.isNotBlank(lastName)) {
            request.put(Constants.API_LAST_NAME, lastName);
        }

        // The assertion carries no channel of its own, so orgId doubles as the channel the learner
        // service resolves the root org from. This holds only while the assertion's orgId matches
        // the organisation.channel column - switch to DEFAULT_ORG_NAME_ATTRIBUTE if it turns out
        // orgName is the channel instead. When absent the learner service falls back to the
        // custodian org, which is almost never intended for a bank user.
        String channel = attribute(user, Constants.SAML_ORG_ID_ATTRIBUTE, Constants.DEFAULT_ORG_ID_ATTRIBUTE);
        if (StringUtils.isNotBlank(channel)) {
            request.put(Constants.CHANNEL, channel);
        } else {
            logger.warn(
                    "CreateLearnerUserAuthenticator: no orgId attribute on the brokered user, so no"
                            + " channel can be sent; the learner service will fall back to the"
                            + " custodian org. email=" + email);
        }

        List<String> roles = new ArrayList<>();
        roles.add(Constants.PUBLIC);
        request.put(Constants.ROLES, roles);

        addProfileDetails(user, request);

        Map<String, Object> body = new HashMap<>();
        body.put(Constants.REQUEST, request);
        logger.info("CreateLearnerUserAuthenticator: sending create request for user: " + body.toString());
        String response = HttpClientUtil.post(createUrl, writeJson(body), buildHeaders());
        if (StringUtils.isBlank(response)) {
            return false;
        }

        try {
            JsonNode json = MAPPER.readTree(response);
            String status = json.path("params").path("status").asText("");
            String responseCode = json.path("responseCode").asText("");
            return Constants.SUCCESS.equalsIgnoreCase(status) || Constants.OK.equalsIgnoreCase(responseCode);
        } catch (Exception ex) {
            logger.warn("CreateLearnerUserAuthenticator: unable to parse create response: " + response, ex);
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

    /**
     * Attach designation, group and org details from the assertion.
     *
     * <p>Sent in both shapes the V5 create routes understand: the self/custom register routes lift
     * {@code designation} and {@code group} out of a top-level {@code personalDetails} map, while
     * the admin route copies {@code profileDetails.professionalDetails} through verbatim. Whichever
     * route is configured reads its own shape and ignores the other.
     */
    private void addProfileDetails(UserModel user, Map<String, Object> request) {
        String designation = attribute(user, Constants.SAML_DESIGNATION_ATTRIBUTE,
                Constants.DEFAULT_DESIGNATION_ATTRIBUTE);
        String group = attribute(user, Constants.SAML_GROUP_ATTRIBUTE, Constants.DEFAULT_GROUP_ATTRIBUTE);
        String orgId = attribute(user, Constants.SAML_ORG_ID_ATTRIBUTE, Constants.DEFAULT_ORG_ID_ATTRIBUTE);
        String orgName = attribute(user, Constants.SAML_ORG_NAME_ATTRIBUTE, Constants.DEFAULT_ORG_NAME_ATTRIBUTE);

        Map<String, Object> professionalDetail = new LinkedHashMap<>();
        putIfNotBlank(professionalDetail, Constants.DESIGNATION, designation);
        putIfNotBlank(professionalDetail, Constants.GROUP, group);
        putIfNotBlank(professionalDetail, Constants.NAME, orgName);
        putIfNotBlank(professionalDetail, Constants.ORGID, orgId);
        if (professionalDetail.isEmpty()) {
            return;
        }

        Map<String, Object> personalDetails = new LinkedHashMap<>();
        putIfNotBlank(personalDetails, Constants.DESIGNATION, designation);
        putIfNotBlank(personalDetails, Constants.GROUP, group);
        if (!personalDetails.isEmpty()) {
            request.put(Constants.PERSONAL_DETAILS, personalDetails);
        }

        Map<String, Object> profileDetails = new LinkedHashMap<>();
        profileDetails.put(Constants.PROFESIONAL_DETAILS, List.of(professionalDetail));
        request.put(Constants.PROFILE_DETAILS, profileDetails);
    }

    /** Read a Keycloak attribute whose name is overridable by the given env var. */
    private String attribute(UserModel user, String envVar, String defaultAttribute) {
        logger.info("CreateLearnerUserAuthenticator: reading attribute for env var: " + envVar);
        String attributeName = System.getenv(envVar);
        if (StringUtils.isBlank(attributeName)) {
            attributeName = defaultAttribute;
        }
        return StringUtils.trimToEmpty(user.getFirstAttribute(attributeName));
    }

    private static void putIfNotBlank(Map<String, Object> map, String key, String value) {
        if (StringUtils.isNotBlank(value)) {
            map.put(key, value);
        }
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
        Response errorPage =
                context.form()
                        .setError(Constants.ERROR_PHONE_ALREADY_REGISTERED)
                        .createErrorPage(Response.Status.BAD_REQUEST);
        context.failure(AuthenticationFlowError.INVALID_USER, errorPage);
    }

    private void handleFailure(AuthenticationFlowContext context, String message) {
        boolean failOnError =
                Boolean.parseBoolean(System.getenv(Constants.SAML_FAIL_ON_CREATE_ERROR));
        if (failOnError) {
            Response errorPage =
                    context.form().setError(message).createErrorPage(Response.Status.BAD_REQUEST);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
        } else {
            logger.warn(
                    "CreateLearnerUserAuthenticator: continuing login despite provisioning issue: " + message);
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
