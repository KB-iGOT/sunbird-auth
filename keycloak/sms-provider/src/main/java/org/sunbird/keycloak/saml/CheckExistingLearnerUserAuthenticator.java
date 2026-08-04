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
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.sunbird.keycloak.storage.spi.UserSearchService;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.keycloak.utils.HttpClientUtil;

/**
 * Runs first in the "first broker login" flow's user-creation-or-linking alternatives, ahead of
 * Keycloak's stock "Create User If Unique".
 *
 * <p>Keycloak's identity brokering always needs <em>some</em> {@link UserModel} to attach the SAML
 * assertion to before the flow can proceed. Left to its own devices, "Create User If Unique" creates
 * a native (JPA-backed) Keycloak user for every first-time federated login. This authenticator
 * intercepts before that ever happens, working directly off the raw {@link BrokeredIdentityContext}
 * (available before any {@code UserModel} exists):
 *
 * <ul>
 *   <li>if a learner user already exists for the assertion's email, it resolves the corresponding
 *       {@code UserServiceProvider}-backed federated user (id format {@code
 *       f:<componentId>:<lmsUserId>}, see {@code UserAdapter#getId()}), points the session at it via
 *       {@link AuthenticationFlowContext#setUser}, and calls {@link
 *       AuthenticationFlowContext#success()} - no native Keycloak user is ever created;
 *   <li>if no learner user exists yet, it provisions one directly against the V5 create API (the
 *       same call {@code CreateLearnerUserAuthenticator} used to make from "Learner Provisioning"),
 *       then resolves and points the session at the newly created federated user the same way.
 * </ul>
 *
 * <p>Because both branches resolve to a federated (non-local-storage) user before Keycloak's own
 * "Create User If Unique" ever runs, no throwaway native user is created and nothing needs to be
 * relinked or deleted afterward - for first-time signups or returning logins alike. This replaces the
 * old create-then-relink-then-delete approach in {@code CreateLearnerUserAuthenticator}/"Learner
 * Provisioning", which is no longer needed and should be removed from the flow.
 */
public class CheckExistingLearnerUserAuthenticator extends AbstractIdpAuthenticator {

    private static final Logger logger = Logger.getLogger(CheckExistingLearnerUserAuthenticator.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    protected void authenticateImpl(
            AuthenticationFlowContext context,
            SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {

        String email = brokerContext.getEmail();
        if (StringUtils.isBlank(email)) {
            email = brokerContext.getUserAttribute(Constants.SAML_EMAIL);
        }
        logger.info("[SAML-SBI-TEST] CheckExistingLearnerUserAuthenticator: brokered email=" + email);

        if (StringUtils.isBlank(email)) {
            logger.error(
                    "CheckExistingLearnerUserAuthenticator: SAML assertion has no email; cannot resolve or"
                            + " create a learner user.");
            handleFailure(context, Constants.ERROR_MISSING_EMAIL);
            return;
        }

        String phone = extractPhone(brokerContext);
        logger.info("[SAML-SBI-TEST] CheckExistingLearnerUserAuthenticator: extracted phone=" + phone);

        try {
            boolean emailExists = learnerUserExists(Constants.EMAIL, email.toLowerCase());
            logger.info("[SAML-SBI-TEST] learnerUserExists(email=" + email + ") = " + emailExists);

            if (emailExists) {
                setUserToFederatedLearner(context, email);
                return;
            }

            // Email is new, so any phone match here belongs to a different account. Phone is only
            // required from this point on - an existing learner is found purely by email above.
            if (StringUtils.isBlank(phone)) {
                logger.error(
                        "CheckExistingLearnerUserAuthenticator: brokered identity has no phone attribute;"
                                + " cannot create learner user. email=" + email);
                handleFailure(context, Constants.ERROR_MISSING_PHONE);
                return;
            }

            if (!isValidPhone(phone)) {
                logger.error(
                        "CheckExistingLearnerUserAuthenticator: phone from SAML assertion is not a valid"
                                + " 10-digit number; cannot create learner user. email=" + email);
                handleFailure(context, Constants.ERROR_INVALID_PHONE);
                return;
            }

            boolean phoneExists = learnerUserExists(Constants.PHONE, phone);
            logger.info("[SAML-SBI-TEST] learnerUserExists(phone=" + phone + ") = " + phoneExists);
            if (phoneExists) {
                logger.error(
                        "CheckExistingLearnerUserAuthenticator: phone is already registered to another"
                                + " learner user; aborting create for email=" + email);
                handleDuplicatePhone(context);
                return;
            }

            boolean created = createLearnerUser(brokerContext, email, phone);
            logger.info("[SAML-SBI-TEST] createLearnerUser() returned = " + created);
            if (created) {
                setUserToFederatedLearner(context, email);
            } else {
                logger.error("CheckExistingLearnerUserAuthenticator: learner user creation failed for email="
                        + email);
                handleFailure(context, "Failed to create learner-service user.");
            }
        } catch (Exception ex) {
            logger.error(
                    "CheckExistingLearnerUserAuthenticator: exception while resolving/provisioning learner"
                            + " user for email=" + email,
                    ex);
            handleFailure(context, "Internal error while creating learner-service user.");
        }
    }

    /**
     * Never reached: {@link #authenticateImpl} always terminates the execution (success, attempted or
     * failure) without rendering a form, so no user action is ever submitted back to this
     * authenticator.
     */
    @Override
    protected void actionImpl(
            AuthenticationFlowContext context,
            SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
        // No user interaction; nothing to do.
    }

    /**
     * False by design: this authenticator runs <em>before</em> any {@link UserModel} exists - that is
     * the whole point, since it resolves or provisions the federated learner user itself instead of
     * letting "Create User If Unique" create a native one.
     */
    @Override
    public boolean requiresUser() {
        return false;
    }

    /** Nothing to configure per user: the authenticator applies to every brokered login. */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    /**
     * Resolve the learner-service-backed federated user for {@code email} and point the session at
     * it. Falls through to "Create User If Unique" (rather than blocking the login) if the lookup
     * table says the user exists but the federation SPI can't resolve it - e.g. a transient
     * learner-service error - so a real outage doesn't lock users out entirely.
     */
    private void setUserToFederatedLearner(AuthenticationFlowContext context, String email) {
        UserModel federatedUser = context.getSession().users().getUserByEmail(context.getRealm(), email);
        if (federatedUser == null) {
            logger.warn(
                    "CheckExistingLearnerUserAuthenticator: learner_lookup reports email=" + email
                            + " exists but UserServiceProvider could not resolve it; falling through to"
                            + " Create User If Unique.");
            context.attempted();
            return;
        }
        logger.info("[SAML-SBI-TEST] CheckExistingLearnerUserAuthenticator: setting session user to federated id="
                + federatedUser.getId() + " for email=" + email + "; no native Keycloak user will be created.");
        context.setUser(federatedUser);
        context.success();
    }

    /**
     * Read the phone number mapped from the SAML assertion (via the "phone" Attribute Importer
     * mapper on the IdP), stripping formatting characters and any country-code prefix so the value
     * can be validated as a plain 10-digit national number.
     */
    private String extractPhone(BrokeredIdentityContext brokerContext) {
        String phoneAttr = System.getenv(Constants.SAML_PHONE_ATTRIBUTE);
        if (StringUtils.isBlank(phoneAttr)) {
            phoneAttr = Constants.DEFAULT_PHONE_ATTRIBUTE;
        }
        return normalizePhone(brokerContext.getUserAttribute(phoneAttr));
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
     * <p>Delegates to the shared {@link UserSearchService#getUserByKey} lookup, which hits {@code
     * /private/user/v1/lookup} - the authoritative {@code user_lookup} uniqueness table that the
     * create API enforces against, so the two can never disagree.
     */
    private boolean learnerUserExists(String field, String value) {
        boolean exists = !UserSearchService.getUserByKey(field, value).isEmpty();
        logger.info("[SAML-SBI-TEST] learnerUserExists() lookup field=" + field + ", value=" + value + ", exists="
                + exists);
        return exists;
    }

    /** Call the V5 create API to provision the learner-service user, directly off the broker context. */
    private boolean createLearnerUser(BrokeredIdentityContext brokerContext, String email, String phone) {
        Map<String, Object> request = new LinkedHashMap<>();

        request.put(Constants.FIRST_NAME_KEY, buildFirstName(brokerContext));
        String lastName = StringUtils.trimToEmpty(brokerContext.getLastName());
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
                    "CheckExistingLearnerUserAuthenticator: " + Constants.CUSTODIAN_CHANNEL
                            + " is not set, so no channel can be sent; the learner service will fall"
                            + " back to its own custodian org. email=" + email);
        }
        request.put(Constants.EMAIL, email);
        request.put(Constants.EMAIL_VERIFIED, true);
        request.put(Constants.PHONE, phone);
        request.put(Constants.PHONE_VERIFIED, true);

        Map<String, Object> body = new HashMap<>();
        body.put(Constants.REQUEST, request);
        String url = System.getenv(Constants.SUNBIRD_USER_SERVICE_BASE_URL) + Constants.CREATE_USER_URI;
        logger.info("CheckExistingLearnerUserAuthenticator: sending create request to " + url + ", body=" + body);
        String response = HttpClientUtil.post(url, writeJson(body), buildHeaders());
        logger.info("[SAML-SBI-TEST] createLearnerUser() raw response = " + response);
        if (StringUtils.isBlank(response)) {
            return false;
        }

        try {
            Map<String, Object> json = MAPPER.readValue(response, new TypeReference<Map<String, Object>>() {});
            String status = stringValue(asMap(json.get(Constants.PARAMS)).get(Constants.STATUS));
            String responseCode = stringValue(json.get(Constants.RESPONSE_CODE));
            boolean success = Constants.SUCCESS.equalsIgnoreCase(status) || Constants.OK.equalsIgnoreCase(responseCode);
            logger.info("[SAML-SBI-TEST] createLearnerUser() parsed status=" + status + ", responseCode="
                    + responseCode + ", success=" + success);
            return success;
        } catch (Exception ex) {
            logger.warn("CheckExistingLearnerUserAuthenticator: unable to parse create response: " + response, ex);
            return false;
        }
    }

    private String buildFirstName(BrokeredIdentityContext brokerContext) {
        String first = StringUtils.trimToEmpty(brokerContext.getFirstName());
        if (StringUtils.isBlank(first)) {
            first = StringUtils.trimToEmpty(brokerContext.getUsername());
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
            logger.error("CheckExistingLearnerUserAuthenticator: failed to serialize request body.", ex);
            return "{}";
        }
    }

    /**
     * Headers for the create call. {@code sunbird_authorization} holds a bare token; the {@code
     * Bearer} prefix is added here.
     */
    private Map<String, String> buildHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON);
        String auth = System.getenv(Constants.SUNBIRD_LMS_AUTHORIZATION);
        if (StringUtils.isNotBlank(auth)) {
            headers.put(Constants.AUTHORIZATION, Constants.BEARER + " " + auth);
        } else {
            logger.warn(
                    "CheckExistingLearnerUserAuthenticator: " + Constants.SUNBIRD_LMS_AUTHORIZATION
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
                context.form().setError(Constants.ERROR_PHONE_ALREADY_REGISTERED).createErrorPage(Response.Status.BAD_REQUEST);
        context.failure(AuthenticationFlowError.INVALID_USER, errorPage);
    }

    /**
     * Always blocks the login. {@code sunbird_saml_fail_on_create_error=false} used to mean
     * "continue anyway" back when "Learner Provisioning" ran after Keycloak had already created a
     * native user - continuing there just meant leaving that native user without a linked learner
     * account, which was already broken. Now that this authenticator runs before any user exists,
     * "continuing" would mean falling through to "Create User If Unique" and creating a native
     * Keycloak user with no learner account behind it at all - strictly worse. So this always blocks
     * regardless of that env var; it's kept only so ops can still search it out of config if desired.
     */
    private void handleFailure(AuthenticationFlowContext context, String message) {
        logger.info("[SAML-SBI-TEST] handleFailure() invoked, message=" + message);
        Response errorPage = context.form().setError(message).createErrorPage(Response.Status.BAD_REQUEST);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
    }
}
