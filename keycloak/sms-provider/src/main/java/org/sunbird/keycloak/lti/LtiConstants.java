package org.sunbird.keycloak.lti;

/** Shared keys/URIs for the LTI 1.3 marker authenticator + protocol mapper pair. */
public final class LtiConstants {

    private LtiConstants() {
    }

    /** Non-standard OIDC param Moodle sends only on LTI launches; its presence is how we tell an LTI
     *  authorize request apart from a normal iGOT login, without touching the existing login flow. */
    public static final String LTI_MESSAGE_HINT_PARAM = "lti_message_hint";

    public static final String CLAIM_MESSAGE_TYPE = "https://purl.imsglobal.org/spec/lti/claim/message_type";
    public static final String CLAIM_VERSION = "https://purl.imsglobal.org/spec/lti/claim/version";
    public static final String CLAIM_DEPLOYMENT_ID = "https://purl.imsglobal.org/spec/lti/claim/deployment_id";
    public static final String CLAIM_TARGET_LINK_URI = "https://purl.imsglobal.org/spec/lti/claim/target_link_uri";
    public static final String CLAIM_RESOURCE_LINK = "https://purl.imsglobal.org/spec/lti/claim/resource_link";
    public static final String CLAIM_ROLES = "https://purl.imsglobal.org/spec/lti/claim/roles";

    public static final String MESSAGE_TYPE_RESOURCE_LINK_REQUEST = "LtiResourceLinkRequest";
    public static final String LTI_VERSION = "1.3.0";

    /** PoC placeholders: no provider/resource-link registry exists since the removal of
     *  cios-content-service's LTI package. Single hardcoded deployment, matching the one
     *  Deployment ID ("1") registered on Moodle's side today. Replace with a real per-Tool,
     *  per-content lookup once that registry is rebuilt. */
    public static final String PLACEHOLDER_DEPLOYMENT_ID = "1";
    public static final String PLACEHOLDER_RESOURCE_LINK_ID = "1";
    public static final String PLACEHOLDER_RESOURCE_LINK_TITLE = "iGOT LTI Resource";

    public static final String LEARNER_ROLE =
            "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";
}
