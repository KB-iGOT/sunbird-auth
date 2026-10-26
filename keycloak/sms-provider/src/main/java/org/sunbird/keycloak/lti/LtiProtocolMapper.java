package org.sunbird.keycloak.lti;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

/**
 * Injects the LTI 1.3 Core Message claims into the token, but only when
 * {@link LtiMarkerAuthenticator} has already marked this session as an LTI launch (via the
 * user-session note it sets from the incoming {@code lti_message_hint}). For every ordinary
 * iGOT login that note is absent, so {@link #setClaim} does nothing - the existing
 * {@code CustomProtocolMapper}'s claims (org, user_roles, etc.) are untouched either way.
 *
 * <p>deployment_id / resource_link are PoC placeholders (see {@link LtiConstants}) until the
 * provider/content registry that used to live in cios-content-service is rebuilt elsewhere.
 */
public class LtiProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final Logger logger = Logger.getLogger(LtiProtocolMapper.class);
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    public static final String PROVIDER_ID = "lti-claims-mapper";

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "LTI 1.3 Claims Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getHelpText() {
        return "Injects LTI 1.3 Core Message claims (message_type, deployment_id, target_link_uri, "
                + "resource_link, roles) only for sessions LtiMarkerAuthenticator has flagged as an "
                + "LTI launch; a no-op for every other login.";
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        String ltiMessageHint = userSession.getNote(LtiConstants.LTI_MESSAGE_HINT_PARAM);
        if (ltiMessageHint == null || ltiMessageHint.isEmpty()) {
            return;
        }

        logger.debug("LtiProtocolMapper: injecting LTI claims for lti_message_hint=" + ltiMessageHint);

        token.getOtherClaims().put(LtiConstants.CLAIM_MESSAGE_TYPE, LtiConstants.MESSAGE_TYPE_RESOURCE_LINK_REQUEST);
        token.getOtherClaims().put(LtiConstants.CLAIM_VERSION, LtiConstants.LTI_VERSION);
        token.getOtherClaims().put(LtiConstants.CLAIM_DEPLOYMENT_ID, LtiConstants.PLACEHOLDER_DEPLOYMENT_ID);

        String targetLinkUri = userSession.getNote("lti_target_link_uri");
        token.getOtherClaims().put(LtiConstants.CLAIM_TARGET_LINK_URI, targetLinkUri);

        Map<String, Object> resourceLink = new LinkedHashMap<>();
        resourceLink.put("id", LtiConstants.PLACEHOLDER_RESOURCE_LINK_ID);
        resourceLink.put("title", LtiConstants.PLACEHOLDER_RESOURCE_LINK_TITLE);
        token.getOtherClaims().put(LtiConstants.CLAIM_RESOURCE_LINK, resourceLink);

        token.getOtherClaims().put(LtiConstants.CLAIM_ROLES, Collections.singletonList(LtiConstants.LEARNER_ROLE));
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();
        if (accessToken) {
            config.put("access.token.claim", "true");
        }
        if (idToken) {
            config.put("id.token.claim", "true");
        }
        if (userInfo) {
            config.put("userinfo.token.claim", "true");
        }
        mapper.setConfig(config);
        return mapper;
    }

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, LtiProtocolMapper.class);
    }
}
