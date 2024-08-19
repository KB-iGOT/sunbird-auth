package org.sunbird.keycloak.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

public class CustomProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList();
    public static final String PROVIDER_ID = "customer-igot-mapper";

    public CustomProtocolMapper() {
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    public String getId() {
        return "customer-igot-mapper";
    }

    public String getDisplayType() {
        return "customer-igot-mapper";
    }

    public String getDisplayCategory() {
        return "customer-igot-mapper";
    }

    public String getHelpText() {
        return "customer-igot-mapper";
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        UserModel user = userSession.getUser();
        List<String> orgList = user.getAttributes().get("org");
        String org = "";
        if(orgList != null && orgList.size() >0 )
            org = orgList.get(0);
        token.getOtherClaims().put("org", org);
        token.getOtherClaims().put("user_roles", user.getAttributes().get("roles"));
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper("customer-igot-mapper");
        mapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap();
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
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, org.sunbird.keycloak.utils.CustomProtocolMapper.class);
    }
}
