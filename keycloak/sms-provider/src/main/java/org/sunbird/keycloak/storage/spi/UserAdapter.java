package org.sunbird.keycloak.storage.spi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.sunbird.keycloak.utils.Constants;

public class UserAdapter extends AbstractUserAdapterFederatedStorage {
    private static final Logger logger = Logger.getLogger(UserAdapter.class);
    private final User user;
    private final String keycloakId;

    public UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel,
            User user) {
        super(session, realm, storageProviderModel);
        this.user = user;
        this.keycloakId = StorageId.keycloakId(storageProviderModel, user.getId());

        logger.info("[KC24_DEBUG] UserAdapter created:");
        logger.info("[KC24_DEBUG]   - External User ID: " + user.getId());
        logger.info("[KC24_DEBUG]   - Federated Keycloak ID: " + this.keycloakId);
        logger.info("[KC24_DEBUG]   - Storage Provider ID: " + storageProviderModel.getId());
        logger.info("[KC24_DEBUG]   - Username: " + user.getUsername());
        logger.info("[KC24_DEBUG]   - Realm: " + realm.getName());
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public void setUsername(String username) {
        user.setUsername(username);
    }

    @Override
    public String getFirstName() {
        return user.getFirstName();
    }

    @Override
    public void setFirstName(String firstName) {
        user.setFirstName(firstName);
    }

    @Override
    public String getLastName() {
        return user.getLastName();
    }

    @Override
    public void setLastName(String lastName) {
        user.setLastName(lastName);
    }

    @Override
    public String getEmail() {
        return user.getEmail();
    }

    @Override
    public void setEmail(String email) {
        user.setEmail(email);
    }

    public String getPassword() {
        return user.getPassword();
    }

    public void setPassword(String password) {
        user.setPassword(password);
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        user.setEnabled(enabled);
    }

    public List<String> getAttribute(String name) {
        logger.info("UserAdapter:getAttribute method called with name: " + name);
        Map<String, List<String>> attrs = getFederatedStorage().getAttributes(realm, keycloakId);
        List<String> list = attrs != null ? attrs.get(name) : null;
        if (list != null) {
            return list;
        }
        logger.info("UserAdapter:getAttribute method attribute name: " + name + " value is null, wrapping in list");
        switch (name) {
            case Constants.ID:
                return wrap(user.getId());
            case Constants.SAML_EMAIL:
                return wrap(user.getId() + "@karmayogi.com");
            case Constants.PHONE:
                return wrap(user.getPhone());
            case Constants.COUNTRY_CODE:
                return wrap(user.getCountryCode());
            case Constants.ORG:
                return wrap(user.getOrg());
            case Constants.ORGNAME:
                return wrap(user.getOrgName());
            case Constants.DESIGNATION:
                return wrap(user.getDesignation());
            case Constants.GROUP:
                return wrap(user.getGroup());
            case Constants.ROLES:
                return user.getRoles() != null ? user.getRoles() : new ArrayList<>();
            case Constants.FIRST_NAME:
                return wrap(user.getFirstName());
            case Constants.LAST_NAME:
                return wrap(user.getLastName());
            case Constants.EMAIL:
                return wrap(user.getEmail());
            case Constants.USER_TYPE:
                return wrap("anonymous");
            case Constants.IS_VERIFIED:
                return wrap("true");
            case Constants.LOGIN_ID:
                return wrap("\"\"");
            default:
                return new ArrayList<>();
        }
    }

    // Stream-based method required in Keycloak 24.x
    @Override
    public Stream<String> getAttributeStream(String name) {
        List<String> attrs = getAttribute(name);
        return attrs != null ? attrs.stream() : Stream.empty();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        logger.info("UserAdapter:getAttributes method started " );
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put(Constants.ID, wrap(user.getId()));
        attributes.put(Constants.PHONE, wrap(user.getPhone()));
        attributes.put(Constants.COUNTRY_CODE, wrap(user.getCountryCode()));
        attributes.put(Constants.ORG, wrap(user.getOrg()));
        attributes.put(Constants.ORGNAME, wrap(user.getOrgName()));
        attributes.put(Constants.DESIGNATION, wrap(user.getDesignation()));
        attributes.put(Constants.GROUP, wrap(user.getGroup()));
        attributes.put(Constants.ROLES, user.getRoles() != null ? user.getRoles() : new ArrayList<>());
        attributes.put(Constants.SAML_EMAIL, wrap(user.getId() + "@karmayogi.com"));
        attributes.put(Constants.USER_TYPE, wrap("anonymous"));
        attributes.put(Constants.IS_VERIFIED, wrap("true"));
        attributes.put(Constants.LOGIN_ID, wrap(" "));
        logger.info("User Attributes: " + attributes);
        logger.info("UserAdapter:getAttributes method ended " );
        return attributes;
    }

    @Override
    public String getId() {
        logger.info("[KC24_DEBUG] getId() called, returning: " + keycloakId);
        return keycloakId;
    }

    /**
     * Override to include realm default roles (e.g. offline_access) for federated users.
     * AbstractUserAdapterFederatedStorage does NOT include realm default roles by itself,
     * unlike AbstractUserAdapter. This ensures KC24's offline token role check passes.
     */
    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        Stream<RoleModel> federatedRoles = super.getRoleMappingsStream();
        RoleModel defaultRole = realm.getDefaultRole();
        if (defaultRole != null) {
            return Stream.concat(federatedRoles, Stream.of(defaultRole));
        }
        return federatedRoles;
    }

    private List<String> wrap(String value) {
        List<String> list = new ArrayList<>();
        if (value != null) {
            list.add(value);
        }
        return list;
    }
}
