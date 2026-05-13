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
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

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

    @Override
    public List<String> getAttribute(String name) {
        logger.info("UserAdapter:getAttribute method called with name: " + name);
        Map<String, List<String>> attrs = getFederatedStorage().getAttributes(realm, keycloakId);
        List<String> list = attrs != null ? attrs.get(name) : null;
        if (list != null) {
            return list;
        }
        logger.info("UserAdapter:getAttribute method attribute name: " + name + " value is null, wrapping in list");
        switch (name) {
            case "phone":
                return wrap(user.getPhone());
            case "countryCode":
                return wrap(user.getCountryCode());
            case "org":
                return wrap(user.getOrg());
            case "roles":
                return user.getRoles() != null ? user.getRoles() : new ArrayList<>();
            case "firstName":
                return wrap(user.getFirstName());
            case "lastName":
                return wrap(user.getLastName());
            case "email":
                return wrap(user.getEmail());
            default:
                return new ArrayList<>();
        }
    }

    // Stream-based method required in Keycloak 24.x
    public Stream<String> getAttributeStream(String name) {
        List<String> attrs = getAttribute(name);
        return attrs != null ? attrs.stream() : Stream.empty();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        logger.info("UserAdapter:getAttributes method started");
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("phone", wrap(user.getPhone()));
        attributes.put("countryCode", wrap(user.getCountryCode()));
        attributes.put("org", wrap(user.getOrg()));
        attributes.put("roles", user.getRoles() != null ? user.getRoles() : new ArrayList<>());
        logger.info("UserAdapter:getAttributes method ended");
        return attributes;
    }

    @Override
    public String getId() {
        logger.info("[KC24_DEBUG] getId() called, returning: " + keycloakId);
        return keycloakId;
    }

    private List<String> wrap(String value) {
        List<String> list = new ArrayList<>();
        if (value != null) {
            list.add(value);
        }
        return list;
    }
}
