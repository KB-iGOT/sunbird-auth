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

    // Updated method to handle null values properly
    public List<String> getAttribute(String name) {
        Map<String, List<String>> attrs = getFederatedStorage().getAttributes(realm, keycloakId);
        List<String> list = attrs != null ? attrs.get(name) : null;
        return list != null ? list : new ArrayList<>();
    }

    // Add the Stream-based method that may be required in Keycloak 24.x
    public Stream<String> getAttributeStream(String name) {
        List<String> attrs = getAttribute(name);
        return attrs != null ? attrs.stream() : Stream.empty();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        logger.info("UserAdapter:getAttributes method started");
        Map<String, List<String>> attributes = new HashMap<>();

        // Add phone attribute
        if (user.getPhone() != null) {
            List<String> phoneValues = new ArrayList<>();
            phoneValues.add(user.getPhone());
            attributes.put("phone", phoneValues);
        }

        // Add country code attribute
        if (user.getCountryCode() != null) {
            List<String> countrycodeValues = new ArrayList<>();
            countrycodeValues.add(user.getCountryCode());
            attributes.put("countryCode", countrycodeValues);
        }

        // Add org attribute
        if (user.getOrg() != null) {
            List<String> rootOrgValue = new ArrayList<>();
            rootOrgValue.add(user.getOrg());
            attributes.put("org", rootOrgValue);
        }

        // Add roles attribute
        if (user.getRoles() != null) {
            attributes.put("roles", user.getRoles());
        }

        logger.info("UserAdapter:getAttributes method ended");
        return attributes;
    }

    @Override
    public String getId() {
        logger.info("[KC24_DEBUG] getId() called, returning: " + keycloakId);
        return keycloakId;
    }
}