package org.sunbird.keycloak.storage.spi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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
    List<String> list = getFederatedStorage().getAttributes(realm, keycloakId).get(name);
    if (list != null) {
        logger.info("UserAdapter:getAttribute method called with name: " + name);
        return list;
    }
    logger.info("UserAdapter:getAttribute method attribute name: " + name + " value is null, wrapping in list");
    switch (name) {
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
        default:
            return new ArrayList<>();
    }
  }
  
  @Override
  public Map<String, List<String>> getAttributes() {
	logger.info("UserAdapter:getAttributes method started " );  
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put(Constants.PHONE, wrap(user.getPhone()));
    attributes.put(Constants.COUNTRY_CODE, wrap(user.getCountryCode()));
    attributes.put(Constants.ORG, wrap(user.getOrg()));
    attributes.put(Constants.ORGNAME, wrap(user.getOrgName()));
    attributes.put(Constants.DESIGNATION, wrap(user.getDesignation()));
    attributes.put(Constants.GROUP, wrap(user.getGroup()));
    attributes.put(Constants.ROLES, user.getRoles() != null ? user.getRoles() : new ArrayList<>());
    logger.info("UserAdapter:getAttributes method ended " );
    return attributes;
  }

  @Override
  public String getId() {
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
