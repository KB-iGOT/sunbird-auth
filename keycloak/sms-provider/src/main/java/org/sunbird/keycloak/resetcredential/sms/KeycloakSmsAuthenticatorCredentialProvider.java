package org.sunbird.keycloak.resetcredential.sms;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import org.keycloak.credential.UserCredentialManager;

/**
 * Created by nickpack on 09/08/2017.
 * Updated for Keycloak 24.0.4
 */
public class KeycloakSmsAuthenticatorCredentialProvider implements CredentialProvider, CredentialInputValidator, CredentialInputUpdater, OnUserCache {
    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticatorCredentialProvider.class);

    private static final String CACHE_KEY = KeycloakSmsAuthenticatorCredentialProvider.class.getName() + "." + KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE;

    private final KeycloakSession session;

    public KeycloakSmsAuthenticatorCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE;
    }

    private CredentialModel getSecret(RealmModel realm, UserModel user) {
        CredentialModel secret = null;
        if (user instanceof CachedUserModel) {
            CachedUserModel cached = (CachedUserModel) user;
            secret = (CredentialModel) cached.getCachedWith().get(CACHE_KEY);

        } else {
            // Fix: Use new UserCredentialManager constructor
            List<CredentialModel> creds = new UserCredentialManager(session, realm, user)
                    .getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE)
                    .collect(Collectors.toList());
            if (!creds.isEmpty()) secret = creds.get(0);
        }
        return secret;
    }

    // NEW METHODS REQUIRED FOR KEYCLOAK 24.x
    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE)
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("SMS Authentication Code")
                .helpText("SMS based authentication")
                .iconCssClass("kcAuthenticatorSMSClass")
                .createAction("sms-auth-setup")
                .updateAction("sms-auth-setup")
                .removeable(true)
                .build(session);
    }

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel model) {
        return model;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel credentialModel) {
        logger.debug("KeycloakSmsAuthenticatorCredentialProvider@createCredential called for User = " + user.getUsername());
        // Fix: Use new UserCredentialManager constructor
        return new UserCredentialManager(session, realm, user).createStoredCredential(credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        logger.debug("KeycloakSmsAuthenticatorCredentialProvider@deleteCredential called for User = " + user.getUsername());
        // Fix: Use new UserCredentialManager constructor
        return new UserCredentialManager(session, realm, user).removeStoredCredentialById(credentialId);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        logger.debug("KeycloakSmsAuthenticatorCredentialProvider@action called ... for User = " + user.getUsername());

        if (!KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;

        UserCredentialModel credInput = (UserCredentialModel) input;
        UserCredentialManager credManager = new UserCredentialManager(session, realm, user);

        List<CredentialModel> creds = credManager
                .getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE)
                .collect(Collectors.toList());

        if (creds.isEmpty()) {
            CredentialModel secret = new CredentialModel();
            secret.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
            secret.setValue(credInput.getValue());
            secret.setCreatedDate(Time.currentTimeMillis());
            credManager.createStoredCredential(secret);
            logger.debug("KeycloakSmsAuthenticatorCredentialProvider@action New Credentials added for User = " + user.getUsername());

        } else {
            creds.get(0).setValue(credInput.getValue());
            credManager.updateStoredCredential(creds.get(0));
            logger.debug("KeycloakSmsAuthenticatorCredentialProvider@action Credentials updated for User = " + user.getUsername());
        }
        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        if (!KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(credentialType)) return;
        // Fix: Use new UserCredentialManager constructor
        new UserCredentialManager(session, realm, user).disableCredentialType(credentialType);
    }

    // Updated method signature for Keycloak 24.x
    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        UserCredentialManager credManager = new UserCredentialManager(session, realm, user);
        if (!credManager.getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE)
                .collect(Collectors.toList()).isEmpty()) {
            Set<String> set = new HashSet<>();
            set.add(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
            return set.stream();
        } else {
            return Stream.empty();
        }
    }

    // Legacy method for backward compatibility (deprecated in newer versions)
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return getDisableableCredentialTypesStream(realm, user).collect(Collectors.toSet());
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(credentialType) && getSecret(realm, user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;

        CredentialModel secret = getSecret(realm, user);
        if (secret == null) return false;

        return secret.getValue() != null && ((UserCredentialModel) input).getValue().equals(secret.getValue());
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        UserCredentialManager credManager = new UserCredentialManager(session, realm, user);
        List<CredentialModel> creds = credManager
                .getStoredCredentialsByTypeStream(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE)
                .collect(Collectors.toList());
        if (!creds.isEmpty()) {
            user.getCachedWith().put(CACHE_KEY, creds.get(0));
        }
    }
}