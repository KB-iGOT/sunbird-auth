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

/**
 * Created by nickpack on 09/08/2017.
 */
public class KeycloakSmsAuthenticatorCredentialProvider implements CredentialProvider, CredentialInputValidator, CredentialInputUpdater, OnUserCache {
    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticatorCredentialProvider.class);

    private static final String CACHE_KEY = KeycloakSmsAuthenticatorCredentialProvider.class.getName() + "." + KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE;

    private final KeycloakSession session;

    public KeycloakSmsAuthenticatorCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    private CredentialModel getSecret(RealmModel realm, UserModel user) {
        logger.info("KeycloakSmsAuthenticatorCredentialProvider:getSecret called ... for User = " + user.getUsername());
        CredentialModel secret = null;
        if (user instanceof CachedUserModel) {
            logger.info("KeycloakSmsAuthenticatorCredentialProvider:getSecret user is cached ... for User = " + user.getUsername());
            CachedUserModel cached = (CachedUserModel) user;
            secret = (CredentialModel) cached.getCachedWith().get(CACHE_KEY);
            logger.info("KeycloakSmsAuthenticatorCredentialProvider:getSecret secret from cache ... for User = " + user.getUsername());

        } else {
            logger.info("KeycloakSmsAuthenticatorCredentialProvider:getSecret user is not cached ... for User = " + user.getUsername());
            List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
            if (!creds.isEmpty()) secret = creds.get(0);
        }
        logger.info("KeycloakSmsAuthenticatorCredentialProvider:getSecret returning secret ... for User = " + user.getUsername());
        return secret;
    }


    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        logger.debug("KeycloakSmsAuthenticatorCredentialProvider@action called ... for User = " + user.getUsername());
        logger.info("KeycloakSmsAuthenticatorCredentialProvider@action called ... for User = " + user.getUsername());

        if (!KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;
        UserCredentialModel credInput = (UserCredentialModel) input;
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
        if (creds.isEmpty()) {
            logger.info("KeycloakSmsAuthenticatorCredentialProvider@action No existing Credentials found for User = " + user.getUsername() + " ... creating new one");
            CredentialModel secret = new CredentialModel();
            secret.setType(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
            secret.setValue(credInput.getValue());
            secret.setCreatedDate(Time.currentTimeMillis());
            session.userCredentialManager().createCredential(realm, user, secret);
            logger.debug("KeycloakSmsAuthenticatorCredentialProvider@action New Credentials added for User = " + user.getUsername());

        } else {
            logger.info("KeycloakSmsAuthenticatorCredentialProvider@action Existing Credentials found for User = " + user.getUsername() + " ... updating existing one");
            creds.get(0).setValue(credInput.getValue());
            session.userCredentialManager().updateCredential(realm, user, creds.get(0));
            logger.debug("KeycloakSmsAuthenticatorCredentialProvider@action Credentials updated for User = " + user.getUsername());
        }
        session.userCache().evict(realm, user);
        logger.info("KeycloakSmsAuthenticatorCredentialProvider@action completed successfully for User = " + user.getUsername());
        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: disableCredentialType called ... for User = " + user.getUsername());
        if (!KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(credentialType)) return;
        session.userCredentialManager().disableCredentialType(realm, user, credentialType);
        session.userCache().evict(realm, user);
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: disableCredentialType completed successfully for User = " + user.getUsername());

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: getDisableableCredentialTypes called ... for User = " + user.getUsername());
        if (!session.userCredentialManager().getStoredCredentialsByType(realm, user, KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE).isEmpty()) {
            Set<String> set = new HashSet<>();
            set.add(KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
            logger.info("KeycloakSmsAuthenticatorCredentialProvider: getDisableableCredentialTypes completed successfully for User = " + user.getUsername());
            return set;
        } else {
            logger.info("KeycloakSmsAuthenticatorCredentialProvider: getDisableableCredentialTypes found no credentials for User = " + user.getUsername());
            return Collections.<String>emptySet();
        }

    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: supportsCredentialType called for credentialType = " + credentialType);
        return KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: isConfiguredFor called for User = " + user.getUsername() + " and credentialType = " + credentialType);
        return KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(credentialType) && getSecret(realm, user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: isValid called for User = " + user.getUsername());
        if (!KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;

        String secret = getSecret(realm, user).getValue();
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: isValid completed for User = " + user.getUsername());

        return secret != null && ((UserCredentialModel) input).getValue().equals(secret);
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        logger.info("KeycloakSmsAuthenticatorCredentialProvider: onCache called for User = " + user.getUsername());
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_CODE);
        if (!creds.isEmpty()) {
            user.getCachedWith().put(CACHE_KEY, creds.get(0));
        }
    }
}
