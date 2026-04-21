package org.sunbird.keycloak.storage.spi;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.sunbird.keycloak.utils.Constants;

public class UserServiceProvider
        implements UserStorageProvider, UserLookupProvider, UserQueryProvider, CredentialInputValidator {
    private static final Logger logger = Logger.getLogger(UserStorageProvider.class);

    public static final String PASSWORD_CACHE_KEY = UserAdapter.class.getName() + ".password";
    private final KeycloakSession session;
    private final ComponentModel model;
    private final UserService userService;

    public UserServiceProvider(KeycloakSession session, ComponentModel model,
            UserService userService) {
        this.session = session;
        this.model = model;
        this.userService = userService;
    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        logger.info("UserServiceProvider:getUserById: id = " + id);
        String externalId = StorageId.externalId(id);
        logger.info("UserServiceProvider:getUserById: externalId found = " + externalId);
        User user = userService.getById(externalId);
        if (user == null) {
            return null;
        }
        logger.info("UserServiceProvider:keycloak_24: user 11111111 :" + user);
        return new UserAdapter(session, realm, model, user);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        logger.info("UserServiceProvider: getUserByUsername called");
        List<User> users = userService.getByUsername(username);
        logger.info("UserServiceProvider: getUserByUsername called and user is :" + users);
        if (users != null && users.size() == 1) {
            logger.info("UserServiceProvider:keycloak_24: user 22222222 :" + users.get(0));
            return new UserAdapter(session, realm, model, users.get(0));
        } else if (users != null && users.size() > 1) {
            throw new ModelDuplicateException(
                    "Multiple users are associated with this login credentials.", "login credentials");
        } else {
            return null;
        }
    }

    // Fix: Add missing method required by UserLookupProvider interface
    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        logger.info("UserServiceProvider trying to rebuild and see if changes is coming: getUserByEmail called");
        return getUserByUsername(realm, email);
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        return 0;
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        logger.info("UserServiceProvider: searchForUserByUserAttributeStream called");
        if (Constants.PHONE.equalsIgnoreCase(attrName)) {
            return userService.getByKey(attrName, attrValue).stream()
                    .map(user -> new UserAdapter(session, realm, model, user));
        }
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search) {
        logger.info("UserServiceProvider: searchForUserStream called with search: " + search);

        if (search == null || search.trim().isEmpty()) {
            return Stream.empty();
        }

        // Enhanced search logic
        String trimmedSearch = search.trim();
        List<User> users = userService.getByUsername(trimmedSearch);

        // If no users found by username, try additional searches
        if (users.isEmpty()) {
            // Try searching by email if it looks like an email
            if (trimmedSearch.contains("@")) {
                users = userService.getByKey("email", trimmedSearch);
            }
            // Try searching by phone if it's numeric
            else if (trimmedSearch.matches("\\d+")) {
                users = userService.getByKey("phone", trimmedSearch);
            }
        }

        return users.stream()
                .map(user -> new UserAdapter(session, realm, model, user));
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult,
            Integer maxResults) {
        logger.info("UserServiceProvider: searchForUserStream called with firstResult = " + firstResult);
        return searchForUserStream(realm, search);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params) {
        String search = params.get(UserModel.SEARCH);
        if (search == null) {
            search = params.get(UserModel.USERNAME);
        }
        if (search == null) {
            search = params.get(UserModel.EMAIL);
        }
        if (search != null && !search.trim().isEmpty()) {
            return searchForUserStream(realm, search);
        }
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        return searchForUserStream(realm, params);
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult,
            Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group) {
        return Stream.empty();
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        logger.info("[KC24_CRED] supportsCredentialType called: " + credentialType);
        boolean result = PasswordCredentialModel.TYPE.equals(credentialType);
        logger.info("[KC24_CRED] supportsCredentialType result: " + result);
        return result;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        logger.info("[KC24_CRED] isConfiguredFor called: user=" + user.getId() + ", type=" + credentialType);
        if (!supportsCredentialType(credentialType))
            return false;
        try {
            PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) session
                    .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
            boolean result = passwordProvider.isConfiguredFor(realm, user, credentialType);
            logger.info("[KC24_CRED] isConfiguredFor result: " + result);
            return result;
        } catch (Exception e) {
            logger.error("[KC24_CRED] isConfiguredFor error", e);
            return false;
        }
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        logger.info("[KC24_CRED] ===== isValid() ENTRY =====");
        logger.info("[KC24_CRED] user: " + user.getUsername() + ", userId: " + user.getId()
                + ", userClass: " + user.getClass().getName());
        logger.info("[KC24_CRED] credentialType: " + input.getType());
        
        // DEBUG: Check if we came through PasswordAndOtpAuthenticator
        String authSessionNote = null;
        try {
            authSessionNote = session.getContext().getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
        } catch (Exception e) {
            logger.warn("[KC24_CRED] Could not access authSession: " + e.getMessage());
        }
        logger.info("[KC24_CRED] DEBUG: secretKey authNote present: " + (authSessionNote != null));
        
        // DEBUG: Check stack trace to see what called us
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        logger.info("[KC24_CRED] DEBUG: Call stack (first 10 frames):");
        for (int i = 0; i < Math.min(10, stack.length); i++) {
            if (stack[i].getClassName().contains("sunbird") || stack[i].getClassName().contains("keycloak")) {
                logger.info("[KC24_CRED] DEBUG: [" + i + "] " + stack[i].getClassName() + "." + stack[i].getMethodName() + "()");
            }
        }

        if (!supportsCredentialType(input.getType())) {
            logger.warn("[KC24_CRED] FAIL: unsupported credential type: " + input.getType());
            return false;
        }

        try {
            // Step 1: Resolve (decrypt if needed) password
            logger.info("[KC24_CRED] Step 1 - Resolving password from CredentialInput");
            String passwordToValidate = resolvePassword(input);

            if (passwordToValidate == null || passwordToValidate.isEmpty()) {
                logger.warn("[KC24_CRED] FAIL: resolved password is null or empty");
                return false;
            }
            logger.info("[KC24_CRED] Step 1 DONE - password resolved, length: " + passwordToValidate.length());

            // Step 2: Validate the resolved plain-text password against Keycloak's
            // local credential store for this federated user via PasswordCredentialProvider (SPI).
            logger.info("[KC24_CRED] Step 2 - Validating credentials via Keycloak PasswordCredentialProvider for user: " + user.getUsername());
            PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) session
                    .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
            boolean valid = passwordProvider.isValid(realm, user, UserCredentialModel.password(passwordToValidate));
            logger.info("[KC24_CRED] Step 2 DONE - Keycloak PasswordCredentialProvider validation result: " + valid);
            logger.info("[KC24_CRED] ===== isValid() EXIT - result: " + valid + " =====");
            return valid;

        } catch (Exception e) {
            logger.error("[KC24_CRED] isValid() EXCEPTION: " + e.getClass().getName() + " - " + e.getMessage(), e);
            return false;
        }
    }

    private String resolvePassword(CredentialInput input) {
        logger.info("[KC24_CRED] resolvePassword() called");
        String rawPassword = input.getChallengeResponse();
        logger.info("[KC24_CRED] rawPassword from CredentialInput: present=" + (rawPassword != null)
                + ", length=" + (rawPassword != null ? rawPassword.length() : "null"));
        try {
            var httpRequest = session.getContext().getHttpRequest();
            if (httpRequest == null) {
                logger.info("[KC24_CRED] httpRequest is null - using raw password (already decrypted by Authenticator)");
                return rawPassword;
            }

            var formData = httpRequest.getDecodedFormParameters();
            String iv = formData != null ? formData.getFirst("iv") : null;
            logger.info("[KC24_CRED] IV from form: present=" + (iv != null)
                    + ", length=" + (iv != null ? iv.length() : "null"));

            if (iv == null || iv.isEmpty()) {
                logger.info("[KC24_CRED] No IV in form - password was already decrypted by PasswordAndOtpAuthenticator, using as-is");
                return rawPassword;
            }

            String secretKey = session.getContext()
                    .getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);
            logger.info("[KC24_CRED] secretKey from authNote: present=" + (secretKey != null)
                    + ", length=" + (secretKey != null ? secretKey.length() : "null"));

            if (secretKey == null || secretKey.isEmpty()) {
                logger.warn("[KC24_CRED] IV present but secretKey missing from authNote - using raw password");
                logger.warn("[KC24_CRED] DEBUG: This suggests authentication is NOT going through PasswordAndOtpAuthenticator");
                logger.warn("[KC24_CRED] DEBUG: Expected to find secretKey under authNote key: '" + Constants.SECRET_KEY + "'");
                return rawPassword;
            }

            // Guard: if the raw password cannot be valid Base64 it has already been
            // decrypted upstream (e.g. by PasswordAndOtpAuthenticator).  Attempting
            // Base64 decode on plain text would throw IllegalArgumentException and fall
            // back anyway, but doing the check here avoids the noisy exception.
            try {
                java.util.Base64.getDecoder().decode(rawPassword);
            } catch (IllegalArgumentException notBase64) {
                logger.info("[KC24_CRED] rawPassword is not Base64-encoded - already decrypted by Authenticator, using as-is");
                return rawPassword;
            }

            logger.info("[KC24_CRED] Attempting AES decryption in resolvePassword");
            String decrypted = decryptPassword(rawPassword, secretKey, iv);
            logger.info("[KC24_CRED] AES decryption successful, decrypted length: " + decrypted.length());
            return decrypted;

        } catch (Exception e) {
            logger.warn("[KC24_CRED] resolvePassword() exception: " + e.getClass().getName() + " - " + e.getMessage(), e);
            logger.warn("[KC24_CRED] Using raw password as fallback");
            return rawPassword;
        }
    }
 
    private String decryptPassword(String encryptedPassword, String secretKey, String iv) {
        try {
            byte[] decodedBytes = java.util.Base64.getDecoder().decode(encryptedPassword);
            byte[] ivBytes = java.util.Base64.getDecoder().decode(iv);
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(ivBytes);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(secretKey.getBytes("UTF-8"),
                    "AES");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec);

            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting password", e);
        }
    }

}