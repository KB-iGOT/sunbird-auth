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
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType))
            return false;
        try {
            PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) session
                    .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
            return passwordProvider.isConfiguredFor(realm, user, credentialType);
        } catch (Exception e) {
            logger.error("isConfiguredFor error", e);
            return false;
        }
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        try {
            // Step 1: Resolve (decrypt if needed) password
            String passwordToValidate = resolvePassword(input);

            if (passwordToValidate == null || passwordToValidate.isEmpty()) {
                return false;
            }

            // Step 2: Validate the resolved plain-text password against Keycloak's
            // local credential store for this federated user via PasswordCredentialProvider (SPI).
            PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) session
                    .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
            return passwordProvider.isValid(realm, user, UserCredentialModel.password(passwordToValidate));

        } catch (Exception e) {
            logger.error("isValid() exception: " + e.getClass().getName() + " - " + e.getMessage(), e);
            return false;
        }
    }

    private String resolvePassword(CredentialInput input) {
        String rawPassword = input.getChallengeResponse();
        try {
            var httpRequest = session.getContext().getHttpRequest();
            if (httpRequest == null) {
                return rawPassword;
            }

            var formData = httpRequest.getDecodedFormParameters();
            String iv = formData != null ? formData.getFirst("iv") : null;

            if (iv == null || iv.isEmpty()) {
                return rawPassword;
            }

            String secretKey = session.getContext()
                    .getAuthenticationSession().getAuthNote(Constants.SECRET_KEY);

            if (secretKey == null || secretKey.isEmpty()) {
                return rawPassword;
            }

            // Guard: if the raw password cannot be valid Base64 it has already been
            // decrypted upstream (e.g. by PasswordAndOtpAuthenticator).  Attempting
            // Base64 decode on plain text would throw IllegalArgumentException and fall
            // back anyway, but doing the check here avoids the noisy exception.
            try {
                java.util.Base64.getDecoder().decode(rawPassword);
            } catch (IllegalArgumentException notBase64) {
                return rawPassword;
            }

            return decryptPassword(rawPassword, secretKey, iv);

        } catch (Exception e) {
            logger.warn("resolvePassword() exception: " + e.getClass().getName() + " - " + e.getMessage(), e);
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