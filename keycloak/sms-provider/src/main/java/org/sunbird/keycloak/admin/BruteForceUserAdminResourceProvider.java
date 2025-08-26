package org.sunbird.keycloak.admin;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.sunbird.keycloak.storage.spi.User;
import org.sunbird.keycloak.storage.spi.UserSearchService;
import org.sunbird.keycloak.storage.spi.UserService;
import org.jboss.logging.Logger;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class BruteForceUserAdminResourceProvider implements AdminRealmResourceProvider {

    private static final Logger logger = Logger.getLogger(BruteForceUserAdminResourceProvider.class);
    private final KeycloakSession session;

    public BruteForceUserAdminResourceProvider(KeycloakSession session) {
        this.session = session;
        logger.debug("PROVIDER CONSTRUCTOR CALLED - BruteForceUserResourceProvider created");
    }

    @Override
    public void close() {
        logger.debug("PROVIDER close() CALLED");
    }

    public static class BruteForceResource {
        private static final Logger logger = Logger.getLogger(BruteForceResource.class);
        private final KeycloakSession session;
        private final UserService userService;

        public BruteForceResource(KeycloakSession session) {
            this.session = session;
            this.userService = new UserService();
            logger.debug("RESOURCE CONSTRUCTOR CALLED - BruteForceResource created");
        }

        @GET
        @Path("test")
        @Produces(MediaType.APPLICATION_JSON)
        public Response test() {
            logger.debug("TEST ENDPOINT CALLED!");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Test endpoint working!");
            response.put("timestamp", System.currentTimeMillis());
            response.put("session", session != null ? "Available" : "NULL");
            return Response.ok(response).build();
        }

        @GET
        @Path("brute-force-user")
        @Produces(MediaType.APPLICATION_JSON)
        public Response getBruteForceUsers(@QueryParam("search") String search,
                                        @QueryParam("first") @DefaultValue("0") int first,
                                        @QueryParam("max") @DefaultValue("20") int max,
                                        @QueryParam("briefRepresentation") @DefaultValue("false") boolean briefRepresentation,
                                        @QueryParam("q") String q) {
            
            logger.debug("BruteForceUserResource: getBruteForceUsers called");
            logger.debug("Parameters: search=" + search + ", q=" + q + ", first=" + first + ", max=" + max + ", brief=" + briefRepresentation);
            
            RealmModel realm = session.getContext().getRealm();
            logger.debug("Realm: " + (realm != null ? realm.getName() : "NULL"));
            
            if (search == null || search.trim().isEmpty()) {
                logger.warn("Search term is empty, returning empty list");
                return Response.ok(List.of()).build();
            }

            String trimmedSearch = search.trim();
            logger.debug("Searching for users with search term: '" + trimmedSearch + "'");

            List<User> users = null;
            
            try {
                // Method 1: Try UserService first
                logger.debug("Step 1: Trying UserService.getByUsername()");
                if (userService != null) {
                    users = userService.getByUsername(trimmedSearch);
                    logger.debug("UserService.getByUsername result: " + (users != null ? users.size() : "NULL") + " users");
                } else {
                    logger.warn("UserService is null, skipping");
                }
                
                // Method 2: Try UserSearchService by email
                if (users == null || users.isEmpty()) {
                    logger.debug("Step 2: Trying UserSearchService.getUserByKey('email')");
                    try {
                        users = UserSearchService.getUserByKey("email", trimmedSearch);
                        logger.debug("getUserByKey('email') result: " + (users != null ? users.size() : "NULL") + " users");
                    } catch (Exception e) {
                        logger.error("Error in UserSearchService.getUserByKey('email'): " + e.getMessage(), e);
                    }
                }
                
                // Method 3: Try UserSearchService by username
                if (users == null || users.isEmpty()) {
                    logger.debug("Step 3: Trying UserSearchService.getUserByKey('userName')");
                    try {
                        users = UserSearchService.getUserByKey("userName", trimmedSearch);
                        logger.debug("getUserByKey('userName') result: " + (users != null ? users.size() : "NULL") + " users");
                    } catch (Exception e) {
                        logger.error("Error in UserSearchService.getUserByKey('userName'): " + e.getMessage(), e);
                    }
                }
                
            } catch (Exception e) {
                logger.error("Exception during user search: " + e.getMessage(), e);
                return Response.serverError().entity(Map.of("error", "Search failed: " + e.getMessage())).build();
            }
            
            if (users == null) {
                logger.warn("Users list is null, initializing empty list");
                users = List.of();
            }
            
            logger.debug("Total users found before conversion: " + users.size());
            
            // Convert to UserRepresentation
            List<UserRepresentation> userReps;
            try {
                userReps = users.stream()
                        .peek(user -> logger.debug("Processing user: " + (user != null ? user.getUsername() : "NULL")))
                        .map(user -> {
                            UserRepresentation rep = new UserRepresentation();
                            rep.setId(user.getId());
                            rep.setUsername(user.getUsername());
                            rep.setFirstName(user.getFirstName());
                            rep.setLastName(user.getLastName());
                            rep.setEmail(user.getEmail());
                            rep.setEnabled(user.isEnabled());
                            rep.setEmailVerified(user.isEmailVerified());
                            
                            if (!briefRepresentation) {
                                // Add more detailed information if not brief
                                Map<String, List<String>> attributes = new HashMap<>();
                                if (user.getPhone() != null) {
                                    attributes.put("phone", List.of(user.getPhone()));
                                }
                                if (user.getCountryCode() != null) {
                                    attributes.put("countryCode", List.of(user.getCountryCode()));
                                }
                                rep.setAttributes(attributes);
                            }
                            
                            return rep;
                        })
                        .skip(first)
                        .limit(max)
                        .collect(Collectors.toList());
                        
                logger.debug("Successfully converted " + userReps.size() + " users to UserRepresentation");
                logger.debug("Final response size: " + userReps.size() + " users");
                
            } catch (Exception e) {
                logger.error("Exception during user conversion: " + e.getMessage(), e);
                return Response.serverError().entity(Map.of("error", "Conversion failed: " + e.getMessage())).build();
            }

            return Response.ok(userReps).build();
        }

        // Add a simple root endpoint for testing
        @GET
        @Produces(MediaType.APPLICATION_JSON)
        public Response root() {
            logger.debug("ROOT ENDPOINT CALLED!");
            Map<String, Object> response = new HashMap<>();
            response.put("message", "BruteForce Resource Provider is working!");
            response.put("available_endpoints", new String[]{"test", "brute-force-users"});
            response.put("timestamp", System.currentTimeMillis());
            return Response.ok(response).build();
        }
    }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        logger.debug("PROVIDER getResource() CALLED - returning BruteForceResource");
        return new BruteForceResource(session);
    }

}