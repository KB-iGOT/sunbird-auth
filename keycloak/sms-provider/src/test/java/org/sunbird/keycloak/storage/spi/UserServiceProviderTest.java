package org.sunbird.keycloak.storage.spi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import org.junit.BeforeClass;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.RoleModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.sunbird.keycloak.storage.spi.User;
import org.sunbird.keycloak.storage.spi.UserAdapter;
import org.sunbird.keycloak.storage.spi.UserService;
import org.sunbird.keycloak.storage.spi.UserSearchService;

@RunWith(PowerMockRunner.class)
@PrepareForTest({StorageId.class, KeycloakSession.class, ComponentModel.class, UserService.class,
  UserAdapter.class, RealmModel.class, UserModel.class, UserSearchService.class, GroupModel.class,
  User.class, RoleModel.class})
@PowerMockIgnore({"javax.management.*", "javax.net.ssl.*", "javax.security.*"})
public class UserServiceProviderTest {

  private static KeycloakSession session = null;
  private static ComponentModel model = null;
  private static UserService userService = null;
  private static UserAdapter userAdapter = null;
  private static RealmModel realm = null;
  private static UserModel userModel = null;
  private static User user = null;
  private static User user2 = null;
  private static List<User> userList = new ArrayList<>();
  private static List<User> multipleUserList = new ArrayList<>();
  private static GroupModel groupModel = null;
  private static RoleModel roleModel = null;
  
  @BeforeClass
  public static void setUp() throws Exception {
    // Initialize mocks first
    groupModel = PowerMockito.mock(GroupModel.class);
    session = PowerMockito.mock(KeycloakSession.class);
    model = PowerMockito.mock(ComponentModel.class);
    userService = PowerMockito.mock(UserService.class);
    realm = PowerMockito.mock(RealmModel.class);
    userAdapter = PowerMockito.mock(UserAdapter.class);
    userModel = PowerMockito.mock(UserModel.class);
    roleModel = PowerMockito.mock(RoleModel.class);
    
    // Create user objects
    user = new User("12345", "firstName", "lastName");
    user.setUsername("username");
    user.setEmail("amit@gmail.com");
    user.setPhone("9876543210");
    userList.add(user);
    
    user2 = new User("67890", "firstName2", "lastName2");
    user2.setUsername("username2");
    user2.setEmail("amit2@gmail.com");
    user2.setPhone("9123456780");
    multipleUserList.add(user);
    multipleUserList.add(user2);
    
    // Setup static mocks
    mockStatic(StorageId.class);
    mockStatic(UserSearchService.class);
    
    // Setup StorageId mock
    PowerMockito.when(StorageId.externalId(Mockito.anyString())).thenReturn("12345");
    
    // Setup UserService mocks
    PowerMockito.when(userService.getById("12345")).thenReturn(user);
    PowerMockito.when(userService.getById("67890")).thenReturn(user2);
    PowerMockito.when(userService.getByUsername("username")).thenReturn(userList);
    PowerMockito.when(userService.getByUsername("username2")).thenReturn(multipleUserList);
    PowerMockito.when(userService.getByUsername("amit@gmail.com")).thenReturn(userList);
    PowerMockito.when(userService.getByUsername("amit2@gmail.com")).thenReturn(multipleUserList);
    
    // Setup UserAdapter constructor mock
    PowerMockito.whenNew(UserAdapter.class)
      .withArguments(Mockito.eq(session), Mockito.eq(realm), Mockito.eq(model), Mockito.eq(user))
      .thenReturn(userAdapter);
    
    PowerMockito.whenNew(UserAdapter.class)
      .withArguments(Mockito.eq(session), Mockito.eq(realm), Mockito.eq(model), Mockito.eq(user2))
      .thenReturn(userAdapter);
    
    // Setup UserAdapter method mocks
    PowerMockito.when(userAdapter.getFirstName()).thenReturn("firstName");
    PowerMockito.when(userAdapter.getLastName()).thenReturn("lastName");
    PowerMockito.when(userAdapter.getUsername()).thenReturn("username");
    PowerMockito.when(userAdapter.getEmail()).thenReturn("amit@gmail.com");
    PowerMockito.when(userAdapter.getId()).thenReturn("12345");
  }
  
  @Before
  public void setUpEach() {
    // Reset any per-test specific mocks if needed
  }
  
  @Test
  public void getUserByIdTest() throws Exception {
    UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
    UserModel result = userServiceProvider.getUserById(realm, "12345");
    assertNotNull(result);
    assertEquals("firstName", result.getFirstName());
  }
  
  @Test
  public void getUserByIdTestNotFound() {
    PowerMockito.when(userService.getById("nonexistent")).thenReturn(null);
    UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
    UserModel result = userServiceProvider.getUserById(realm, "nonexistent");
    assertNull(result);
  }
  
  @Test
  public void getUserByUsernameTest() throws Exception {
    UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
    UserModel result = userServiceProvider.getUserByUsername(realm, "username");
    assertNotNull(result);
    assertEquals("firstName", result.getFirstName()); 
    assertEquals("username", result.getUsername());
  }
  
  @Test
  public void getUserByUsernameTestNotFound() {
    PowerMockito.when(userService.getByUsername("nonexistent")).thenReturn(new ArrayList<>());
    UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
    UserModel result = userServiceProvider.getUserByUsername(realm, "nonexistent");
    assertNull(result);
  }
  
  @Test
  public void getUserByEmailTest() throws Exception {
    UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
    UserModel result = userServiceProvider.getUserByEmail(realm, "amit@gmail.com");
    assertNotNull(result);
    assertEquals("amit@gmail.com", result.getEmail());
  }
  
  @Test
  public void getUserByEmailTestNotFound() {
    PowerMockito.when(userService.getByUsername("nonexistent@email.com")).thenReturn(new ArrayList<>());
    UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
    UserModel result = userServiceProvider.getUserByEmail(realm, "nonexistent@email.com");
    assertNull(result);
  }
  
  // @Test
  // public void searchForUserByStringTest() throws Exception {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   List<UserModel> userModelList = userServiceProvider.searchForUser("amit@gmail.com", realm);
  //   assertNotNull(userModelList);
  //   assertEquals(1, userModelList.size());
  //   assertEquals("amit@gmail.com", userModelList.get(0).getEmail());
  // }
  
  // @Test
  // public void searchForUserByStringTestNotFound() {
  //   PowerMockito.when(userService.getByUsername("nonexistent")).thenReturn(new ArrayList<>());
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   List<UserModel> userModelList = userServiceProvider.searchForUser("nonexistent", realm);
  //   assertNotNull(userModelList);
  //   assertEquals(0, userModelList.size());
  // }
  
  // @Test
  // public void searchForUserWithPaginationTest() throws Exception {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   List<UserModel> userModelList = userServiceProvider.searchForUser("amit@gmail.com", realm, 0, 5);
  //   assertNotNull(userModelList);
  //   assertEquals(1, userModelList.size());
  //   assertEquals("amit@gmail.com", userModelList.get(0).getEmail());
  // }
  
  // @Test
  // public void searchForUserWithParamsWithPaginationTest() {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   Map<String, String> params = new HashMap<>();
  //   List<UserModel> userModelList = userServiceProvider.searchForUser(params, realm, 1, 5);
  //   assertNotNull(userModelList);
  //   assertEquals(0, userModelList.size());
  // }
  
  // @Test
  // public void searchForUserWithParamsTest() {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   Map<String, String> params = new HashMap<>();
  //   List<UserModel> userModelList = userServiceProvider.searchForUser(params, realm);
  //   assertNotNull(userModelList);
  //   assertEquals(0, userModelList.size());
  // }
  
  // @Test
  // public void searchForUserWithParamsUsernameTest() throws Exception {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   Map<String, String> params = new HashMap<>();
  //   params.put("username", "username");
  //   List<UserModel> userModelList = userServiceProvider.searchForUser(params, realm);
  //   assertNotNull(userModelList);
  //   assertEquals(1, userModelList.size());
  // }
  
  // @Test
  // public void searchForUserWithParamsEmailTest() throws Exception {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   Map<String, String> params = new HashMap<>();
  //   params.put("email", "amit@gmail.com");
  //   List<UserModel> userModelList = userServiceProvider.searchForUser(params, realm);
  //   assertNotNull(userModelList);
  //   assertEquals(1, userModelList.size());
  // }
  
  // @Test
  // public void getGroupMembersTest() {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   List<UserModel> userModelList = userServiceProvider.getGroupMembers(realm, groupModel);
  //   assertNotNull(userModelList);
  //   assertEquals(0, userModelList.size());
  // }
  
  // @Test
  // public void getGroupMembersWithPaginationTest() {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   List<UserModel> userModelList = userServiceProvider.getGroupMembers(realm, groupModel, 1, 5);
  //   assertNotNull(userModelList);
  //   assertEquals(0, userModelList.size());
  // }
  
  @Test
  public void getUsersCountTest() {
    UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
    int userCount = userServiceProvider.getUsersCount(realm);
    assertEquals(0, userCount);
  }
  
  // @Test
  // public void getUsersWithPaginationTest() {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   List<UserModel> userModelList = userServiceProvider.getUsers(realm, 1, 5);
  //   assertNotNull(userModelList);
  //   assertEquals(0, userModelList.size());
  // }
  
  // @Test
  // public void getUsersTest() {
  //   UserServiceProvider userServiceProvider = new UserServiceProvider(session, model, userService);
  //   List<UserModel> userModelList = userServiceProvider.getUsers(realm);
  //   assertNotNull(userModelList);
  //   assertEquals(0, userModelList.size());
  // }
}
