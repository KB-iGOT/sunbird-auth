package org.sunbird.keycloak.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Unit tests for the phone normalisation/validation used before provisioning a learner user. */
public class CheckExistingLearnerUserAuthenticatorTest {

  @Test
  public void plainTenDigitNumberIsAcceptedAsIs() {
    assertEquals("9876543210", CheckExistingLearnerUserAuthenticator.normalizePhone("9876543210"));
    assertTrue(CheckExistingLearnerUserAuthenticator.isValidPhone("9876543210"));
  }

  @Test
  public void formattingCharactersAreStripped() {
    assertEquals("9876543210", CheckExistingLearnerUserAuthenticator.normalizePhone(" (987) 654-3210 "));
  }

  @Test
  public void countryCodeAndTrunkPrefixAreStripped() {
    assertEquals("9876543210", CheckExistingLearnerUserAuthenticator.normalizePhone("+91 98765 43210"));
    assertEquals("9876543210", CheckExistingLearnerUserAuthenticator.normalizePhone("+919876543210"));
    assertEquals("9876543210", CheckExistingLearnerUserAuthenticator.normalizePhone("09876543210"));
    assertEquals("9876543210", CheckExistingLearnerUserAuthenticator.normalizePhone("00919876543210"));
  }

  @Test
  public void blankPhoneNormalisesToEmptyAndIsInvalid() {
    assertEquals("", CheckExistingLearnerUserAuthenticator.normalizePhone(null));
    assertEquals("", CheckExistingLearnerUserAuthenticator.normalizePhone("   "));
    assertFalse(CheckExistingLearnerUserAuthenticator.isValidPhone(""));
    assertFalse(CheckExistingLearnerUserAuthenticator.isValidPhone(null));
  }

  @Test
  public void shortLongAndNonNumericPhonesAreInvalid() {
    assertFalse(CheckExistingLearnerUserAuthenticator.isValidPhone("98765"));
    assertFalse(CheckExistingLearnerUserAuthenticator.isValidPhone("98765432101234"));
    assertFalse(CheckExistingLearnerUserAuthenticator.isValidPhone("98765abcde"));
    assertFalse(CheckExistingLearnerUserAuthenticator.isValidPhone("987654321"));
  }

  /** Values too long to be a country code + national number must not be silently truncated. */
  @Test
  public void implausiblyLongNumbersAreNotTruncated() {
    String tooLong = "98765432101234";
    assertEquals(tooLong, CheckExistingLearnerUserAuthenticator.normalizePhone(tooLong));
    assertFalse(CheckExistingLearnerUserAuthenticator.isValidPhone(
        CheckExistingLearnerUserAuthenticator.normalizePhone(tooLong)));
  }
}
