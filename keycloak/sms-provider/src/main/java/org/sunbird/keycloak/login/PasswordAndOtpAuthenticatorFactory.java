package org.sunbird.keycloak.login;

import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorConstants;

public class PasswordAndOtpAuthenticatorFactory implements AuthenticatorFactory {

    Logger logger = Logger.getLogger(PasswordAndOtpAuthenticatorFactory.class);
	public static final String ID = "password-otp-form";

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED };

	static {
		ProviderConfigProperty property;

		// SMS Code
		property = new ProviderConfigProperty();
		property.setName(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_TTL);
		property.setLabel("SMS code time to live");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setHelpText("The validity of the sent code in seconds.");
		configProperties.add(property);

		property = new ProviderConfigProperty();
		property.setName(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_CODE_LENGTH);
		property.setLabel("Length of the SMS code");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setHelpText("Length of the SMS code.");
		configProperties.add(property);

		property = new ProviderConfigProperty();
		property.setName(KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_PROVIDER);
		property.setLabel("Name of the SMS Service Provider");
		property.setHelpText("Provide the SMS Service Provider. Currently supported Providers - NIC, MSG91");
		configProperties.add(property);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
        logger.info("PasswordAndOtpAuthenticatorFactory@create - PasswordAndOtpAuthenticator is created");
		return new PasswordAndOtpAuthenticator();
	}

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public String getDisplayType() {
		return "Password And OTP Login Form";
	}

	@Override
	public String getReferenceCategory() {
		return "password-otp";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public String getHelpText() {
		return "Password And OTP Login Form";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public void init(Scope config) {
        logger.info("PasswordAndOtpAuthenticatorFactory@init - called");

	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
        logger.info("PasswordAndOtpAuthenticatorFactory@postInit - called");
	}

	@Override
	public void close() {
        logger.info("PasswordAndOtpAuthenticatorFactory@close - called");
	}
}
