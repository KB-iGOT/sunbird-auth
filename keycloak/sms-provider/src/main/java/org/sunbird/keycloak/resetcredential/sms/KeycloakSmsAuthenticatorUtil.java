package org.sunbird.keycloak.resetcredential.sms;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.sunbird.sms.msg91.Msg91SmsProviderFactory;
import org.sunbird.sms.provider.ISmsProvider;
import org.sunbird.utils.JsonUtil;

import com.amazonaws.util.StringUtils;

/**
 * Created by joris on 18/11/2016.
 */
public class KeycloakSmsAuthenticatorUtil {

    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticatorUtil.class);

    public static String getAttributeValue(UserModel user, String attributeName) {
        String result = null;
        List<String> values = user.getAttribute(attributeName);
        if (values != null && values.size() > 0) {
            result = values.get(0);
        }

        return result;
    }

    public static String getConfigString(AuthenticatorConfigModel config, String configName) {
        logger.info("KeycloakSmsAuthenticatorUtil@getConfigString: configName = " + configName);
        return getConfigString(config, configName, null);
    }

    public static String getConfigString(AuthenticatorConfigModel config, String configName, String defaultValue) {
        logger.info("KeycloakSmsAuthenticatorUtil@getConfigString: configName = " + configName + ", defaultValue = " + defaultValue);

        String value = defaultValue;

        if (config.getConfig() != null) {
            logger.info("KeycloakSmsAuthenticatorUtil@getConfigString: config.getConfig() is not null");
            // Get value
            value = config.getConfig().get(configName);
        }

        return value;
    }

    public static Long getConfigLong(AuthenticatorConfigModel config, String configName) {
        return getConfigLong(config, configName, null);
    }

    public static Long getConfigLong(AuthenticatorConfigModel config, String configName, Long defaultValue) {
        logger.info("KeycloakSmsAuthenticatorUtil@getConfigLong: configName = " + configName + ", defaultValue = " + defaultValue);

        Long value = defaultValue;

        if (config.getConfig() != null) {
            logger.info("KeycloakSmsAuthenticatorUtil@getConfigLong: config.getConfig() is not null");
            // Get value
            Object obj = config.getConfig().get(configName);
            try {
                logger.info("KeycloakSmsAuthenticatorUtil@getConfigLong: obj = " + obj);
                value = Long.valueOf((String) obj); // s --> ms
            } catch (NumberFormatException nfe) {
                logger.error("Can not convert " + obj + " to a number.");
            }
        }

        return value;
    }

    public static String createMessage(String code, String mobileNumber, AuthenticatorConfigModel config) {
        logger.info("KeycloakSmsAuthenticatorUtil@createMessage : code - " + code + ", mobileNumber - " + mobileNumber);
        String text = KeycloakSmsAuthenticatorUtil.getConfigString(config, KeycloakSmsAuthenticatorConstants.CONF_PRP_SMS_TEXT);
        logger.debug("KeycloakSmsAuthenticatorUtil@createMessage : templateText - " + text);
        text = text.replaceAll("%sms-code%", code);
        text = text.replaceAll("%phonenumber%", mobileNumber);
        logger.info("KeycloakSmsAuthenticatorUtil@createMessage : text - " + text);

        return text;
    }

    public static String setDefaultCountryCodeIfZero(String mobileNumber) {
        if (mobileNumber.startsWith(KeycloakSmsAuthenticatorConstants.DEFAULT_COUNTRY_CODE)) {
            mobileNumber = KeycloakSmsAuthenticatorConstants.COUNTRY_CODE + mobileNumber.substring(1);
        } else if (mobileNumber.startsWith(KeycloakSmsAuthenticatorConstants.COUNTRY_CODE)) {
            //nothing to do
        } else {
            mobileNumber = KeycloakSmsAuthenticatorConstants.COUNTRY_CODE + mobileNumber;
        }

        return mobileNumber;
    }

    static boolean sendSmsCode(String mobileNumber, String code, AuthenticatorConfigModel config) {
        logger.info("KeycloakSmsAuthenticatorUtil@sendSmsCode : mobileNumber - " + mobileNumber + ", code - " + code);
        String smsText = createMessage(code, mobileNumber, config);
        logger.debug("KeycloakSmsAuthenticatorUtil@sendSmsCode : smsText - " + smsText);
        logger.info("KeycloakSmsAuthenticatorUtil@sendSmsCode : Sending SMS to " + mobileNumber + " with text: " + smsText);

        return send(mobileNumber, smsText);
    }

    public static boolean send(String mobileNumber, String code) {
        logger.info("KeycloakSmsAuthenticatorUtil@send : mobileNumber - " + mobileNumber + ", code - " + code);
        String filePath = new File(KeycloakSmsAuthenticatorConstants.MSG91_SMS_PROVIDER_CONFIGURATIONS_PATH).getAbsolutePath();
        logger.debug("KeycloakSmsAuthenticatorUtil@sendSmsCode : filePath - " + filePath);

        if (!StringUtils.isNullOrEmpty(filePath)) {
            Map<String, String> configurations = JsonUtil.readFromJson(filePath);
            logger.debug("KeycloakSmsAuthenticatorUtil@sendSmsCode : configurations - " + configurations);

            Msg91SmsProviderFactory msg91SmsProviderFactory = new Msg91SmsProviderFactory();

            ISmsProvider msg91SmsProvider = msg91SmsProviderFactory.create(configurations);

            if (msg91SmsProvider != null) {
                return msg91SmsProvider.send(mobileNumber, code);
            }
        }
        return false;
    }

    public static String getSmsCode(long nrOfDigits) {
        logger.info("KeycloakSmsAuthenticatorUtil@getSmsCode: nrOfDigits = " + nrOfDigits);
        if (nrOfDigits < 1) {
            throw new RuntimeException("Number of digits must be bigger than 0");
        }

        long minValue = (long) Math.pow(10.0, (nrOfDigits - 1));
        long maxValue = (long) Math.pow(10.0, nrOfDigits); // 10 ^ nrOfDigits;
        long code = ThreadLocalRandom.current().nextLong(minValue, maxValue);
        logger.info("KeycloakSmsAuthenticatorUtil@getSmsCode: code = " + code);
        return Long.toString(code);
    }

    public static boolean validateTelephoneNumber(String telephoneNumber) {
        String pattern = "\\d{10}|(?:\\d{3}-){2}\\d{4}|\\(\\d{3}\\)\\d{3}-?\\d{4}";
        return telephoneNumber.matches(pattern);
    }
}
