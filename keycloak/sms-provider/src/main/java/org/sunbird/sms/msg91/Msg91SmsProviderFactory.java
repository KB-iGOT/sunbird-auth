package org.sunbird.sms.msg91;

import java.util.Map;

import org.sunbird.sms.provider.ISmsProvider;
import org.sunbird.sms.provider.ISmsProviderFactory;

public class Msg91SmsProviderFactory implements ISmsProviderFactory {

	private static EnhancedMsg91SmsProvider msg91SmsProvider = null;

	@Override
	public ISmsProvider create(Map<String, String> configurations) {
		if (msg91SmsProvider == null) {
			msg91SmsProvider = new EnhancedMsg91SmsProvider();
			try {
				msg91SmsProvider.configure(configurations);
			} catch (Exception e) {
			}
		}
		return msg91SmsProvider;
	}
}
