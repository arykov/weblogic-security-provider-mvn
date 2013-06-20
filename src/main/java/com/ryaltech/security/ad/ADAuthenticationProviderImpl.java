package com.ryaltech.security.ad;

import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.TrustManager;
import javax.security.auth.login.AppConfigurationEntry;

import weblogic.logging.NonCatalogLogger;
import weblogic.management.security.ProviderMBean;
import weblogic.security.provider.PrincipalValidatorImpl;
import weblogic.security.spi.AuthenticationProvider;
import weblogic.security.spi.IdentityAsserter;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;



public class ADAuthenticationProviderImpl implements AuthenticationProvider {
	static final String AUTHENTICATOR = "AUTHENTICATOR";
	static final String VERBOSE_KEY = "VERBOSE_KEY";

	private static final String LOGIN_MODULE_CLASS_NAME = ADLoginModuleImpl.class
			.getName();
	private static final NonCatalogLogger logger = new NonCatalogLogger(
			"ADAuthenticationProviderImpl");

	private AppConfigurationEntry.LoginModuleControlFlag ctrlFlag = null;

	private Boolean verboseDebug = null;
	private String description;
	private ActiveDirectoryUserAuthenticator authenticator;

	private static final Pattern cnExtractorPattern = Pattern
			.compile("CN=(.*?)(?<!\\\\),.*");

	/**
	 * This method exists to extract 123 from the following CN=123,OU=xyz,....
	 * It is created to deal with some security providers(SiteMinder as well as our SimplifiedADAuthenticator)
	 * passing full DNs from AD in some circumstances If name does not match the
	 * pattern name is returned back untouched
	 *
	 * @param name
	 * @return
	 */
	private String getPrincipalName(Principal p) {
		String name = p.getName();
		Matcher matcher = cnExtractorPattern.matcher(name);
		if (matcher.matches()) {
			return matcher.group(1);
		} else {
			return name;
		}
	}

	@Override
	public String getDescription() {

		return description;
	}

	@Override
	public void initialize(ProviderMBean providerMBean, SecurityServices arg1) {
		SimplifiedADAuthenticatiorMBean adAuthMapperMBean = (SimplifiedADAuthenticatiorMBean) providerMBean;
		description = adAuthMapperMBean.getDescription() + "\n"
				+ adAuthMapperMBean.getVersion();
		verboseDebug = adAuthMapperMBean.isVerbose() ? Boolean.TRUE
				: Boolean.FALSE;

		String flag = adAuthMapperMBean.getControlFlag();

		//configure SSL if needed
		TrustManager trustManager = null;
		if(Boolean.TRUE == adAuthMapperMBean.isSslEnabled()){
			trustManager = new WebLogicTrustManager(adAuthMapperMBean.getRealm().getName());
		}

		//TODO: add validation
		try {
			authenticator = new ActiveDirectoryUserAuthenticator(adAuthMapperMBean.getUserBaseDn(), adAuthMapperMBean.getPrincipal(), adAuthMapperMBean.getCredential(), adAuthMapperMBean.getAdHost(), adAuthMapperMBean.getAdPort(), adAuthMapperMBean.getPoolSize(), adAuthMapperMBean.isSslEnabled(), trustManager);
		} catch (GeneralSecurityException e) {
			logger.error("Failed to create ad authenticator",e);
		}




		if ("REQUIRED".equalsIgnoreCase(flag)) {
			ctrlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
		} else if ("OPTIONAL".equalsIgnoreCase(flag)) {
			ctrlFlag = AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL;
		} else if ("SUFFICIENT".equalsIgnoreCase(flag)) {
			ctrlFlag = AppConfigurationEntry.LoginModuleControlFlag.SUFFICIENT;
		} else if ("REQUISITE".equalsIgnoreCase(flag)) {
			ctrlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUISITE;
		} else {
			throw new IllegalArgumentException("Invalid control flag " + flag);
		}

	}

	@Override
	public void shutdown() {
	}

	@Override
	public AppConfigurationEntry getAssertionModuleConfiguration() {

		return null;
	}

	@Override
	public IdentityAsserter getIdentityAsserter() {
		return null;
	}

	@Override
	public AppConfigurationEntry getLoginModuleConfiguration() {
		Map<String, Object> options = new HashMap<String, Object>(4);
		options.put(VERBOSE_KEY, verboseDebug);
		options.put(AUTHENTICATOR, authenticator);

		return new AppConfigurationEntry(LOGIN_MODULE_CLASS_NAME, ctrlFlag,
				options);
	}

	@Override
	public PrincipalValidator getPrincipalValidator() {
		return new PrincipalValidatorImpl();
	}

}
