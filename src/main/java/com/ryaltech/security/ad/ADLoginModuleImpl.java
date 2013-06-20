package com.ryaltech.security.ad;

import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import weblogic.logging.NonCatalogLogger;
import weblogic.security.principal.WLSGroupImpl;
import weblogic.security.principal.WLSUserImpl;



public class ADLoginModuleImpl implements LoginModule {

	private static final NonCatalogLogger logger = new NonCatalogLogger(
			"ADLoginModuleImpl");
	private Subject subject;
	private boolean verbose;
	boolean loginCommited = false;
	private Set<Principal> principalsBeforeCommit = new HashSet<Principal>();
	private ActiveDirectoryUserAuthenticator authenticator;
	private CallbackHandler callbackHandler;


	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		Boolean oVerbose = ((Boolean) options.get(ADAuthenticationProviderImpl.VERBOSE_KEY));
		authenticator = (ActiveDirectoryUserAuthenticator) options
				.get(ADAuthenticationProviderImpl.AUTHENTICATOR);

		if (oVerbose != null) {
			verbose = oVerbose.booleanValue();
		} else {
			verbose = false;
		}

	}

	@Override
	public boolean login() throws LoginException {

		NameCallback nameCallback = new NameCallback("username");
		PasswordCallback passwordCallback = new PasswordCallback("password",
				false);

		try {
			callbackHandler.handle(new Callback[] { nameCallback,
					passwordCallback });
		} catch (Exception ex) {
			logger.error("Failed to obtain user/password", ex);
			throw new LoginException(ex.getMessage());
		}
		String userName = nameCallback.getName();
		char[] password = passwordCallback.getPassword();

		try {

			principalsBeforeCommit = authenticator.authenticate(userName,
					password);
			StringBuffer sb = null;
			if (verbose) {
				sb = new StringBuffer("Userid ").append(userName).append(
						" maps to the following principals: ");
				for (Principal principal : principalsBeforeCommit) {
					if (verbose) {
						sb.append(principal).append(", ");
					}
				}

				logger.debug(sb.toString());
			}
		} catch (Exception ex) {
			logger.error("Failed to login user: " + userName, ex);
			throw new LoginException(ex.getMessage());

		}

		return true;
	}

	@Override
	public boolean commit() throws LoginException {
		subject.getPrincipals().addAll(principalsBeforeCommit);
		loginCommited = true;
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		if (loginCommited) {
			subject.getPrincipals().removeAll(principalsBeforeCommit);
		}
		return true;
	}

	@Override
	public boolean logout() throws LoginException {

		return true;
	}

}
