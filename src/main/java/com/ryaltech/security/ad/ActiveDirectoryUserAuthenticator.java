package com.ryaltech.security.ad;

import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.forgerock.opendj.ldap.Attribute;
import org.forgerock.opendj.ldap.ByteString;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.ConnectionFactory;
import org.forgerock.opendj.ldap.Connections;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LDAPOptions;
import org.forgerock.opendj.ldap.SSLContextBuilder;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.TrustManagers;
import org.forgerock.opendj.ldap.requests.Requests;
import org.forgerock.opendj.ldap.requests.SearchRequest;
import org.forgerock.opendj.ldap.responses.BindResult;
import org.forgerock.opendj.ldap.responses.SearchResultEntry;
import org.forgerock.opendj.ldif.ConnectionEntryReader;

import weblogic.security.principal.WLSGroupImpl;
import weblogic.security.principal.WLSUserImpl;

public class ActiveDirectoryUserAuthenticator {
	private ConnectionFactory lookupFactory;
	private ConnectionFactory bindFactory;
	private String baseDN;

	ActiveDirectoryUserAuthenticator(String baseDN, String principal,
			String password, String adServer, int adPort, int poolSize,
			boolean isSsl, TrustManager tm) throws GeneralSecurityException {
		LDAPOptions options = new LDAPOptions();
		if(isSsl){
			SSLContext sslContext =
                    new SSLContextBuilder().setTrustManager(tm)
                            .getSSLContext();
			options.setSSLContext(sslContext);

		}
		lookupFactory = Connections
				.newFixedConnectionPool(
						Connections.newAuthenticatedConnectionFactory(
								Connections
										.newHeartBeatConnectionFactory(new LDAPConnectionFactory(
												adServer, adPort, options)), Requests
										.newSimpleBindRequest(principal,
												password.toCharArray())),
						poolSize);
		bindFactory = Connections.newFixedConnectionPool(Connections
				.newHeartBeatConnectionFactory(new LDAPConnectionFactory(
						adServer, adPort, options)), poolSize);
		this.baseDN = baseDN;

	}



	Set<Principal> authenticate(String user, char[] password) throws Exception {
		Connection lookupConn = lookupFactory.getConnection();

		Connection bindConn = bindFactory.getConnection();
		try {
			SearchRequest sr = Requests
					.newSearchRequest(
							baseDN,
							SearchScope.WHOLE_SUBTREE,
							String.format(
									"(&(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
									user), "sAMAccountName", "memberOf");
			ConnectionEntryReader reader = lookupConn.search(sr);
			SearchResultEntry sre = null;
			while (reader.hasNext()) {
				if (reader.isEntry()) {
					sre = reader.readEntry();
				}
			}
			if (sre == null)
				throw new RuntimeException(String.format(
						"Failed to find user: %s in AD", user));
			String userDn = sre.getName().toString();
			BindResult br = bindConn.bind(Requests.newSimpleBindRequest(userDn,
					password));
			if (br.isSuccess()) {
				Set<Principal> principals = new HashSet<Principal>();
				Attribute attr = sre.getAttribute("sAMAccountName");
				principals.add(new WLSUserImpl(attr.firstValueAsString()));
				attr = sre.getAttribute("memberOf");
				Iterator<ByteString> groupIterator = attr.iterator();
				while (groupIterator.hasNext()) {
					principals.add(new WLSGroupImpl(groupIterator.next().toString()));
				}

				return principals;


			} else {
				throw new RuntimeException(
						String.format("Failed to authenticate user: %s due to %s"));
			}
					} finally {
			try {
				lookupConn.close();
			} catch (Exception ex) {

			}
			try {
				bindConn.close();
			} catch (Exception ex) {

			}

		}
	}

}
