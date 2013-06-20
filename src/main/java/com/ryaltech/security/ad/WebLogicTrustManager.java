package com.ryaltech.security.ad;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.X509TrustManager;

import weblogic.security.pk.CertPathValidatorParameters;

public class WebLogicTrustManager implements X509TrustManager {
	private String realm;
	CertPathValidator validator;

	CertificateFactory factory;

	CertPathValidator getValidator() {
		if (validator == null) {
			try {
				validator = CertPathValidator
						.getInstance("WLSCertPathValidator");

			} catch (NoSuchAlgorithmException ex) {
				throw new RuntimeException(ex);
			}

		}
		return validator;
	}

	CertificateFactory getCertificateFactory() {
		if (factory == null) {
			try {

				factory = CertificateFactory.getInstance("X509");
			} catch (CertificateException e) {
				throw new RuntimeException(e);
			}
		}
		return factory;
	}

	public WebLogicTrustManager(String realm) {
		this.realm = realm;

	}

	@Override
	public void checkClientTrusted(X509Certificate[] arg0, String arg1)
			throws CertificateException {
		throw new UnsupportedOperationException();

	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String arg1)
			throws CertificateException {
		CertPath certPath = getCertificateFactory().generateCertPath(Arrays.asList(chain));
		CertPathParameters params = new CertPathValidatorParameters(realm,
				null, null);
		try {
			getValidator().validate(certPath, params);
		} catch (CertPathValidatorException e) {
			throw new CertificateException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new CertificateException(e);
		}

	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		throw new UnsupportedOperationException();
	}

}
