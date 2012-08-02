package examples.security.providers.identityassertion.simple;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import weblogic.management.security.ProviderMBean;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;

/**
 * The simple sample identity asserter's runtime implementation.
 *
 * It looks for tokens of type "SamplePerimeterAtnToken"
 * whose matching token is an array of bytes containing a
 * string in the form "username=someusername".
 *
 * It extracts the username from the token and stores it
 * in a SimpleSampleCallbackHandlerImpl.  This is returned to the
 * security framework who hands it to the authenticators'
 * login modules.  The login modules can use a NameCallback
 * to retrieve the user name from the simple sample identity
 * asserter's callback handler.
 *
 * Since it is an identity asserter, it must implement
 * the weblogic.security.spi.AuthenticationProvider and
 * the weblogic.security.spi.IdentityAsserter interfaces.
 *
 * It can either implement two classes, and use the
 * provider implementation as the factory as the
 * factory for the identity asserter, or it can implement
 * both interfaces in one class.  The simple sample identity
 * asserter implments both interfaces in one class.
 *
 * Note: The simple sample identity asserter's mbean's ProviderClassName
 * attribute must be set the the name of this class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
public final class SimpleSampleIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2
{
  final static private String TOKEN_TYPE   = "SamplePerimeterAtnToken"; // the kind of token's we handle
  final static private String TOKEN_PREFIX = "username="; // the token contains a string in the form "username=someusername"

  private String description; // a description of this provider

  /**
   * Initialize the simple sample identity asserter.
   *
   * @param mbean A ProviderMBean that holds the simple sample identity asserter's
   * configuration data.  This mbean must be an instance of the simple sample
   * identity asserter's mbean.
   *
   * @param services The SecurityServices gives access to the auditor
   * so that the provider can to post audit events.
   * The simple sample role mapper doesn't use this parameter.
   *
   * @see SecurityProvider
   */
  public void initialize(ProviderMBean mbean, SecurityServices services)
  {
    System.out.println("SimpleSampleIdentityAsserterProviderImpl.initialize");
    SimpleSampleIdentityAsserterMBean myMBean = (SimpleSampleIdentityAsserterMBean)mbean;
    description                         = myMBean.getDescription() + "\n" + myMBean.getVersion();
  }

  /**
   * Get the simple sample identity asserter's description.
   *
   * @return A String containing a brief description of the simple sample identity asserter.
   *
   * @see SecurityProvider
   */
  public String getDescription()
  {
    return description;
  }

  /**
   * Shutdown the simple sample identity asserter.
   *
   * A no-op.
   *
   * @see SecurityProvider
   */
  public void shutdown()
  {
    System.out.println("SimpleSampleIdentityAsserterProviderImpl.shutdown");
  }

  /**
   * Gets the simple sample identity assertion provider's identity asserter object.
   *
   * @return The simple sample identity assertion provider's IdentityAsserter object.
   *
   * @see AuthenticationProvider
   */
  public IdentityAsserterV2 getIdentityAsserter()
  {
    return this;
  }

  /**
   * Assert identity given a token that identifies the user.
   *
   * @param type A String containing the token type.  The simple sample identity
   * asserter only supports tokens of type "SamplePerimeterAtnToken".
   * Also, the simple sample identity asserter's mbean's "ActiveTypes" attribute
   * must be set to "SamplePerimeterAtnToken" (which is done by default
   * when the mbean is created).
   *
   * @param token An Object containing the token that identifies the user.
   * The simple sample identity asserter's token must be an array of bytes
   * containing a String of the form "username=someusername".
   *
   * @param handler A ContextHandler object that can optionally
   * be used to obtain additional information that may be used in
   * asserting the identity.  If the caller is unable to provide additional
   * information, a null value should be specified.  This sample
   * ignores the handler.
   *
   * While, for simplicity, this sample does not validate the
   * contents of the token, identity asserters typically should do
   * this (to prevent someone from forging a token).  For
   * example, when using Kerberos, the token may be generated
   * and "signed" by a Kerberos server and the identity asserter
   * hands the token back to the Kerberos server to get it
   * validated.  Another example: when asserting identity from
   * X509 certificates, then identity asserter should validate the
   * certificate - that it hasn't been tampered, that it's been
   * signed by a trusted CA, that it hasn't expired or revoked, etc.
   *
   * @return a CallbackHandler that stores the username from the token.
   * The username can only be retrieved from the callback handler by
   * passing in a NameCallback.  The sample returns an instance of
   * its CallbackHandler implementation (SimpleSampleCallbackHandlerImpl).
   *
   * @throws IdentityAssertionException if another token type is passed
   * in or the token doesn't have the correct form.
   */
  public CallbackHandler assertIdentity(String type, Object token, ContextHandler context) throws IdentityAssertionException
  {
    System.out.println("SimpleSampleIdentityAsserterProviderImpl.assertIdentity");
    System.out.println("\tType\t\t= "  + type);
    System.out.println("\tToken\t\t= " + token);

    // check the token type
    if (!(TOKEN_TYPE.equals(type))) {
      String error =
        "SimpleSampleIdentityAsserter received unknown token type \"" + type + "\"." +
        " Expected " + TOKEN_TYPE;
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }

    // make sure the token is an array of bytes
    if (!(token instanceof byte[])) {
      String error = 
        "SimpleSampleIdentityAsserter received unknown token class \"" + token.getClass() + "\"." +
        " Expected a byte[].";
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }

    // convert the array of bytes to a string
    byte[] tokenBytes = (byte[])token;
    if (tokenBytes == null || tokenBytes.length < 1) {
      String error =
        "SimpleSampleIdentityAsserter received empty token byte array";
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }

    String tokenStr = new String(tokenBytes);

    // make sure the string contains "username=someusername
    if (!(tokenStr.startsWith(TOKEN_PREFIX))) {
      String error =
        "SimpleSampleIdentityAsserter received unknown token string \"" + type + "\"." +
        " Expected " + TOKEN_PREFIX + "username";
      System.out.println("\tError: " + error);
      throw new IdentityAssertionException(error);
    }

    // extract the username from the token
    String userName = tokenStr.substring(TOKEN_PREFIX.length());
    System.out.println("\tuserName\t= " + userName);

    // store it in a callback handler that authenticators can use
    // to retrieve the username.
    return new SimpleSampleCallbackHandlerImpl(userName);
  }

  /**
   * Return how to call the login module to perform authentication.
   *
   * @return A null AppConfigurationEntry since the simple sample identity
   * asserter is not an authenticator (thus doesn't have a login module).
  */
  public AppConfigurationEntry getLoginModuleConfiguration()
  {
    return null;
  }

  /**
   * Return how to call the login module to complete identity
   * assertion (where the identity asserter finds the user name
   * and the authenticator puts the user and its groups into the
   * subject).
   *
   * @return A null AppConfigurationEntry since the simple sample identity
   * asserter is not an authenticator (thus doesn't have a login module).
  */
  public AppConfigurationEntry getAssertionModuleConfiguration()
  {
    return null;
  }

  /**
   * Return an object that can validate principals (eg. users
   * and groups) that this provider puts into the subject.
   *
   * @return A null PrincipalValidator since the simple sample identity asserter
   * is not an authenticator (thus doesn't put principals into the subject).
   */
  public PrincipalValidator getPrincipalValidator() 
  {
    return null;
  }
}
