package examples.security.providers.identityassertion.simple;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * The simple sample identity asserter's implementation of the
 * CallbackHandler interface.
 *
 * It is used to make the name of the user from the identity
 * assertion token available to the authenticators (who, in
 * turn, will populate the subject with the user and the user's
 * groups).
 *
 * This class is internal to the simple sample identity asserter.
 * It is not a public class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
/*package*/ class SimpleSampleCallbackHandlerImpl implements CallbackHandler
{
  private String userName; // the name of the user from the identity assertion token

  /**
   * Create a callback handler that stores the user name.
   *
   * @param user A String containing the name of the user
   * from the identity assertion token
   */
  /*package*/ SimpleSampleCallbackHandlerImpl(String user)
  {
    userName = user;
  }

  /**
   * Used by the authenticators' login modules to get the user name
   * that the identity asserter extracted from the identity assertion token.
   * This name can only be retrieved via a NameCallback.
   *
   * @param callbacks An array of Callback objects indicating what data
   * the login module is trying to extract from this callback handler.
   * It must only contain NameCallbacks.
   *
   * @exception UnsupportedCallbackException thrown if any of the callbacks
   * aren't NameCallbacks.
   *
   * @see CallbackHandler
   */
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException
  {
    // loop over the callbacks
    for (int i = 0; i < callbacks.length; i++) {

      Callback callback = callbacks[i];

      // we only handle NameCallbacks
      if (!(callback instanceof NameCallback)) {
        throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
      }

      // send the user name to the name callback:
      NameCallback nameCallback = (NameCallback)callback;
      nameCallback.setName(userName);
    }
  }
}
