package examples.security.providers.authentication.simple;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;
import weblogic.management.utils.NotFoundException;

/**
 * The simple sample authenticator's persistent state (ie. database).
 *
 * The simple sample authenticator needs to keep a persistent
 * list of  user and group definitions.  A user has
 * a password and a list of groups that it is a member of.
 * A group has a list of other groups that it is a member of.
 *
 * This class holds this persistent state in a java properties
 * file.  The format of the file is:
 *  user.username=password,parentgroupname...  OR
 *  group.groupname=parentgroupname,...
 * That is, the user entries are prefixed by "user." and
 * the group entries are prefixed by "group."
 * Also, members list their groups (vs. groups listing
 * their members).
 *
 * While user names, group names and passwords normally have
 * no restrictions, the simple sample authenticator doesn't allow
 * these strings to have white space at the ends or to contain
 * commas.  Also, they may not be null.
 *
 * The name of the java properties file is
 * SimpleSampleAuthenticatorRealmName.properties where RealmName
 * is the name of the realm that containing the simple sample
 * authenticator.  Therefore, you should only configure one
 * simple sample authenticator in a realm (otherwise, the other one
 * will vie for the same properties file).
 *
 * If the properties file doesn't exist, then create one
 * and seed it with the default user and group definitions that
 * all authenticators should create.  It also creates the
 * users and groups that are needed for the perimeter
 * authentication (identity asserter) test.
 *
 * This class has methods for reading reading user and
 * group information.
 *
 * The simple sample authenticator's runtime implementation
 * delegates much of its work to this class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
/*package*/ final class SimpleSampleAuthenticatorDatabase
{
  private File       database; // the java properties file that the users & groups are stored in
  private Properties data = new Properties(); // an in-memory version of these users & groups

  private static final String USER_PREFIX  = "user.";  // prefix for properties containing user definitions
  private static final String GROUP_PREFIX = "group."; // prefix for properties containing group definitions

  /**
   * Determines if a user exists.
   *
   * @param user A String containing the user's name.
   *
   * @return A boolean.  true if the user exists, false otherwise.
   */
  /*package*/ synchronized boolean userExists(String user)
  {
    return keyExists(getUserKey(user));
  }

  /**
   * Looks up a user's password.
   *
   * @param user A String containing the user's name.
   *
   * @return A String containing the user's password.
   *
   * @throws NotFoundException if the user does not exist.
   */
  /*package*/ synchronized String getUserPassword(String user)
    throws NotFoundException
  {
    // find the name of property for this user
    String key = getUserKey(user);
    if (!keyExists(key)) {
      throw new NotFoundException("User \"" + user + "\" doesn't exist.");
    }

    // get the password out of the user's property value
    return getPasswordFromUserProperty(data.getProperty(key));
  }

  /**
   * Looks up the groups that a user is a member of recursively.
   * That is, if user1 is a member of group1 and group1 is a member
   * of group2, then group1 and group2 are returned.
   *
   * @param user A String containing the user's name.
   *
   * @return An Enumeration of Strings containing the group names.
   * Returns an empty enumeration if the user doesn't exist.
   */
  /*package*/ synchronized Enumeration getUserGroups(String user)
  {
    checkVal(user);

    // make a list for the groups
    Vector v = new Vector();

    // find the name of property for this user
    String key = getUserKey(user);

    if (keyExists(key)) {

      // get the groups that the user is immediately a member of from
      // the user's property value.
      String groupList = getGroupListFromUserProperty(data.getProperty(key));

      // recursively find all the groups that these groups are a member of.
      expandGroupList(v, groupList);
    }

    // return the groups
    return v.elements();
  }

  /**
   * Finds the property name for a user.
   *
   * The property name is "user.username".  It also checks
   * that the user name is valid.
   *
   * @param user A String containing the user's name.
   *
   * @return A String containing the user's property name.
   */
  private String getUserKey(String user)
  {
    checkVal(user);
    return USER_PREFIX + user;
  }

  /**
   * Finds the property name for a group.
   *
   * The property name is "group.groupname".  It also checks
   * that the group name is valid.
   *
   * @param group A String containing the group's name.
   *
   * @return A String containing the group's property name.
   */
  private String getGroupKey(String group)
  {
    checkVal(group);
    return GROUP_PREFIX + group;
  }

  /**
   * Determines if a property (ie. user/group) exists.
   *
   * @param key A String containing the property name
   *
   * @return A boolean. true if the property exists, false otherwise
   */
  private boolean keyExists(String key)
  {
    if (key == null) return false;
    return data.containsKey(key);
  }

  /**
   * Extracts a user's password from a user's property value.
   *
   * @param userProperty A String containing the user's property value
   * (which has the form "password,parentGroup,...")
   *
   * @return A String containing the user's password.
   */
  private String getPasswordFromUserProperty(String userProperty)
  {
    // if there are groups, we'll find a comma separating
    //  the password from the groups
    // if not, we only have a password
    int commaIndex = userProperty.indexOf(",");
    return (commaIndex >= 0) ? userProperty.substring(0, commaIndex) : userProperty;
  }

  /**
   * Extracts the list of groups that a user is a member of from
   * the user's property value.
   *
   * @param userProperty A String containing the user's property value
   * (which has the form "password,parentGroup,...")
   *
   * @return A String containing a comma separated list of the groups
   * the user is immediately a member of.
   */
  private String getGroupListFromUserProperty(String userProperty)
  {
    // if there are groups, we'll find a comma separating
    // the password from the groups
    int commaIndex = userProperty.indexOf(",");
    return (commaIndex >= 0) ? userProperty.substring(commaIndex+1) : null;
  }

  /**
   * Recursively expands a list of groups that is a user
   * or group is a member of.
   *
   * @param v A Vector contaning the list of groups.
   * This method adds groups to this list.
   *
   * @param groupList A String containing a comma separated list of groups.
   *
   */
  private void expandGroupList(Vector v, String groupList)
  {
    if (groupList == null) return;

    // use a string tokenizer to extract the individual group
    // names from the comma separated list.
    StringTokenizer st = new StringTokenizer(groupList, ",");
    while (st.hasMoreTokens()) {

      // get the current group name
      String group = st.nextToken().trim();

      // add it to the list
      v.add(group);

      // get the name of the property for this group.
      String groupKey = getGroupKey(group);

      // get the list of groups that this group is a member of.
      // A group's property value is a comma separated list of
      // groups that it is a member of.
      String nextGroupList = data.getProperty(groupKey);

      // recurse to add the group's parent groups to the list.
      expandGroupList(v, nextGroupList);
    }
  }

  /**
   * Checks that a value (username, groupname, password) is valid.
   *
   * The simple sample authenticator places some restrictions on user names,
   * group names and passwords.  This method enforces those restrictions.
   *
   * @param val A String containing the value to validate.
   *
   * @throws IllegalArgumentException if the name is not valid.
   */
  private void checkVal(String val)
  {
    if (val == null) {
      throw new IllegalArgumentException("value must not be null");
    }
    if (val.indexOf(",") >= 0) {
      throw new IllegalArgumentException("value must not contain \",\":\"" + val + "\"");
    }
    if (val.length() != val.trim().length()) {
      throw new IllegalArgumentException("value must not begin or end with whitespace:\"" + val + "\"");
    }
    if (val.length() == 0) {
      throw new IllegalArgumentException("value must not be empty");
    }
  }

  /**
   * Creates a user.
   *
   * Used to seed the simple sample authenticator's properties file.
   *
   * @param user A String containing the name of the user to create.
   *
   * @param password A String containing the new user's password.
   *
   * @param parentGroups An array of Strings containing the
   * names of the groups that this user is immediately a member of.
   */
  private void createUser(String user, String password, String[] parentGroups)
  {
    checkVal(password);

    // The property value for a user has the form "password,parentGroup,..."

    // Start off by adding the password.
    String userProperty = password;

    // Then add the parent groups (comma separated)
    for (int i = 0; parentGroups != null &&  i < parentGroups.length; i++) {
      String parentGroup = parentGroups[i];
      checkVal(parentGroup);
      userProperty = userProperty + "," + parentGroup;
    }

    // Store the new user in the in-memory properties list.
    data.setProperty(getUserKey(user), userProperty);

    // And write it out to the properties file.
    updatePersistentState();
  }

  /**
   * Creates a group.
   *
   * Used to seed the simple sample authenticator's properties file.
   *
   * @param group A String containing the name of the group to create.
   *
   * @param parentGroup An array of Strings containing the names of
   * the groups that this group is immediately a member of
   */
  private void createGroup(String group, String[] parentGroups)
  {
    // THe property value for a group has the form "parentGroup,..."

    // Start off with an empty property value.
    String groupProperty = "";

    // Then add the parent groups (comma separated)
    for (int i = 0; parentGroups != null && i < parentGroups.length; i++) {
      if (i > 0) {
        groupProperty = groupProperty + ",";
      }
      String parentGroup = parentGroups[i];
      checkVal(parentGroup);
      groupProperty = groupProperty + parentGroup;
    }

    // Store the new group in the in-memory properties list.
    data.setProperty(getGroupKey(group), groupProperty);

    // And write it out to the properties file
    updatePersistentState();
  }

  /**
   * Write the in-memory properties list containing user and group
   * definitions to the properties file.
   */
  private void updatePersistentState()
  {
    try {
      FileOutputStream os = new FileOutputStream(database);
      try {
        data.store(
          os,
          database.getName() + " PersistentState, format: " +
          "user.username=password,parentgroupname... " +
          "group.groupname=parentgroupname,..."
        );
      } finally {
        os.close();
      }
    } catch (IOException e) {
      throw new RuntimeException(e.toString());
    }
  }

  /**
   * Create or re-open a simple sample authenticator's database.
   *
   * @param mbean A SimpleSampleAuthenticatorMBean containing the
   * simple sample authenticator's configuration data.
   */
  /*package*/ SimpleSampleAuthenticatorDatabase(SimpleSampleAuthenticatorMBean mbean)
  {
    // Get the name of the realm from the simple sample authenticator's mbean.
    String realm = mbean.getRealm().getName();

    // Compute the name of the properties file that holds the user
    // and group definitions the simple sample authenticator in this realm.
    // The file name is relative to where the domain is booted.
    database = new File("SimpleSampleAuthenticator" + realm + ".properties");

    if (!database.exists()) {

      // This is the first time we've used the simple sample authenticator
      // for this realm.

      // create a properties file and seed it with the default
      // user and group definitions that all authenticators providers
      // should have.  Also seed it with the user and groups needed
      // for the perimeter authentication (identity assertion) simple sample.

      // seed with default users and groups
      createGroup("Administrators", null);
      createGroup("Deployers",      null);
      createGroup("Operators",      null);
      createGroup("Monitors",       null);
      createGroup("AppTesters",     null);
      createUser("sampleuser", "samplepassword", new String[] { "Administrators" });

      // and create users for testing the sample identity asserter
      createGroup("SamplePerimeterAtnUsers", null);
      createUser("SamplePerimeterAtnUser1", "nopassword", new String[] { "SamplePerimeterAtnUsers" });
      createUser("SamplePerimeterAtnUser2", "nopassword", null                                      );

    } else {

      // The simple sample authenticator has already been used for this realm.
      // Open its properties file that contains the user and group
      // definitions and load it into memory.

      try {
        FileInputStream is = new FileInputStream(database);
        try {
          data.load(is);
        } finally {
          is.close();
        }
      } catch (IOException e) {
        throw new RuntimeException(e.toString());
      }
    }
  }
}
