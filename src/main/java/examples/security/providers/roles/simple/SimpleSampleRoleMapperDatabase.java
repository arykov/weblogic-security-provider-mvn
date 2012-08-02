package examples.security.providers.roles.simple;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import weblogic.security.ResourceId;
import weblogic.security.WLSPrincipals;
import weblogic.security.spi.Resource;
import weblogic.security.spi.ApplicationInfo.ComponentType;

/**
 * The simple sample role mapper's persistent state (ie. database).
 *
 * The simple sample role mapper needs to keep a persistent
 * list of role definitions - that is, what users/groups
 * are in a role for a resource.
 *
 * While role mappers can use more complex rules to grant
 * roles (for example, only between 8 am & 5 pm), the simple
 * sample role mapper grants roles based on user and group
 * names only.
 *
 * This class holds this persistent state in a java properties
 * file.  The format of the file is:
 *   role,[global|resource.toString()]=user,group...
 * In other words, for a role name on either a resource or
 * for a global role, list the users and groups that are
 * granted that role.
 *
 * The name of the java properties file is
 * SimpleSampleRoleMapperRealmName.properties where RealmName
 * is the name of the realm that containing the simple sample
 * role mapper.  Therefore, you should only configure one
 * simple sample role mapper in a realm (otherwise, the other one
 * will vie for the same properties file).
 *
 * If the properties file doesn't exist, then this class will
 * create one and seed it with the default role definitions that
 * all role mappers should create.
 *
 * This class has methods for reading roles as well as
 * editing roles (so that roles from webapp & EJB
 * deployment can be stored here).
 *
 * The simple sample role mapper's runtime implementation
 * delegates much of its work to this class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
/*package*/ final class SimpleSampleRoleMapperDatabase
{
  private static final String GLOBAL = "global";

  private File       database; // the java properties file that the roles are stored in
  private Properties roles = new Properties(); // an in-memory version of these roles
  private boolean    dirty = false; // in-memory version updated

  /**
   * Create or over-writes a role for a resource.
   *
   * @param resource The Resource the role is scoped by
   * (or null if it is a global role).
   *
   * @param role A String containing the role's name (scoped by the resource)
   *
   * @param principalNames An array of String containing the names of
   * the users and groups that are in that role for that resource.
   *
   */
  /*package*/ synchronized void setRole(Resource resource, String role, String[] principalNames)
  {
    // convert the list of who has is in the role into a comma separated list
    String names = "";
    for (int i = 0; i < principalNames.length; i++) {
      if (i > 0) {
        names = names + ",";
      }
      names = names + principalNames[i].trim();
    }

    // set the role definition in-memory
    roles.setProperty(getRoleKey(resource, role), names);

    // flag new properties file should be created
    dirty = true;
  }

  /**
   * Saves all previous set roles.
   *
   * Optimization to write database after all roles have been defined.
   */
  /*package*/ synchronized void saveRoles()
  {
    // check for pending saves
    if (!dirty) return;

    // write out a new properties file
    updatePersistentState();
  }

  /**
   * Creates roles for the newly specified application.
   *
   * Search the resource keys in the database for existing applications
   * and create new entries that match the source application information.
   *
   * @param source the current application identifier being cloned
   * @param destination the newly created application identifier
   */
  /*package*/ synchronized void cloneRolesForApplication(String source,
                                                         String destination)
  {
    // The role names in the properties list are of the form:
    //   role,[global|resource.toString()]

    // List of new roles
    Map updates = new HashMap();

    // Loop over each role definition and pick out the ones
    // that match the component information.
    for (Enumeration e = roles.propertyNames(); e.hasMoreElements();) {

      // get the property name (role,resource)
      String roleKey = (String)e.nextElement();

      // extract the resource name from the property name
      String resourceKey = roleKey.substring(roleKey.indexOf(",")+1);

      // see if it matches the resource we're looking for
      String newResourceKey = cloneApplication(resourceKey,source,destination);
      if (newResourceKey != null) {

        // it does so we add the database entry to the update list
        String names = roles.getProperty(roleKey);
        String role = roleKey.substring(0,roleKey.indexOf(","));
        updates.put(getRoleKey(newResourceKey,role), names);
      }
    }

    // Add all new enties
    if (!updates.isEmpty()) {
      roles.putAll(updates);
      updatePersistentState();
    }
  }

  /**
   * Removes all roles for the specified application.
   *
   * Search the resource keys in the database and remove
   * entries that match the specified application information.
   *
   * @param application the application identifier
   */
  /*package*/ synchronized void removeRolesForApplication(String application)
  {
    // The role names in the properties list are of the form:
    //   role,[global|resource.toString()]

    // List of matching roles
    Set matched = new HashSet();

    // Loop over each role definition and pick out the ones
    // that match the component information.
    for (Enumeration e = roles.propertyNames(); e.hasMoreElements();) {

      // get the property name (role,resource)
      String roleKey = (String)e.nextElement();

      // extract the resource name from the property name
      String resourceKey = roleKey.substring(roleKey.indexOf(",")+1);

      // see if it matches the resource we're looking for
      if (applicationMatches(resourceKey,application)) {

        // it does so add to the matched list
        matched.add(roleKey);
      }
    }

    // Remove all enties matched
    if (!matched.isEmpty()) {
      for (Iterator i = matched.iterator(); i.hasNext();) {
        roles.remove((String)i.next());
      }
      updatePersistentState();
    }
  }

  /**
   * Removes all roles for the specified component.
   *
   * Search the resource keys in the database and remove
   * entries that match the specified component information.
   *
   * @param application the application identifier
   * @param component   the component name
   * @param compType    the component type
   */
  /*package*/ synchronized void removeRolesForComponent(String application,
                                                        String component,
                                                        ComponentType compType)
  {
    // The role names in the properties list are of the form:
    //   role,[global|resource.toString()]

    // List of matching roles
    Set matched = new HashSet();

    // Loop over each role definition and pick out the ones
    // that match the component information.
    for (Enumeration e = roles.propertyNames(); e.hasMoreElements();) {

      // get the property name (role,resource)
      String roleKey = (String)e.nextElement();

      // extract the resource name from the property name
      String resourceKey = roleKey.substring(roleKey.indexOf(",")+1);

      // see if it matches the resource we're looking for
      if (componentMatches(resourceKey,application,component,compType)) {

        // it does so add to the matched list
        matched.add(roleKey);
      }
    }

    // Remove all enties matched
    if (!matched.isEmpty()) {
      for (Iterator i = matched.iterator(); i.hasNext();) {
        roles.remove((String)i.next());
      }
      updatePersistentState();
    }
  }

  /**
   * Determines if there is a role defined on a resource.
   *
   * @param resource The Resource the role is scoped by
   * (or null if it is a global role).
   *
   * @param role A String containing the role's name (scoped by the resource)
   *
   * @return A boolean.  true if there is a role by that name defined
   * on the resource, false otherwise.
   *
   */
  /*package*/ synchronized boolean roleExists(Resource resource, String role)
  {
    return roles.containsKey(getRoleKey(resource, role));
  }

  /**
   * Gets the list of users and groups that are in a role.
   *
   * @param resource The Resource the role is scoped by
   * (or null if it is a global role).
   *
   * @param role A String containing the role's name (scoped by the resource)
   *
   * @return An Enumeration whose elements are Strings that
   * contain the names of the users and groups in this role.
  */
  /*package*/ synchronized Enumeration getPrincipalsForRole(Resource resource, String role)
  {
    // Get the comma separated list of user and group names
    // for this role definition
    String names = roles.getProperty(getRoleKey(resource, role));

    // Make a list to hold the user and group names
    Vector principalNames = new Vector();

    // Use a string tokenizer to get the individual
    // user and group names.  put them in the list.
    StringTokenizer st = new StringTokenizer(names, ",");
    while (st.hasMoreTokens()) {
      String principalName = st.nextToken().trim();
      principalNames.add(principalName);
    }

    // return the list.
    return principalNames.elements();    
  }

  /**
   * Gets the list of roles defined on a resource.
   *
   * @param resource A Resource whose roles will
   * be listed (or null to return all global roles).
   *
   * @return An Enumeration whose elements are Strings that
   * contain the names of the roles defined on this resource.
   */
  /*package*/ synchronized Enumeration getRoles(Resource resource)
  {
    // The role names in the properties list are of the form:
    //   role,[global|resource.toString()]

    // Get from the resource to its part of the property name
    String resourceKeyWant = getResourceKey(resource);

    // Make a list to hold the role names
    Vector roleNames = new Vector();

    // Loop over each role definition and pick out the ones
    // that are scoped by this role.
    for (Enumeration e = roles.propertyNames(); e.hasMoreElements();) {

      // get the property name (role,resource)
      String roleKey = (String)e.nextElement();

      // extract the resource name from the property name
      String resourceKeyHave = roleKey.substring(roleKey.indexOf(",")+1);

      // see if it matches the resource we're looking for
      if (resourceKeyWant.equals(resourceKeyHave)) {

        // it does.  extract the role name from the property name
        // and add it to the list of roles for this resource.
        String role = roleKey.substring(0, roleKey.indexOf(","));
        roleNames.add(role);
      }
    }

    // return the list.
    return roleNames.elements();
  }

  /**
   * Converts a Resource object to its part of a role's property name.
   *
   * While the runtime uses Resource objects to identity
   * resources, the properties list uses name/value pairs
   * where the property name is "role.resource.toString()"
   * or "role.global".
   *
   * This helper method converts a Resource object its part
   * property name.  It just uses the "toString" form of
   * the resource or "global" if there is no resurce.
   *
   * @param resource A Resource.
   *
   * @return A String containing the Resource object's part
   * of the role's property name.
   */
  private String getResourceKey(Resource resource)
  {
    // If we have a resource, return its string form.
    if (resource != null) {
      String resourceId = resource.toString();
      if (resourceId.length() > 0) {
        return resourceId;
      }
    }
    // If not, just return "global" since this is for a global role.
    return GLOBAL;
  }

  /**
   * Converts a map of Resource key/value pairs to its part
   * of a role's property name. When no value is returned
   * the information supplied was not valid for conversion.
   *
   * This helper method converts the Map by delegating to
   * the ResourceId class.
   *
   * @param map A Map of resource key/value pairs.
   *
   * @return A String containing the Resource object's part
   * of the role's property name or null when no conversion.
   */
  private String getResourceKey(Map map)
  {
    try {
      return ResourceId.getResourceIdFromMap(map);
    } catch (IllegalArgumentException e) {
      // unable to create key
      return null;
    }
  }

  /**
   * Converts a resource key to a Map of Resource key/value
   * pairs. When no value is returned the key supplied was
   * not valid for conversion.
   *
   * This helper method converts the key by delegating to
   * the ResourceId class.
   *
   * @param key the database resource key.
   *
   * @return A Map of resource key/value pairs or null when no conversion.
   */
  private Map getResourceMap(String key)
  {
    try {
      return ResourceId.getMapFromResourceId(key);
    } catch (IllegalArgumentException e) {
      // unable to create map
      return null;
    }
  }

  /**
   * Converts a Resource object and a role name to the role's property name.
   *
   * While the runtime uses Resource objects to identity
   * resources, the properties list uses name/value pairs
   * where the property name is "role.resource.toString()" or
   * "role.global".
   *
   * @param resource A Resource.
   *
   * @param role A String containing the role's name (scoped by that
   * resource if the resource is not null, a global role otherwise).
   *
   * @return A String containing the role's property name.
   */
  private String getRoleKey(Resource resource, String role)
  {
    return getRoleKey(getResourceKey(resource),role);
  }

  /**
   * Converts a resource key and a role name to the role's property name.
   *
   * @param resourceKey A database resource key.
   * @param role A String containing the role's name.
   *
   * @return A String containing the role's property name.
   */
  private String getRoleKey(String resourceKey, String role)
  {
    return role + "," + resourceKey;
  }

  /**
   * Determines if the resource key matches the application information.
   *
   * @param resourceKey a database resource key
   * @param application an application identifier
   *
   * @return A boolean. true if the match is successful, false otherwise.
   */
  private boolean applicationMatches(String resourceKey, String application)
  {
    // first, see if it's a global role
    if (GLOBAL.equals(resourceKey)) {
      return false;
    }

    // convert the resource key to a Map
    Map resourceMap = getResourceMap(resourceKey);
    if (resourceMap == null) {
      return false;
    }

    // second, see if there is an application match
    if (application.equals(resourceMap.get("application"))) {
      return true;
    }

    // didn't match
    return false;
  }

  /**
   * Determines if the resource key matches the component information.
   *
   * @param resourceKey a database resource key
   * @param application an application identifier
   * @param component   a component name
   * @param compType    a component type
   *
   * @return A boolean. true if the match is successful, false otherwise.
   */
  private boolean componentMatches(String resourceKey, String application,
                                   String component, ComponentType compType)
  {
    // first, see if it's a global role
    if (GLOBAL.equals(resourceKey)) {
      return false;
    }

    // convert the resource key to a Map
    Map resourceMap = getResourceMap(resourceKey);
    if (resourceMap == null) {
      return false;
    }

    // second, see if there is an application match
    if (!application.equals(resourceMap.get("application"))) {
      return false;
    }

    // last, based on the component type, determine if the Map
    // contains the matching component information
    if ((compType == ComponentType.WEBAPP)
        && ("<url>".equals(resourceMap.get(ResourceId.RESOURCE_TYPE)))
        && (component.equals(resourceMap.get("contextPath")))) {
      return true;
    }
    if ((compType == ComponentType.EJB)
        && ("<ejb>".equals(resourceMap.get(ResourceId.RESOURCE_TYPE)))
        && (component.equals(resourceMap.get("module")))) {
      return true;
    }
    if ((compType == ComponentType.APPLICATION)
        && ("<app>".equals(resourceMap.get(ResourceId.RESOURCE_TYPE)))) {
      return true;
    }

    // didn't match
    return false;
  }

  /**
   * Determines if the resource key matches the application information
   * and converts the resource key to the new application information.
   *
   * @param resourceKey a database resource key
   * @param application an application identifier
   * @param newApplication the new application identifier
   *
   * @return A String which is the new application database resource key
   */
  private String cloneApplication(String resourceKey,
                                  String application,
                                  String newApplication)
  {
    // first, see if it's a global role
    if (GLOBAL.equals(resourceKey)) {
      return null;
    }

    // convert the resource key to a Map
    Map resourceMap = getResourceMap(resourceKey);
    if (resourceMap == null) {
      return null;
    }

    // second, see if there is an application match
    if (application.equals(resourceMap.get("application"))) {
      resourceMap.put("application",newApplication);
      return getResourceKey(resourceMap);
    }

    // didn't match
    return null;
  }

  /**
   * Write the in-memory properties list containing role
   * definitions to the properties file.
   */
  private void updatePersistentState()
  {
    try {
      FileOutputStream os = new FileOutputStream(database);
      try {
        roles.store(os, database.getName() + " PersistentState, format: role,[global|resource.toString()]=user,group...");
      } finally {
        os.close();
      }
    } catch (IOException e) {
      throw new RuntimeException(e.toString());
    }

    // flag new properties file was created
    dirty = false;
  }

  /**
   * Constructor for the SimpleSampleRoleMapperDatabase.
   * Create or re-open a sample role mapper's database.
   *
   * @param mbean A SimpleSampleRoleMapperMBean containing the
   * the simple sample role mapper's configuration data.
   */
  /*package*/ SimpleSampleRoleMapperDatabase(SimpleSampleRoleMapperMBean mbean)
  {
    // Get the name of the realm from the simple sample role mapper's mbean.
    String realm = mbean.getRealm().getName();

    // Compute the name of the properties file that holds the role
    // definitions the simple sample role mapper in this realm.  The file
    // name is relative to where the domain is booted.
    database = new File("SimpleSampleRoleMapper" + realm + ".properties");

    if (!database.exists()) {


      // This is the first time we've used the simple sample role mapper
      // for this realm.

      // create a properties file and seed it with the default
      // role definitions that all role mappers providers should have.

      // seed with default global roles
      setRole( null, "Admin"     , new String[] { WLSPrincipals.getAdministratorsGroupname() } );
      setRole( null, "Deployer"  , new String[] { "Deployers"                                } );
      setRole( null, "Operator"  , new String[] { "Operators"                                } );
      setRole( null, "Monitor"   , new String[] { "Monitors"                                 } );
      setRole( null, "AppTester" , new String[] { "AppTesters"                               } );
      setRole( null, "Anonymous" , new String[] { WLSPrincipals.getEveryoneGroupname()       } );

      saveRoles();

    } else {

      // The simple sample role mapper has already been used for this realm.
      // Open its properties file that contains the role definitions
      // and load it into memory.

      try {
        FileInputStream is = new FileInputStream(database);
        try {
          roles.load(is);
        } finally {
          is.close();
        }
      } catch (IOException e) {
        throw new RuntimeException(e.toString());
      }
    }
  }
}
