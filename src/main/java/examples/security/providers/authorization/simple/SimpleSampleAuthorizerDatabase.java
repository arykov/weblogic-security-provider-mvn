package examples.security.providers.authorization.simple;

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
import weblogic.security.service.AdminResource;
import weblogic.security.service.ControlResource;
import weblogic.security.service.EISResource;
import weblogic.security.service.EJBResource;
import weblogic.security.service.JDBCResource;
import weblogic.security.service.JMSResource;
import weblogic.security.service.JNDIResource;
import weblogic.security.service.MBeanResource;
import weblogic.security.service.ServerResource;
import weblogic.security.service.URLResource;
import weblogic.security.service.WebServiceResource;
import weblogic.security.service.WorkContextResource;
import weblogic.security.spi.Resource;
import weblogic.security.spi.ApplicationInfo.ComponentType;

/**
 * The simple sample authorizer's persistent state (ie. database).
 *
 * The simple sample authorizer needs to keep a persistent
 * list of security policies - that is, what users/groups/roles
 * can access what resources.
 *
 * This class holds this persistent state in a java properties
 * file.  The format of the file is:
 *   resource.toString()=user,group,role...
 * In other words, for each resource, list the users, groups
 * and roles that can access it.
 *
 * The name of the java properties file is
 * SimpleSampleAuthorizerRealmName.properties where RealmName
 * is the name of the realm that containing the simple sample
 * authorizer.  Therefore, you should only configure one
 * simple sample authorizer in a realm (otherwise, the other one
 * will vie for the same properties file).
 *
 * If the properties file doesn't exist, then this class will
 * create one and seed it with the default policies that all
 * authorizers should create.
 *
 * This class has methods for reading policies as well as
 * editing policies (so that policies from webapp & EJB
 * deployment can be stored here).
 *
 * The simple sample authorizer's runtime implementation
 * delegates much of its work to this class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
/*package*/ final class SimpleSampleAuthorizerDatabase
{
  private File       database; // the java properties file that the policies are stored in
  private Properties policies = new Properties(); // an in-memory version of these policies
  private boolean    dirty = false; // in-memory version updated

  /**
   * Create or over-writes a security policy for a resource.
   *
   * @param resource The Resource the policy applies to.
   *
   * @param principalAndRoleNamesAllowed An array of String
   * containing the names of the users, groups and/or roles
   * that can access this resource.
   *
   */
  /*package*/ synchronized void setPolicy(Resource resource, String[] principalAndRoleNamesAllowed)
  {
    // convert the list of who has accesses into a comma separated list
    String names = "";
    for (int i = 0; i < principalAndRoleNamesAllowed.length; i++) {
      if (i > 0) {
        names = names + ",";
      }
      names = names + principalAndRoleNamesAllowed[i].trim();
    }

    // set the policy definition in-memory
    policies.setProperty(getResourceKey(resource), names);

    // flag new properties file should be created
    dirty = true;
  }

  /**
   * Saves all previous set policy.
   *
   * Optimization to write database after all policy has been defined.
   */
  /*package*/ synchronized void savePolicies()
  {
    // check for pending saves
    if (!dirty) return;

    // write out a new properties file
    updatePersistentState();
  }

  /**
   * Creates policies for the newly specified application.
   *
   * Search the resource keys in the database for existing applications
   * and create new entries that match the source application information.
   *
   * @param source the current application identifier being cloned
   * @param destination the newly created application identifier
   */
  /*package*/ synchronized void clonePoliciesForApplication(String source,
                                                            String destination)
  {
    // List of new policies
    Map updates = new HashMap();

    // Loop over each policy definition and pick out the ones
    // that match the component information.
    for (Enumeration e = policies.propertyNames(); e.hasMoreElements();) {

      // get the property name (resource)
      String resourceKey = (String)e.nextElement();

      // see if it matches the resource we're looking for
      String newResourceKey = cloneApplication(resourceKey,source,destination);
      if (newResourceKey != null) {

        // it does so add to the matched list
        String names = policies.getProperty(resourceKey);
        updates.put(newResourceKey, names);
      }
    }

    // Add all new enties
    if (!updates.isEmpty()) {
      policies.putAll(updates);
      updatePersistentState();
    }
  }

  /**
   * Removes all policy for the specified application.
   *
   * Search the resource keys in the database and remove
   * entries that match the specified application information.
   *
   * @param application the application identifier
   */
  /*package*/ synchronized void removePoliciesForApplication(String application)
  {
    // List of matching policies
    Set matched = new HashSet();

    // Loop over each policy definition and pick out the ones
    // that match the component information.
    for (Enumeration e = policies.propertyNames(); e.hasMoreElements();) {

      // get the property name (resource)
      String resourceKey = (String)e.nextElement();

      // see if it matches the resource we're looking for
      if (applicationMatches(resourceKey,application)) {

        // it does so add to the matched list
        matched.add(resourceKey);
      }
    }

    // Remove all enties matched
    if (!matched.isEmpty()) {
      for (Iterator i = matched.iterator(); i.hasNext();) {
        policies.remove((String)i.next());
      }
      updatePersistentState();
    }
  }

  /**
   * Removes all policy for the specified component.
   *
   * Search the resource keys in the database and remove
   * entries that match the specified component information.
   *
   * @param application the application identifier
   * @param component   the component name
   * @param compType    the component type
   */
  /*package*/ synchronized void removePoliciesForComponent(String application,
                                                           String component,
                                                           ComponentType compType)
  {
    // List of matching policies
    Set matched = new HashSet();

    // Loop over each policy definition and pick out the ones
    // that match the component information.
    for (Enumeration e = policies.propertyNames(); e.hasMoreElements();) {

      // get the property name (resource)
      String resourceKey = (String)e.nextElement();

      // see if it matches the resource we're looking for
      if (componentMatches(resourceKey,application,component,compType)) {

        // it does so add to the matched list
        matched.add(resourceKey);
      }
    }

    // Remove all enties matched
    if (!matched.isEmpty()) {
      for (Iterator i = matched.iterator(); i.hasNext();) {
        policies.remove((String)i.next());
      }
      updatePersistentState();
    }
  }

  /**
   * Determines if there is a policy specified for a resource.
   *
   * @param resource A Resource.
   *
   * @return A boolean.  true if there is a policy defined for the
   * resource, false otherwise.
   *
   */
  /*package*/ synchronized boolean policyExists(Resource resource)
  {
    return policies.containsKey(getResourceKey(resource));
  }

  /**
   * Gets the security policy for a resource.
   *
   * @param resource A Resource.
   *
   * @return An Enumeration whose elements are Strings that contain
   * the names of the users, groups and roles that can access this
   * resource.  Returns an empty list if there is no policy specified
   * for this resource.
   *
   */
  /*package*/ synchronized Enumeration getPolicy(Resource resource)
  {
    String names = policies.getProperty(getResourceKey(resource));
    Vector v = new Vector();
    StringTokenizer st = new StringTokenizer(names, ",");
    while (st.hasMoreTokens()) {
      String principalOrRoleName = st.nextToken().trim();
      v.add(principalOrRoleName);
    }
    return v.elements();    
  }

  /**
   * Converts a Resource object to its property name.
   *
   * While the runtime uses Resource objects to identity
   * resources (thus security policies), the properties list
   * uses name/value pairs.  This helper method converts a
   * Resource object to its property name.  It just uses the
   * "toString" form of the resource.
   *
   * @param resource A Resource.
   *
   * @return A String containing the property name for
   * the Resource's policy.
   */
  private String getResourceKey(Resource resource)
  {
    return resource.toString();
  }

  /**
   * Converts a map of Resource key/value pairs to its
   * property name. When no value is returned the information
   * supplied was not valid for conversion.
   *
   * This helper method converts the Map by delegating to
   * the ResourceId class.
   *
   * @param map A Map of resource key/value pairs.
   *
   * @return A String containing the property name for
   * the Resource's policy or null when no conversion.
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
   * Determines if the resource key matches the application information.
   *
   * @param resourceKey a database resource key
   * @param application an application identifier
   *
   * @return A boolean. true if the match is successful, false otherwise.
   */
  private boolean applicationMatches(String resourceKey, String application)
  {
    // first, convert the resource key to a Map
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
    // first, convert the resource key to a Map
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
    // first, convert the resource key to a Map
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
   * Write the in-memory properties list containing security
   * policies to the properties file.
   */
  private void updatePersistentState()
  {
    try {
      FileOutputStream os = new FileOutputStream(database);
      try {
        policies.store(os, database.getName() + " PersistentState, format: resource.toString()=user,group,role...");
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
   * Constructor for the SimpleSampleAuthorizerDatabase.
   * Create or re-open a simple sample authorizer's database.
   *
   * @param mbean A SimpleSampleAuthorizationMBean containing the
   * simple sample authorizer's configuration data.
   */
  /*package*/ SimpleSampleAuthorizerDatabase(SimpleSampleAuthorizerMBean mbean)
  {
    // Get the name of the realm from the simple sample authorizer's mbean.
    String realm = mbean.getRealm().getName();

    // Compute the name of the properties file that holds policies
    // for the simple sample authorizer in this realm.  The file name is
    // relative to where the domain is booted.
    database = new File("SimpleSampleAuthorizer" + realm + ".properties");

    if (!database.exists()) {
      String[] jndiPath;

      // This is the first time we've used the simple sample authorizer for
      // this realm.

      // create a properties file and seed it with the default policies
      // that all authorization providers should have.

      setPolicy(
        new MBeanResource(null, null, null, null, null, null),
        new String[] { WLSPrincipals.getEveryoneGroupname() } );

      setPolicy(
        new AdminResource(null, null, null),
        new String[] { "Admin" } );

      setPolicy(
        new AdminResource("Configuration", null, null),
        new String[] { "Admin", "Deployer", "Operator", "Monitor" } );

      setPolicy(
        new AdminResource("FileDownload", null, null),
        new String [] { "Admin", "Operator" } );

      setPolicy(
        new AdminResource("FileUpload", null, null),
        new String [] { "Admin", "Deployer" } );

      setPolicy(
        new AdminResource("ViewLog", null, null),
        new String[] { "Admin", "Deployer", "Operator", "Monitor" } );

      setPolicy(
        new ServerResource(null, null, null),
        new String [] { "Admin", "Operator" } );

      setPolicy(
        new JNDIResource(null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      jndiPath = new String[] { "weblogic" };
      setPolicy(
        new JNDIResource(null, jndiPath, "modify"),
        new String [] { "Admin", "Deployer", "Operator" } );

      jndiPath = new String[] { "weblogic" };
      setPolicy(
        new JNDIResource(null, jndiPath, "list"),
        new String [] { "Admin", "Deployer", "Monitor" } );

      jndiPath = new String[] { "javax" };
      setPolicy(
        new JNDIResource(null, jndiPath, "modify"),
        new String [] { "Admin", "Deployer", "Operator" } );

      jndiPath = new String[] { "javax" };
      setPolicy(
        new JNDIResource(null, jndiPath, "list"),
        new String [] { "Admin", "Deployer", "Monitor" } );

      jndiPath = new String[] { "weblogic", "management", "mbeanservers" };
      setPolicy(
        new JNDIResource(null, jndiPath, "lookup"),
        new String [] { WLSPrincipals.getUsersGroupname() } );

      jndiPath = new String[] { "java", "comp", "jmx" };
      setPolicy(
        new JNDIResource(null, jndiPath, "lookup"),
        new String [] { WLSPrincipals.getUsersGroupname() } );

      setPolicy(
        new JMSResource(null, null, null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      setPolicy(
        new EISResource(null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

       setPolicy(
        new WebServiceResource(null, null, null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      setPolicy(
        new JDBCResource(null, null, null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      setPolicy(
        new JDBCResource(null, null, null, null, "shrink"),
        new String [] { "Admin", "Deployer" } );

      setPolicy(
        new JDBCResource(null, null, null, null, "reset"),
        new String [] { "Admin", "Deployer" } );

      setPolicy(
        new JDBCResource(null, null, null, null, "admin"),
        new String [] { "Admin", "Deployer" } );

      setPolicy(
        new EJBResource(null, null, null, null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      setPolicy(
        new URLResource(null, null, null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      setPolicy(
        new WorkContextResource(null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      setPolicy(
        new ControlResource(null, null, null, null),
        new String [] { WLSPrincipals.getEveryoneGroupname() } );

      savePolicies();

    } else {

      // The simple sample authorizer has already been used for this realm.
      // Open its properties file that contains policies and load it into memory.

      try {
        FileInputStream is = new FileInputStream(database);
        try {
          policies.load(is);
        } finally {
          is.close();
        }
      } catch (IOException e) {
        throw new RuntimeException(e.toString());
      }
    }
  }
}
