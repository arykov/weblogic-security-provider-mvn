package examples.security.providers.roles.simple;

import java.security.Principal;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.security.auth.Subject;
import weblogic.management.security.ProviderMBean;
import weblogic.security.SubjectUtils;
import weblogic.security.WLSPrincipals;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.ApplicationInfo;
import weblogic.security.spi.ApplicationInfo.ComponentType;
import weblogic.security.spi.DeployableRoleProviderV2;
import weblogic.security.spi.DeployRoleHandle;
import weblogic.security.spi.Resource;
import weblogic.security.spi.RoleMapper;
import weblogic.security.spi.SecurityServices;
import weblogic.security.spi.VersionableApplicationProvider;

/**
 * The simple sample role mapper's runtime implementation.
 *
 * It is used to determine what roles the current
 * subject are in for the current resource.
 *
 * Since it is an deployable role mapper, it must implement
 * the weblogic.security.spi.DeployableRoleProvider
 * and the weblogic.security.spi.RoleMapper interfaces.
 *
 * Since it also supports application versioning, it must implement
 * the weblogic.security.spi.VersionableApplicationProvider. The
 * application versioning interface is called when different versions
 * of a deployed application are created and deleted.
 *
 * It can either implement two classes, and use the
 * provider implementation as the factory as the
 * factory for the role mapper, or it can implement
 * both interfaces in one class.  The simple sample role mapper
 * implments both interfaces in one class.
 *
 * The simple sample role mapper also implements the
 * weblogic.security.service.SecurityRole interface
 * (see the SimpleSampleSecurityRoleImpl class).  The simple
 * sample role mapper returns instances of this class when it
 * maps a resource and subject to roles.
 *
 * It stores role definitions (which users and groups
 * are in a role for a resource) in a properties
 * file.  The SimpleSampleRoleMapperDatabase class handles
 * the properties file.  This class just delegates
 * to the database class.
 *
 * Note: The simple sample role mapper's mbean's ProviderClassName
 * attribute must be set the the name of this class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
public final class SimpleSampleRoleMapperProviderImpl
  implements DeployableRoleProviderV2, RoleMapper, VersionableApplicationProvider
{
  private String                         description; // a description of this provider
  private SimpleSampleRoleMapperDatabase database;    // manages the role definitions for this provider

  private static final Map NO_ROLES = Collections.unmodifiableMap(new HashMap(1)); // used when no roles are found

  /**
   * Initialize the simple sample role mapper.
   *
   * It either creates or re-opens the file containing the
   * simple sample role mapper's role definitions.
   *
   * @param mbean A ProviderMBean that holds the simple sample role mapper's
   * configuration data.  This mbean must be an instance of the simple sample
   * role mapper's mbean.
   *
   * @param services The SecurityServices gives access to the auditor
   * so that the provider can to post audit events.
   * The simple sample role mapper doesn't use this parameter.
   *
   * @see SecurityProvider
   */
  public void initialize(ProviderMBean mbean, SecurityServices services)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.initialize");

    // Cast the mbean from a generic ProviderMBean to a SimpleSampleRoleMapperMBean.
    SimpleSampleRoleMapperMBean myMBean = (SimpleSampleRoleMapperMBean)mbean;

    // Set the description to the simple sample role mapper's mbean's description and version 
    description = myMBean.getDescription() + "\n" + myMBean.getVersion();

    // Instantiate the helper that manages this provider's role definitions
    database = new SimpleSampleRoleMapperDatabase(myMBean);
  }

  /**
   * Get the simple sample role mapper's description.
   *
   * @return A String containing a brief description of the simple sample role mapper.
   *
   * @see SecurityProvider
   */
  public String getDescription()
  {
    return description;
  }

  /**
   * Shutdown the simple sample role mapper.
   *
   * A no-op.
   *
   * @see SecurityProvider
   */
  public void shutdown()
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.shutdown");
  }

  /**
   * Gets the simple sample role mapper provider's role mapper object.
   *
   * @return The simple sample role mapper provider's RoleMapper object.
   *
   * @see RoleProvider
   */
  public RoleMapper getRoleMapper()
  {
    // Since this class implements both the DeployableRoleProvider
    // and RoleMapper interfaces, this object is the
    // role mapper object so just return "this".
    return this;
  }

  /**
   * Determines what roles the current subject is in
   * for this resource.
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @param resource The Resource the Subject is trying to access.
   *
   * @param handler A ContextHandler contains additional information that
   * may be considered in computing the roles.  This parameter is not used
   * by the simple sample role mapper.
   *
   * @return a Map containing SecurityRoles identifying the computed roles.
   * The SecurityRoles are instances of the simple sample identity asserter's
   * SecurityRole implementation (SimpleSampleSecurityRoleImpl).
   *
   * @see RoleMapper
   */
  public Map getRoles(Subject subject, Resource resource, ContextHandler handler)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.getRoles");
    System.out.println("\tsubject\t= " + subject);
    System.out.println("\tresource\t= " + resource);

    // Make a list for the roles
    Map roles = new HashMap();

    // Make a list for the roles that have already been found and evaluated
    Set rolesEvaluated = new HashSet();

    // since resources scope roles, and resources are hierarchical,
    // loop over the resource and all its parents, adding in any roles
    // that match the current subject.
    for (Resource res = resource; res != null; res = res.getParentResource()) {
      getRoles(res, subject, roles, rolesEvaluated);
    }

    // try global resources too
    getRoles(null, subject, roles, rolesEvaluated);

    // special handling for no matching roles
    if (roles.isEmpty()) {
      return NO_ROLES;
    }

    // return the roles we found.
    System.out.println("\troles\t= " + roles);
    return roles;
  }

  /**
   * Handles the beginning of an application component deployment. Called
   * on all servers within the domain where an application is targeted.
   *
   * A webapp or EJB's WebLogic deployment descriptor file may contain
   * a list of roles with principal names that are mapped to the role.
   * When the webapp or EJB is deployed, this information is sent to
   * the deployable role providers.
   *
   * This method will remove any existing security roles for the component
   * such that only the most up to date set of roles are maintained.
   * 
   * @param application information about the application being deployed
   *
   * @return a handle for the application that is used when deploying roles
   *
   * @see DeployableRoleProviderV2
   */
  public DeployRoleHandle startDeployRoles(ApplicationInfo application)
  {
    String appId = application.getApplicationIdentifier();
    String compName = application.getComponentName();
    ComponentType compType = application.getComponentType();
    DeployRoleHandle handle = new SampleDeployRoleHandle(appId,compName,compType);

    // ensure that previous roles have been removed so that
    // the most up to date deployment roles are in effect
    database.removeRolesForComponent(appId, compName, compType);

    // A null handle may be returned if needed
    return handle;
  }

  /**
   * Create a role definition specified in a deployed webapp or EJB.
   *
   * A webapp or EJB's WebLogic deployment descriptor file may contain
   * a list of roles with principal names that are mapped to the role.
   * When the webapp or EJB is deployed, this information is sent to
   * the deployable role providers.
   *
   * This method will replace the role definition on the resource
   * if there is already one specified.
   * 
   * @param handle the same handle created from startDeployRoles()
   *
   * @param resource A Resource that identifies the webapp or EJB.
   *
   * @param roleName A String containing the name of the role
   * (scoped by this resource).
   *
   * @param principalNames An array of String containing the users and
   * groups that are in this role on this resource (that is, the role
   * definition).
   *
   * @see DeployableRoleProvider
   */
  public void deployRole(DeployRoleHandle handle, Resource resource,
                         String roleName, String[] principalNames)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.deployRole");
    System.out.println("\thandle\t\t= " + ((SampleDeployRoleHandle)handle).toString());
    System.out.println("\tresource\t\t= " + resource);
    System.out.println("\troleName\t\t= " + roleName);
    for (int i = 0; principalNames != null && i < principalNames.length; i++) {
      System.out.println("\tprincipalNames[" + i + "]\t= " + principalNames[i]);
    }
    database.setRole(resource, roleName, principalNames);
  }

  /**
   * Stores the security roles specified in a deployed webapp or EJB
   * at the end of a deployment. Called on all servers within the domain
   * where an application is targeted.
   *
   * This method saves security roles for the deployed component
   * in the simple sample role mapper's properties file.
   * 
   * @param handle the same handle created from startDeployRoles()
   *
   * @see DeployableRoleProviderV2
   */
  public void endDeployRoles(DeployRoleHandle handle)
  {
    database.saveRoles();
  }

  /**
   * Removes the role definitions for an undeployed webapp or EJB
   * from the simple sample role mapper's properties file.
   *
   * This method removes security roles for the undeployed component
   * by scanning for the roles using the component name that is stored
   * in the SampleDeployRoleHandle.
   * 
   * @param handle the same handle created from startDeployRoles()
   *
   * @see DeployableRoleProviderV2
   */
  public void undeployAllRoles(DeployRoleHandle handle)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.undeployAllRoles");
    SampleDeployRoleHandle myHandle = (SampleDeployRoleHandle)handle;
    System.out.println("\thandle\t= " + myHandle.toString());

    // remove roles
    database.removeRolesForComponent(myHandle.getApplication(),
                                     myHandle.getComponent(),
                                     myHandle.getComponentType());
  }

  /**
   * Removes the security roles for resources when an application is
   * deleted. Only called on the admin server which is controlling the
   * deletion process.
   *
   * This method will search through the security roles for the
   * deleted application and remove all the relevant entries.
   *
   * @param application information about the application being deleted
   *
   * @see DeployableRoleProviderV2
   */
  public void deleteApplicationRoles(ApplicationInfo application)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.deleteApplicationRoles");
    String appId = application.getApplicationIdentifier();
    System.out.println("\tapplication identifier\t= " + appId);

    // clear out roles for the application
    database.removeRolesForApplication(appId);
  }

  /**
   * Adds the roles of a resource that the current subject matches to a list.
   *
   * @param resource A Resource.
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @param roles A Map containing the matching SecurityRoles.  This
   * method adds the roles for this resource (but not the resource's
   * parent resources) to this map.
   * The SecurityRoles are instances of the simple sample identity asserter's
   * SecurityRole implementation (SampleSecurityRoleImpl).
   *
   * @param rolesEvaluated A Set containing the names of roles that where
   * found in the database and have been evaluated. By maintaining a set of
   * evaluated roles only the most specifically scoped role definition for
   * the resource is matched. More general role definitions (such as a
   * global role) will therefore not be used when matching roles.
   */
  private void getRoles(Resource resource, Subject subject,
                        Map roles, Set rolesEvaluated)
  {
    // loop over all the roles in our "database" for this resource
    for (Enumeration e = database.getRoles(resource); e.hasMoreElements();) {
      String role = (String)e.nextElement();

      // Only check for roles not already evaluated
      if (rolesEvaluated.contains(role)) {
        continue;
      }
      // Add the role to the evaluated list
      rolesEvaluated.add(role);

      // If any of the principals is on that role, add the role to the list.
      if (roleMatches(resource, role, subject)) {

        // Add a simple sample role mapper role instance to the list of roles.
        roles.put(role, new SimpleSampleSecurityRoleImpl(role));
      }
    }
  }

  /**
   * Determines if any of the principals in the current subject
   * matches a role definition.
   *
   * @param resource A resource.
   *
   * @param role A String containing the name of a role scoped by this resource.
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @return A boolean.  true if any of the principals matches who is in the role,
   * false otherwise.
   */
  private boolean roleMatches(Resource resource, String role, Subject subject)
  {
    // loop over the the principals that are in this role.
    for (Enumeration e = database.getPrincipalsForRole(resource, role); e.hasMoreElements();) {

      // get the next principal in this role
      String principalWant = (String)e.nextElement();

      // see if any of the current principals match this principal
      if (subjectMatches(principalWant, subject)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Determines if the Subject matches a user/group name.
   *
   * @param principalWant A String containing the name of a principal
   * in this role (that is, the role definition).
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @return A boolean.  true if the current subject matches the name of
   * the principal in the role, false otherwise.
   */
  private boolean subjectMatches(String principalWant, Subject subject)
  {
    // first, see if it's a group name match
    if (SubjectUtils.isUserInGroup(subject, principalWant)) {
      return true;
    }
    // second, see if it's a user name match
    if (principalWant.equals(SubjectUtils.getUsername(subject))) {
      return true;
    }
    // didn't match
    return false;
  }

  /**
   * Called when a new application version is created. Only called on
   * the admin server which is controlling the creation process.
   *
   * This method will search through the security roles for the
   * source application and clone all the entries for the new
   * application version. This will ensure that the new version
   * has any customized roles from the source version.
   *
   * The application identifier contains the application name
   * concatenated with the application version so that the
   * application identifier can be used as a unique key.
   *
   * @param appId the application identifier of the newly
   *        created application version
   *
   * @param sourceAppId the application identifier of the
   *        version containing the source (or seed) data for the new
   *        application version. When no source identifier is supplied
   *        then this is the first version of the application.
   *
   * @see VersionableApplicationProvider
   */
  public void createApplicationVersion(String appId, String sourceAppId)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.createApplicationVersion");
    System.out.println("\tapplication identifier\t= " + appId);
    System.out.println("\tsource app identifier\t= " + ((sourceAppId != null) ? sourceAppId : "None"));

    // create new roles when existing application is specified
    if (sourceAppId != null) {
      database.cloneRolesForApplication(sourceAppId,appId);
    }
  }

  /**
   * Called when an application version is deleted. Only called on
   * the admin server which is controlling the deletion process.
   *
   * This method will search through the security roles for the
   * deleted application version and remove all the entries.
   *
   * @param appId the application identifier of the
   *        deleted application version
   *
   * @see VersionableApplicationProvider
   */
  public void deleteApplicationVersion(String appId)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.deleteApplicationVersion");
    System.out.println("\tapplication identifier\t= " + appId);

    // clear out roles for the application
    database.removeRolesForApplication(appId);
  }

  /**
   * Called when an non-versioned application is deleted. Only called on
   * the admin server which is controlling the deletion process.
   *
   * This method will search through the security roles for the
   * application and remove all the entries.
   *
   * @param appName the application name of the
   *        deleted application
   *
   * @see VersionableApplicationProvider
   */
  public void deleteApplication(String appName)
  {
    System.out.println("SimpleSampleRoleMapperProviderImpl.deleteApplication");
    System.out.println("\tapplication name\t= " + appName);

    // clear out roles for the application
    database.removeRolesForApplication(appName);
  }

  /**
   * Simple implementation of a role deployment handle.
   * @see DeployRoleHandle
   */
  class SampleDeployRoleHandle implements DeployRoleHandle
  {
     Date date;
     String application;
     String component;
     ComponentType componentType;

     SampleDeployRoleHandle(String app, String comp, ComponentType type)
     {
       this.application = app;
       this.component = comp;
       this.componentType = type;
       this.date = new Date();
     }

     public String getApplication() { return application; }
     public String getComponent() { return component; }
     public ComponentType getComponentType() { return componentType; }

     public String toString()
     {
       String name = component;
       if (componentType == ComponentType.APPLICATION)
         name = application;
       return componentType +" "+ name +" ["+ date.toString() +"]";
     }
  }
}
