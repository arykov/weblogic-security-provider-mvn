package examples.security.providers.authorization.simple;

import java.security.Principal;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import weblogic.management.security.ProviderMBean;
import weblogic.security.SubjectUtils;
import weblogic.security.WLSPrincipals;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AccessDecision;
import weblogic.security.spi.ApplicationInfo;
import weblogic.security.spi.ApplicationInfo.ComponentType;
import weblogic.security.spi.DeployableAuthorizationProviderV2;
import weblogic.security.spi.DeployPolicyHandle;
import weblogic.security.spi.Direction;
import weblogic.security.spi.InvalidPrincipalException;
import weblogic.security.spi.Resource;
import weblogic.security.spi.Result;
import weblogic.security.spi.SecurityServices;
import weblogic.security.spi.VersionableApplicationProvider;

/**
 * The Simple Sample Authorizer's runtime implementation.
 *
 * It is used to determine if the current subject
 * and roles can access a resource.
 *
 * Since it is an deployable authorizer, it must implement
 * the weblogic.security.spi.DeployableAuthorizationProviderV2
 * and the weblogic.security.spi.AccessDecision interfaces.
 *
 * Since it also supports application versioning, it must implement
 * the weblogic.security.spi.VersionableApplicationProvider. The
 * application versioning interface is called when different versions
 * of a deployed application are created and deleted.
 *
 * It can either implement two classes, and use the
 * provider implementation as the factory as the
 * factory for the access decision, or it can implement
 * both interfaces in one class.  The simple sample authorizer
 * implments both interfaces in one class.
 *
 * It stores security policies (which users, groups
 * and/or roles can access a resource) in a properties
 * file.  The SimpleSampleAuthorizerDatabase class handles
 * the properties file.  This class just delegates
 * to the database class.
 *
 * Note: The simple sample authorizer's mbean's ProviderClassName
 * attribute must be set the the name of this class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
public final class SimpleSampleAuthorizationProviderImpl
  implements DeployableAuthorizationProviderV2, AccessDecision, VersionableApplicationProvider
{
  // Constants used for deploying excluded and unchecked policy
  private static String[] NO_ACCESS = new String[0];
  private static String[] ALL_ACCESS = new String[] {WLSPrincipals.getEveryoneGroupname()};

  private String                         description; // a description of this provider
  private SimpleSampleAuthorizerDatabase database;    // manages the policy definitions for this provider

  /**
   * Initialize the simple sample authorizer.
   *
   * It either creates or re-opens the file containing the
   * simple sample authorizer's policies.
   *
   * @param mbean A ProviderMBean that holds the simple sample authorizer's
   * configuration data.  This mbean must be an instance of the simple sample
   * authorizer's mbean.
   *
   * @param services The SecurityServices gives access to the auditor
   * so that the provider can to post audit events.
   * The simple sample authorizer doesn't use this parameter.
   *
   * @see SecurityProvider
   */
  public void initialize(ProviderMBean mbean, SecurityServices services)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.initialize");

    // Cast the mbean from a generic ProviderMBean to a SimpleSampleAuthorizerMBean.
    SimpleSampleAuthorizerMBean myMBean = (SimpleSampleAuthorizerMBean)mbean;

    // Set the description to the simple sample authorizer's mbean's description and version 
    description = myMBean.getDescription() + "\n" + myMBean.getVersion();

    // Instantiate the helper that manages this provider's policies
    database = new SimpleSampleAuthorizerDatabase(myMBean);
  }

  /**
   * Get the simple sample authorizer's description.
   *
   * @return A String containing a brief description of the simple sample authorizer.
   *
   * @see SecurityProvider
   */
  public String getDescription()
  {
    return description;
  }

  /**
   * Shutdown the simple sample authorizer.
   *
   * A no-op.
   *
   * @see SecurityProvider
   */
  public void shutdown()
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.shutdown");
  }

  /**
   * Gets the simple sample authorizer's access decision object.
   *
   * @return The simple sample authorization provider's AccessDecision object.
   *
   * @see AuthorizationProvider
   */
  public AccessDecision getAccessDecision()
  {
    // Since this class implements both the DeployableAuthorizationProvider
    // and AccessDecision interfaces, this object is the
    // access decision object so just return "this".
    return this;
  }

  /**
   * Determines if access is granted to a resource.
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @param roles A Map containing SecurityiRoles identifying
   * the subject's current roles for the resource.
   *
   * @param resource The Resource the Subject is trying to access.
   *
   * @param handler A ContextHandler contains additional information that
   * may be considered in the access decision.  This parameter is not used
   * by the simple sample authorizer.
   *
   * @param direction A Direction indicating whether the access decision
   * is being done PRIOR to accessing the resource, or POST access (in
   * which case what is being checked is the resource that represents
   * what is being returned to the caller), or ONCE in which case access
   * is being checked to the resource before it is accessed and
   * what is returned will not be checked.
   * This parameter is not used by the simple sample authorizer.
   *
   * @return The Result of the access decision.
   *
   * If there is a policy defined for this resource or one of
   * its parent resources, then returns PERMIT if that policy
   * grants access to one of the principals in the subject or
   * to one of the roles, DENY otherwise.
   *
   * If neither this resource nor any of its parent resources has
   * a policy specified, then returns ABSTAIN.
   *
   * @see AccessDecision
   */
  public Result
    isAccessAllowed(
      Subject        subject,
      Map            roles,
      Resource       resource,
      ContextHandler handler,
      Direction      direction
    )
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.isAccessAllowed");
    System.out.println("\tsubject\t= " + subject);
    System.out.println("\troles\t= " + roles);
    System.out.println("\tresource\t= " + resource);
    System.out.println("\tdirection\t= " + direction);

    // loop over this resource and its parents
    for (Resource res = resource; res != null; res = res.getParentResource()) {
      if (database.policyExists(res)) {
        // there is a policy defined for this resource.
        // return whether or not it grants access to any
        // of the principals or roles
        Result result = isAccessAllowed(res, subject, roles);
        System.out.println("\tallowed\t= " + result);
        return result;
      }
    }

    // there was no policy specified for this resource or any of
    // its parents so ABSTAIN
    Result result = Result.ABSTAIN;
    System.out.println("\tallowed\t= " + result);
    return result;
  }

  /**
   * Determines if the resource is protected without incurring the
   * cost of a full access check.
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @param resource The Resource the Subject trying is to access.
   *
   * @return A boolean.  true if this resource, or one of its parent resources,
   * has a security policy specified.
   *
   * @see AccessDecision
   */
  public boolean
    isProtectedResource(
      Subject subject,
      Resource resource
    ) throws InvalidPrincipalException
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.isProtectedResource");
    System.out.println("\tsubject\t= " + subject);
    System.out.println("\tresource\t= " + resource);

    // the resource is protected if we have a rule for it or for one of its parents
    for (Resource res = resource; res != null; res = res.getParentResource()) {
      if (database.policyExists(res)) {
        System.out.println("\tprotected\t= true");
        return true;
      }
    }
    System.out.println("\tprotected\t= false");
    return false;
  }

  /**
   * Handles the beginning of an application component deployment. Called
   * on all servers within the domain where an application is targeted.
   *
   * A webapp or EJB's deployment descriptor file may contain a list
   * of policies with role names that are allowed to access the webapp
   * or EJB.  When the webapp or EJB is deployed, this information is
   * sent to the deployable authorization providers.
   *
   * This method will remove any existing security policy for the component
   * such that only the most up to date set of policies are enforced.
   * 
   * @param application information about the application being deployed
   *
   * @return a handle for the application that is used when deploying policy
   *
   * @see DeployableAuthorizationProviderV2
   */
  public DeployPolicyHandle startDeployPolicies(ApplicationInfo application)
  {
    String appId = application.getApplicationIdentifier();
    String compName = application.getComponentName();
    ComponentType compType = application.getComponentType();
    DeployPolicyHandle handle = new SampleDeployPolicyHandle(appId,compName,compType);

    // ensure that previous policies have been removed so that
    // the most up to date deployment policies are in effect
    database.removePoliciesForComponent(appId, compName, compType);

    // A null handle may be returned if needed
    return handle;
  }

  /**
   * Create a security policy specified in a deployed webapp or EJB.
   *
   * A webapp or EJB's deployment descriptor file may contain a list
   * of policies with role names that are allowed to access the webapp
   * or EJB.  When the webapp or EJB has a policy statement, this
   * information is sent to this call so that the authorization provider
   * can perform the access checks for these webapps and EJBs.
   *
   * This method will replace the security policy for the resource
   * if there is already one specified.
   * 
   * @param handle the same handle created from startDeployPolicy()
   *
   * @param resource A Resource that identifies the webapp or EJB.
   *
   * @param roleNamesAllowed An array of String containing the names
   * of the roles that are allowed to access the webapp or EJB (that is,
   * the policy definition).
   *
   * @see DeployableAuthorizationProviderV2
   */
  public void deployPolicy(DeployPolicyHandle handle,
                           Resource resource, String[] roleNamesAllowed)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.deployPolicy");
    System.out.println("\thandle\t= " + ((SampleDeployPolicyHandle)handle).toString());
    System.out.println("\tresource\t= " + resource);
    for (int i = 0; roleNamesAllowed != null && i < roleNamesAllowed.length; i++) {
      System.out.println("\troleNamesAllowed[" + i + "]\t= " + roleNamesAllowed[i]);
    }
    database.setPolicy(resource, roleNamesAllowed);
  }

  /**
   * Create a security policy specified in a deployed webapp or EJB.
   *
   * A policy that always grants access is created for the resource by
   * specifying the group everyone which indicates all users have access.
   *
   * A webapp or EJB's deployment descriptor file may contain a list
   * of policies with role names that are allowed to access the webapp
   * or EJB.  When the webapp or EJB has a policy statement, this
   * information is sent to this call so that the authorization provider
   * can perform the access checks for these webapps and EJBs.
   *
   * This method will replace the security policy for the resource
   * if there is already one specified.
   * 
   * @param handle the same handle created from startDeployPolicy()
   *
   * @param resource A Resource that identifies the webapp or EJB.
   *
   * @see DeployableAuthorizationProviderV2
   */
  public void deployUncheckedPolicy(DeployPolicyHandle handle,
                                    Resource resource)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.deployUncheckedPolicy");
    System.out.println("\thandle\t= " + ((SampleDeployPolicyHandle)handle).toString());
    System.out.println("\tresource\t= " + resource);
    database.setPolicy(resource, ALL_ACCESS);
  }

  /**
   * Create a security policy specified in a deployed webapp or EJB.
   *
   * A policy that always denies access is created for the resource by
   * specifying no principal names which indicates access is disallowed.
   *
   * A webapp or EJB's deployment descriptor file may contain a list
   * of policies with role names that are allowed to access the webapp
   * or EJB.  When the webapp or EJB has a policy statement, this
   * information is sent to this call so that the authorization provider
   * can perform the access checks for these webapps and EJBs.
   *
   * This method will replace the security policy for the resource
   * if there is already one specified.
   * 
   * @param handle the same handle created from startDeployPolicy()
   *
   * @param resource A Resource that identifies the webapp or EJB.
   *
   * @see DeployableAuthorizationProviderV2
   */
  public void deployExcludedPolicy(DeployPolicyHandle handle,
                                   Resource resource)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.deployExcludedPolicy");
    System.out.println("\thandle\t= " + ((SampleDeployPolicyHandle)handle).toString());
    System.out.println("\tresource\t= " + resource);
    database.setPolicy(resource, NO_ACCESS);
  }

  /**
   * Stores the security policies specified in a deployed webapp or EJB
   * at the end of a deployment. Called on all servers within the domain
   * where an application is targeted.
   *
   * This method saves security policy for the deployed component
   * in the simple sample authorizer's properties file.
   * 
   * @param handle the same handle created from startDeployPolicy()
   *
   * @see DeployableAuthorizationProviderV2
   */
  public void endDeployPolicies(DeployPolicyHandle handle)
  {
    database.savePolicies();
  }

  /**
   * Removes the security policies for resources in an undeployed
   * webapp or EJB from the simple sample authorizer's properties file.
   *
   * This method removes security policy for the undeployed component
   * by scanning for policies using the component name that is stored
   * in the SampleDeployPolicyHandle.
   * 
   * @param handle the same handle created from startDeployPolicy()
   *
   * @see DeployableAuthorizationProviderV2
   */
  public void undeployAllPolicies(DeployPolicyHandle handle)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.undeployAllPolicies");
    SampleDeployPolicyHandle myHandle = (SampleDeployPolicyHandle)handle;
    System.out.println("\thandle\t= " + myHandle.toString());

    // remove policies
    database.removePoliciesForComponent(myHandle.getApplication(),
                                        myHandle.getComponent(),
                                        myHandle.getComponentType());
  }

  /**
   * Removes the security policies for resources when an application is
   * deleted. Only called on the admin server which is controlling the
   * deletion process.
   *
   * This method will search through the security policies for the
   * deleted application and remove all the relevant entries.
   *
   * @param application information about the application being deleted
   *
   * @see DeployableAuthorizationProviderV2
   */
  public void deleteApplicationPolicies(ApplicationInfo application)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.deleteApplicationPolicies");
    String appId = application.getApplicationIdentifier();
    System.out.println("\tapplication identifier\t= " + appId);

    // clear out policies for the application
    database.removePoliciesForApplication(appId);
  }

  /**
   * Determines if the roles or sobject trying to access a resource matches
   * the name of one of the principals and roles that
   * are allowed to access the resource.
   *
   * @param roles A Map containing SecurityRoles for the Subject's current roles.
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @param roleOrPrincipalWant A String containing the name of one
   * of the roles or principals that is allowed to access the resource
   * (part of the policy definition).
   *
   * @return A boolean.  true if one of the principals or roles matches
   * the one we're looking for, false otherwise.
   */
  private boolean rolesOrSubjectContains(Map roles, Subject subject, String roleOrPrincipalWant)
  {
    // first, see if it's a role name match
    if (roles.containsKey(roleOrPrincipalWant)) {
      return true;
    }
    // second, see if it's a group name match
    if (SubjectUtils.isUserInGroup(subject, roleOrPrincipalWant)) {
      return true;
    }
    // third, see if it's a user name match
    if (roleOrPrincipalWant.equals(SubjectUtils.getUsername(subject))) {
      return true;
    }
    // didn't match
    return false;
  }

  /**
   * Determines if any of the principals and roles trying to access a resource
   * (that has a policy specified for it) are allowed to.
   *
   * @param resource The Resource the Subject trying is to access.
   *
   * @param subject A Subject that contains the Principals that identify
   * the user who is trying to access the resource as well as the user's
   * groups.
   *
   * @param A Map containing SecurityRoles for the Subject's current roles.
   *
   * @return A Result.  PERMIT if this resource (not one of its parent
   * resources) grants access to one of the principals or roles, DENY if not.
   */
  private Result isAccessAllowed(Resource resource, Subject subject, Map roles)
  {
    // loop over the principals and roles in our database who are allowed to access this resource
    for (Enumeration e = database.getPolicy(resource); e.hasMoreElements();) {
      String roleOrPrincipalAllowed = (String)e.nextElement();
      if (rolesOrSubjectContains(roles, subject, roleOrPrincipalAllowed)) {
        return Result.PERMIT;
      }
    }
    // the resource was explicitly mentioned and didn't grant access
    return Result.DENY;
  }

  /**
   * Called when a new application version is created. Only called on
   * the admin server which is controlling the creation process.
   *
   * This method will search through the security policies for the
   * source application and clone all the entries for the new
   * application version. This will ensure that the new version
   * has any customized policies from the source version.
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
    System.out.println("SimpleSampleAuthorizationProviderImpl.createApplicationVersion");
    System.out.println("\tapplication identifier\t= " + appId);
    System.out.println("\tsource app identifier\t= " + ((sourceAppId != null) ? sourceAppId : "None"));

    // create new policies when existing application is specified
    if (sourceAppId != null) {
      database.clonePoliciesForApplication(sourceAppId,appId);
    }
  }

  /**
   * Called when an application version is deleted. Only called on
   * the admin server which is controlling the deletion process.
   *
   * This method will search through the security policies for the
   * deleted application version and remove all the entries.
   *
   * @param appId the application identifier of the
   *        deleted application version
   *
   * @see VersionableApplicationProvider
   */
  public void deleteApplicationVersion(String appId)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.deleteApplicationVersion");
    System.out.println("\tapplication identifier\t= " + appId);

    // clear out policies for the application
    database.removePoliciesForApplication(appId);
  }

  /**
   * Called when an non-versioned application is deleted. Only called on
   * the admin server which is controlling the deletion process.
   *
   * This method will search through the security policies for the
   * application and remove all the entries.
   *
   * @param appName the application name of the
   *        deleted application
   *
   * @see VersionableApplicationProvider
   */
  public void deleteApplication(String appName)
  {
    System.out.println("SimpleSampleAuthorizationProviderImpl.deleteApplication");
    System.out.println("\tapplication name\t= " + appName);

    // clear out policies for the application
    database.removePoliciesForApplication(appName);
  }

  /**
   * Simple implementation of a policy deployment handle.
   * @see DeployPolicyHandle
   */
  class SampleDeployPolicyHandle implements DeployPolicyHandle
  {
     Date date;
     String application;
     String component;
     ComponentType componentType;

     SampleDeployPolicyHandle(String app, String comp, ComponentType type)
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
