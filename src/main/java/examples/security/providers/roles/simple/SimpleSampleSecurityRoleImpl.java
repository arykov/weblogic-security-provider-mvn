package examples.security.providers.roles.simple;

import weblogic.security.service.SecurityRole;

/**
 * The sample sample role mapper's implementation of the
 * SecurityRole interface.
 *
 * It is used to return roles from the simple sample role mapper.
 *
 * This class is internal to the simple sample role mapper.
 * It is not a public class.
 *
 * @author Copyright (c) 2002 by BEA Systems. All Rights Reserved.
 */
/*package*/ class SimpleSampleSecurityRoleImpl implements SecurityRole
{
  private String roleName; // the role's name
  private int    hashCode; // the role's hash code

  /**
   * Create a simple sample role mapper role instance.
   *
   * @param roleName A String containing the role's name.
   */
  /*package*/ SimpleSampleSecurityRoleImpl(String roleName)
  {
    this.roleName = roleName;
    this.hashCode = roleName.hashCode() + 17;
  }

  /**
   * Deterimines if two role instances are the same.
   *
   * @param genericRole An Object for another role.
   *
   * @return A boolean indicating if this role is the same as the one passed in.
   *
   * @see Object
   */
  public boolean equals(Object genericRole)
  {
    // if the other role is null, we're not the same
    if (genericRole == null) {
      return false;
    }

    // if we're the same java object, we're the same
    if (this == genericRole) {
      return true;
    }

    // if the other role is not a simple sample role mapper role,
    // we're not the same
    if (!(genericRole instanceof SimpleSampleSecurityRoleImpl)) {
      return false;
    }

    // Cast the other role to a simple sample role mapper role.
    SimpleSampleSecurityRoleImpl sampleRole =
      (SimpleSampleSecurityRoleImpl)genericRole;

    // if our names don't match, we're not the same
    if (!roleName.equals(sampleRole.getName())) {
       return false;
    }

    // we're the same
    return true;
  }

  /**
   * Convert the role to a printable string.
   *
   * @return A String containing the role's name.
   *
   * @see Object
   */
  public String toString()
  {
    return roleName;
  }

  /**
   * Get the role's hash code.
   *
   * @return an int containing the role's hash code.
   *
   * @see Object
   */
  public int hashCode()
  {
    return hashCode;
  }

  /**
   * Get the role's name
   *
   * @return A String containing the role's name
   *
   * @see SecurityRole
   */
  public String getName()
  {
     return roleName;
  }

  /**
   * Get the role's description.
   *
   * @return A String containing the role's description.
   * Returns an empty string since the simple sample role mapper
   * doesn't support role descriptions.
   *
   * @see SecurityRole
   */
  public String getDescription()
  {
    return "";
  }
}
