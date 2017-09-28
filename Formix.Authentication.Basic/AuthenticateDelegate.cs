using System.Security.Claims;

namespace Formix.Authentication.Basic
{
    /// <summary>
    /// Execute authentication procedure with the basic authentication
    /// credentials.
    /// </summary>
    /// <param name="data">User name and password credentials.</param>
    /// <returns>Returns an array of claims if the authentication worked. 
    /// Returns null if it failed.</returns>
    public delegate ClaimsPrincipal AuthenticateDelegate(Credentials data);
}
