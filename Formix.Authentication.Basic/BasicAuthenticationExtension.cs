using Microsoft.AspNetCore.Builder;

namespace Formix.Authentication.Basic
{
    /// <summary>
    /// Static class that stores the UseBasicAuthentication extension method.
    /// </summary>
    public static class BasicAuthenticationExtension
    {
        /// <summary>
        /// Extension methods that initialize basic authentication.
        /// </summary>
        /// <param name="builder">The application builder instance.</param>
        /// <param name="authenticate">The authentication delegate used to 
        /// authenticate user credentials.</param>
        /// <param name="realm">The basic authentication realm.</param>
        /// <param name="purgatoryPeriod">How long (ms) the remote ip address 
        /// has to wait before getting its 403 response. During that time, 
        /// the remote ip address is kept in purgatory and its authentication 
        /// requests will fail.</param>
        /// <returns>Return the application builder instance for method chaining.</returns>
        public static IApplicationBuilder UseBasicAuthentication(this IApplicationBuilder builder, AuthenticateDelegate authenticate, string realm = "", int purgatoryPeriod = 500)
        {
            return builder.UseMiddleware<BasicAuthenticationMiddleware>(authenticate, realm, purgatoryPeriod);
        }
    }
}
