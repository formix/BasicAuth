using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Authentication;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Formix.Authentication.Basic
{
    /// <summary>
    /// Middleware class implementing basic authentication.
    /// </summary>
    public class BasicAuthenticationMiddleware
    {
        private const string AUTHORIZATION = "Authorization";

        private RequestDelegate _next;
        private AuthenticateDelegate _authenticate;
        private string _realm;
        private int _purgatoryPeriod;
        private ISet<IPAddress> _purgatory;

        /// <summary>
        /// Constructor of the BasicAuthentication middleware. Saves 
        /// authentication and realm information for usage during 
        /// invocation along with the next delegate for the middleware 
        /// chaining.
        /// </summary>
        /// <param name="next">The next request middleware to be executed.</param>
        /// <param name="authenticate">The authentication method that will do 
        /// the real stuff.</param>
        /// <param name="realm">The basic authentication realms. Can be a 
        /// sentence defining the resources being protected.</param>
        /// <param name="purgatoryPeriod">How long (ms) the remote ip address 
        /// has to wait before getting its 403 response. During that time, 
        /// the remote ip address is kept in purgatory and its authentication 
        /// requests will fail.</param>
        public BasicAuthenticationMiddleware(RequestDelegate next, AuthenticateDelegate authenticate, string realm, int purgatoryPeriod)
        {
            _next = next;
            _authenticate = authenticate;
            _realm = realm;
            _purgatoryPeriod = purgatoryPeriod;
            _purgatory = new HashSet<IPAddress>();
        }

        /// <summary>
        /// Executes the basic authentication asynchronously.
        /// </summary>
        /// <param name="context">The current http context</param>
        /// <returns>Returns a task for asynchronous execution.</returns>
        public async Task Invoke(HttpContext context)
        {
            var remoteIpAddress = context.Request.HttpContext.Connection.RemoteIpAddress;
            lock (_purgatory)
            {
                if (_purgatory.Contains(remoteIpAddress))
                {
                    // Don't want to slowfail further, just deny access.
                    context.Response.StatusCode = 403;
                    return;
                }
            }

            if (!context.Request.Headers.ContainsKey(AUTHORIZATION))
            {
                context.Response.Headers.Add("WWW-Authenticate", $"Basic realm=\"{_realm}\"");
                context.Response.StatusCode = 401;
                return;
            }

            try
            {
                string headerContent = context.Request.Headers[AUTHORIZATION];
                if (string.IsNullOrWhiteSpace(headerContent) || headerContent.Length <= 6)
                {
                    throw new InvalidOperationException("Invalid Authorization header data.");
                }

                var credentials = CreateCredentials(headerContent.Substring(6));
                credentials.RemoteIpAddress = remoteIpAddress;

                var principal = _authenticate(credentials);

                if (principal == null || !principal.Identity.IsAuthenticated)
                {
                    // no principal or a non authenticated identity is a failure.
                    context.Response.StatusCode = 403;
                    WaitForPurgatory(remoteIpAddress);
                    return;
                }

                if (string.IsNullOrWhiteSpace(principal.Identity.AuthenticationType))
                {
                    throw new InvalidCredentialException("The returned " +
                        "principal identity do not have an authentication type " +
                        "defined. You must set a value to " +
                        "Principal.Identity.AuthenticationType.");
                }

                // Creates Sets the principal to the HttpContext and the current thread.
                context.User = principal;
                if (Thread.CurrentPrincipal != principal)
                {
                    Thread.CurrentPrincipal = principal;
                }
            }
            catch (Exception)
            {
                // Makes sure a smartass don't break the authentication 
                // process with an invalid request without paying the price.
                // If the developper is responsible for the error in the 
                // authentication delegate then... users will pay for it as 
                // well.
                WaitForPurgatory(remoteIpAddress);
                throw;
            }

            await _next.Invoke(context);
        }

        private Credentials CreateCredentials(string base64Credentials)
        {
            byte[] credentialsData = Convert.FromBase64String(base64Credentials);
            string credentialString = Decode(credentialsData);
            var credentialSplit = credentialString.Split(new[] { ':' }, 2);

            if (credentialSplit.Length != 2)
            {
                throw new InvalidOperationException("Invalid Authorization header data.");
            }

            return new Credentials()
            {
                Realm = _realm,
                Username = credentialSplit[0],
                Password = credentialSplit[1]
            };
        }

        private static string Decode(byte[] credentialsData)
        {
            try
            {
                var encoding = Encoding.GetEncoding("iso-8859-1");
                string credentialString = encoding.GetString(credentialsData);
                return credentialString;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Unable to decode Authorization header data.", ex);
            }
        }

        private void WaitForPurgatory(IPAddress remoteIpAddress)
        {
            lock (_purgatory)
            {
                _purgatory.Add(remoteIpAddress);
            }

            Thread.Sleep(_purgatoryPeriod);

            lock (_purgatory)
            {
                _purgatory.Remove(remoteIpAddress);
            }
        }

    }
}
