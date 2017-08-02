﻿using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Formix.Authentication.Basic
{
    public class BasicAuthenticationMiddleware
    {
        private const string AUTHORIZATION = "Authorization";

        private RequestDelegate _next;
        private AuthenticateDelegate _authenticate;
        private string _realm;

        public BasicAuthenticationMiddleware(RequestDelegate next, AuthenticateDelegate authenticate, string realm)
        {
            _next = next;
            _authenticate = authenticate;
            _realm = realm;
        }

        public async Task Invoke(HttpContext context)
        {
            if (!context.Request.Headers.ContainsKey(AUTHORIZATION))
            {
                context.Response.Headers.Add("WWW-Authenticate", $"Basic realm=\"{_realm}\"");
                context.Response.StatusCode = 401;
                return;
            }

            string headerContent = context.Request.Headers[AUTHORIZATION];
            if (string.IsNullOrWhiteSpace(headerContent) || headerContent.Length <= 6)
            {
                throw new InvalidOperationException("Invalid Authorization header data.");
            }

            var credentials = CreateCredentials(headerContent.Substring(6));

            var claims = _authenticate(credentials);
            if (claims == null || claims.Length == 0)
            {
                // No claim means failed authentication
                context.Response.StatusCode = 403;
                return;
            }

            // Creates the principal
            context.User = new ClaimsPrincipal(new ClaimsIdentity[]
            {
                new ClaimsIdentity(claims, "Basic")
            });

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
    }
}
