using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Text;

namespace Formix.Authentication.Basic
{
    public static class BasicAuthenticationExtension
    {
        public static IApplicationBuilder UseBasicAuthentication(this IApplicationBuilder builder, AuthenticateDelegate authenticate, string realm = "")
        {
            return builder.UseMiddleware<BasicAuthenticationMiddleware>(authenticate, realm);
        }
    }
}
