using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Text;

namespace Formix.Authentication.Basic
{
    public static class BasicAuthExtension
    {
        public static IApplicationBuilder UseBasicAuthentication(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<BasicAuthMiddleware>();
        }
    }
}
