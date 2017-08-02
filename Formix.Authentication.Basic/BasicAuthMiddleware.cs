using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Formix.Authentication.Basic
{
    public class BasicAuthMiddleware
    {
        private RequestDelegate _next;

        public BasicAuthMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity[]
            {
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, "jpgravel")
                }, "Basic")
            });
            context.User = principal;

            await _next.Invoke(context);
        }

    }
}
