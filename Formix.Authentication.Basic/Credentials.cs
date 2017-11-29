using Microsoft.AspNetCore.Http;
using System.Net;

namespace Formix.Authentication.Basic
{
    /// <summary>
    /// Credentials received during the basic authentication process.
    /// </summary>
    public class Credentials
    {

        /// <summary>
        /// Creates a Credentials object using the given HttpContext.
        /// </summary>
        /// <param name="context"></param>
        public Credentials(HttpContext context)
        {
            Context = context;
        }

        /// <summary>
        /// Gets the HttpContext of the received credentials.
        /// </summary>
        public HttpContext Context { get; }

        /// <summary>
        /// The remote ip address of the connection to authenticate.
        /// </summary>
        public IPAddress RemoteIpAddress
        {
            get
            {
                return Context.Request.HttpContext.Connection.RemoteIpAddress;
            }
        }

        /// <summary>
        /// The realm of the authentication.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets the user name.
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        public string Password { get; set; }
    }
}