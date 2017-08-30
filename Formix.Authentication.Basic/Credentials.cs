using System.Net;

namespace Formix.Authentication.Basic
{
    /// <summary>
    /// Credentials received during the basic authentication process.
    /// </summary>
    public class Credentials
    {
        /// <summary>
        /// The remote ip address of the connection to authenticate.
        /// </summary>
        public IPAddress RemoteIpAddress { get; set; }

        /// <summary>
        /// The realm of the authentication.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets the user name.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        public string Password { get; set; }
    }
}