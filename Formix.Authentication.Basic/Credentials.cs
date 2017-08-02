namespace Formix.Authentication.Basic
{
    /// <summary>
    /// Credentials received during the basic authentication process.
    /// </summary>
    public class Credentials
    {
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