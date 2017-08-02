using System.Security.Claims;

namespace Formix.Authentication.Basic
{
    public delegate Claim[] AuthenticateDelegate(Credentials data);
}
