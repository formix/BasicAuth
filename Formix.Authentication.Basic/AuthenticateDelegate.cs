using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Formix.Authentication.Basic
{
    public delegate Claim[] AuthenticateDelegate(Credentials data);
}
