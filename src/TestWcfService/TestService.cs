using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Claims;
using System.ServiceModel;
using System.Text;

namespace TestWcfService
{    
    public class TestService : ITestService
    {
        public string SayHello()
        {
            ClaimsPrincipal claimsPrincipal = OperationContext.Current.ClaimsPrincipal;
            ClaimsIdentity caller = claimsPrincipal.Identity as ClaimsIdentity;

            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Computed by WCF TestService");          
            builder.AppendLine("IsAuthenticated:" + caller.IsAuthenticated);
            builder.AppendLine("The service received the following issued claims of the client:");

            foreach (Claim claim in claimsPrincipal.Claims)
            {
                builder.AppendLine("ClaimType :" + claim.Type + "   ClaimValue:" + claim.Value);
            }

            return builder.ToString();
        }
    }
}
