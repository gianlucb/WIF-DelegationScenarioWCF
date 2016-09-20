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


            //Impersonation Example
            //----------------------
            //if we want to impersonate we need the UPN as to be able to create a Windows Identity
            //then we should run this service as LOCAL SYSTEM to have all the privileges (psexec -s TestWcfService.exe)
            //and create a c:\temp folder. The file created will be written with the caller privileges and properties (i.e: check the security tab and look for owner field)

            //var upnClaim = claimsPrincipal.Claims.Where((c) => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn").FirstOrDefault();
            //if(upnClaim == null)
            //    throw new InvalidOperationException("The caller has not an UPN claim");

            //WindowsIdentity callerWindowsIdentity = new WindowsIdentity(upnClaim.Value);
            //if (callerWindowsIdentity == null)
            //{
            //    throw new InvalidOperationException("The caller cannot be mapped to a WindowsIdentity");
            //}
            //using (callerWindowsIdentity.Impersonate())
            //{
            //    // Access a file as the caller.
            //    var f = System.IO.File.CreateText(@"c:\temp\test.txt");
            //    f.WriteLine("Hello");
            //    f.Close();
            //}


            return builder.ToString();
        }
    }
}
