using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Mvc;
using TestWcfService;

namespace TestWebApplication.Controllers
{
    public class HomeController : Controller
    {
        //--------------------------------------

        //DELEGATION - CALL TO WCF SERVICE
        //we are going to call the WCF service OnBehalfOf the user, so we need to go to STS to get a token for this.
        // flow:
        //  Client --> WEB = 401, redirection to STS (PASSIVE scenario)
        //  Client --> STS = TOKEN_1
        //  Client --(TOKEN_1)--> WEB
        //  WEB --(TOKEN_1 + OnBehalfOf setting)--> STS = TOKEN_2 (ACTIVE scenario)
        //  WEB --(TOKEN_2)--> WCF service

        //For delegation we have two options: ActAs or OnBehalfOf
        //                
        //   - The ActAs feature is typically used in scenarios that require composite delegation, where the final recipient of the issued token can inspect 
        //     the entire delegation chain and see not just the client, but all intermediaries (the token contains the clamis for all the entities)
        //   - The OnBehalfOf feature is used in scenarios where only the identity of the original client is important (the token will contains only the original caller claims)
        //
        //we use OnBehalfOf for this example.

        //In order to get these types of token we need to provide the STS the original token the user used to access the website
        //Note that the original token is the very same SAML token we are used to in a normal Claim-aware scenario.
        //In a delegation scenario where there are multiple tokens it is called BOOTSTRAP TOKEN.
        //WIF by default, once authenticated the user get rid of the Bootstrap token and create a Session Cookie to maintains the login session
        //As we need this bootstrap token to request the second one, we need to instruct WIF in order to keep it --> saveBootstrapContext = true

        //SETUP
        //in a delegation scenario we need additional steps on the ADFS server:
        //1- we need to GRANT delegation permissions to the Relying party (edit claims rules -> delegation authorization rules -> Permit access to all users)
        //   this tells ADFS to issues ACTAS/ONBEHALFOF token types for our WCF service
        //2- set-ADFSProperties -AcceptableIdentifier http://testWCFService.gianlucb.local
        //3- ADFS server does not allow delegation by default for a new RP, so allowing it via powershell
        //      $rule = '@RuleTemplate = "AllowAllAuthzRule" => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",Value = "true");'
        //      Get - ADFSRelyingPartyTrust - Name TestWCFservice | Set - AdfsRelyingPartyTrust - ImpersonationAuthorizationRules $rule
        //4- In this scenario the standard claim rule that copies the "LDAP values" to Token claims does not work as the Relying party receives a token with the claims already filled
        //  so we need to copy over the claims from the caller's token. 
        //  For this we need to create a new Claim transformation rule of type "Pass Through" for each claim we want to copy to the final token (TOKEN_2)

        //To get the second Token we have two options with WIF:
        //1 - manually create an OnBehalfOf / ActAs request for the STS and then use the token retrieved to call the target service (CreateChannelWithIssuedToken)
        //2 - leverage the WS2007FederationBinding automatic mechanism that contacts STS automatically to request the OnBehalfOf / ActAs token for us (CreateChannelWithOnBehalfOfToken)
        

        //retrieve the token needed for delegation automatically using the Federeation Binding (option 1)
        public ActionResult Index()
        {
            string wcfview = String.Empty;
            string webview = String.Empty;
            string exception = String.Empty;
            try
            {

                //print out all the claims for the website                
                ClaimsIdentity identity = (ClaimsIdentity)User.Identity;                             
                StringBuilder builder = new StringBuilder();               
                foreach (Claim claim in identity.Claims)
                {
                    builder.AppendLine("ClaimType :" + claim.Type + "   ClaimValue:" + claim.Value);
                }

                webview = builder.ToString();

                //--------------------------------------

                //DELEGATION - CALL TO WCF SERVICE
                //we are going to call the WCF service OnBehalfOf the user, so we need to go to STS to get a token for this.
                // flow:
                //  Client --> WEB = 401, redirection to STS (PASSIVE scenario)
                //  Client --> STS = TOKEN_1
                //  Client --(TOKEN_1)--> WEB
                //  WEB --RST OnBehalfOf(TOKEN_1)--> STS = TOKEN_2 (ACTIVE scenario)
                //  WEB --(TOKEN_2)--> WCF service

                //For delegation we have two options: ActAs or OnBehalfOf
                //                
                //   - The ActAs feature is typically used in scenarios that require composite delegation, where the final recipient of the issued token can inspect 
                //     the entire delegation chain and see not just the client, but all intermediaries (the token contains the clamis for all the entities)
                //   - The OnBehalfOf feature is used in scenarios where only the identity of the original client is important (the token will contains only the original caller claims)
                //
                //we use OnBehalfOf for this example.

                //In order to get these types of token we need to provide the STS the original token the user used to access the website
                //Note that the original token is the very same SAML token we are used to in a normal Claim-aware scenario.
                //In a delegation scenario where there are multiple tokens it is called BOOTSTRAP TOKEN.
                //WIF by default, once authenticated the user get rid of the Bootstrap token and create a Session Cookie to maintains the login session
                //As we need this bootstrap token to request the second one, we need to instruct WIF in order to keep it --> saveBootstrapContext = true

                //SETUP
                //in a delegation scenario we need additional steps on the ADFS server:
                //1- we need to GRANT delegation permissions to the Relying party (edit claims rules -> delegation authorization rules -> Permit access to all users)
                //   this tells ADFS to issues ACTAS/ONBEHALFOF token types for our WCF service
                //2- set-ADFSProperties -AcceptableIdentifier http://testWCFService.gianlucb.local
                //3- ADFS server does not allow delegation by default for a new RP, therefore we need to enable it via powershell
                //      $rule = '@RuleTemplate = "AllowAllAuthzRule" => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",Value = "true");'
                //      Get-ADFSRelyingPartyTrust -Name TestWCFservice | Set-AdfsRelyingPartyTrust-ImpersonationAuthorizationRules $rule
                //4- In this scenario the standard claim rule that copies the "LDAP values" to Token claims does not work as the Relying party receives a token with the claims already filled
                //  so we need to copy over the claims from the caller's token. 
                //  For this we need to create a new Claim transformation rule of type "Pass Through" for each claim we want to copy to the final token (TOKEN_2)


                //this requires <identityConfiguration saveBootstrapContext="true"> otherwise the following is null (token not saved by default)
                BootstrapContext bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as BootstrapContext;
                SecurityToken callerToken = bootstrapContext.SecurityToken;
                if (callerToken == null) throw new Exception("Bootstrap token not found");

                //To get the second Token we have two options with WIF:
                //1 - leverage the WS2007FederationBinding automatic mechanism that contacts STS automatically to request the OnBehalfOf / ActAs token for us (CreateChannelWithOnBehalfOfToken)
                //2 - manually create an OnBehalfOf / ActAs request for the STS and then use the token retrieved to call the target service (CreateChannelWithIssuedToken)

                //option 1
                wcfview = "Using CreateChannelWithOnBehalfOfToken: ";
                wcfview += CallWebServiceAutomaticOption(callerToken);

            }
            catch(Exception ex)
            {
                wcfview = ex.Message;
                exception = ex.StackTrace;
            }

            ViewBag.Webview = webview;
            ViewBag.WcfView = wcfview;
            ViewBag.Exception = exception;

            return View();
        }

        //retrieve the token needed for delegation manually, calling STS directly before to call the WCF service (option 2)
        public ActionResult Index2()
        {
            string wcfview = String.Empty;
            string webview = String.Empty;
            string exception = String.Empty;
            try
            {

                //print out all the claims for the website                
                ClaimsIdentity identity = (ClaimsIdentity)User.Identity;
                StringBuilder builder = new StringBuilder();
                foreach (Claim claim in identity.Claims)
                {
                    builder.AppendLine("ClaimType :" + claim.Type + "   ClaimValue:" + claim.Value);
                }

                webview = builder.ToString();
               
                //this requires <identityConfiguration saveBootstrapContext="true"> otherwise the following is null (token not saved by default)
                BootstrapContext bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as BootstrapContext;
                SecurityToken callerToken = bootstrapContext.SecurityToken;
                if (callerToken == null) throw new Exception("Bootstrap token not found");

                //option 1
                //being done manually we have more control on the token request, for example we can specify the target URI (== audienceUri) that can be different from the listening URI of the WCF service
                wcfview = "Using CreateChannelWithIssuedToken: ";
                wcfview += CallWebServiceManualOption(callerToken);

            }
            catch (Exception ex)
            {
                wcfview = ex.Message;
                exception = ex.StackTrace;
            }

            ViewBag.Webview = webview;
            ViewBag.WcfView = wcfview;
            ViewBag.Exception = exception;

            return View();
        }

        #region Manual (Option 1)
        private string CallWebServiceManualOption(SecurityToken callerToken)
        {
            //demonstrate how to call the target webservice - MANUALLY requesting a OnBehalfToken for it            

            //creating the channel and calling it, matching the binding configured on service side               
            WS2007FederationHttpBinding federationBinding = new WS2007FederationHttpBinding();
            federationBinding.Security.Mode = WSFederationHttpSecurityMode.TransportWithMessageCredential;
            federationBinding.Security.Message.EstablishSecurityContext = false;
            federationBinding.Security.Message.NegotiateServiceCredential = false;
            federationBinding.Security.Message.IssuedKeyType = SecurityKeyType.SymmetricKey;

            EndpointAddress wcfServiceEndpoint = new EndpointAddress(Program.WCFAddress);
            ChannelFactory<ITestService> factory = new ChannelFactory<ITestService>(federationBinding, wcfServiceEndpoint);            
            factory.Credentials.SupportInteractive = false;
            factory.Credentials.UseIdentityConfiguration = true;

            //because we are going to call the service manually, we first need to retrieve ourself the OnBehalfOf token
            //this token will then be used to call the remote service
            var tokenOnBehalf = GetSecurityTokenOnBehalf(callerToken);

            // Create a channel.
            ITestService client = factory.CreateChannelWithIssuedToken(tokenOnBehalf);
            string result = client.SayHello();
            ((IClientChannel)client).Close();

            return result;
        }

        public SecurityToken GetSecurityTokenOnBehalf(SecurityToken bootstrapToken)
        {

            //service identifier whitin the ADFS server where I want to access, must be configured as RP in ADFS
            //this is the same value we configure on server side for the parameter audienceUris
            EndpointReference serviceAddress = new EndpointReference(@"http://testWCFService.gianlucb.local");

            //who gives me the token
            string stsAddress;

            //ignores certificates error
            ServicePointManager.ServerCertificateValidationCallback = (x, y, z, w) => true;

            //we use windows transport, that means the WEB server uses the application pool account to authenticate with STS
            stsAddress = @"https://sts.gianlucb.local/adfs/services/trust/13/windowstransport";

            WS2007HttpBinding stsBinding = new WS2007HttpBinding(SecurityMode.Transport);
            stsBinding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;

            WSTrustChannelFactory trustChannelFactory = new WSTrustChannelFactory(stsBinding, stsAddress);
            trustChannelFactory.Credentials.SupportInteractive = false;
            trustChannelFactory.TrustVersion = TrustVersion.WSTrust13;
            //---------------------

            //connection
            WSTrustChannel channel = (WSTrustChannel)trustChannelFactory.CreateChannel();

            RequestSecurityToken rst = new RequestSecurityToken(RequestTypes.Issue);
            rst.AppliesTo = serviceAddress;
            rst.KeyType = KeyTypes.Symmetric;
            rst.RequestType = RequestTypes.Issue;
            rst.OnBehalfOf = new SecurityTokenElement(bootstrapToken);  //required for delegation

            RequestSecurityTokenResponse rstr = null;
            SecurityToken token = channel.Issue(rst, out rstr);
            var xmlSecurityToken = token as GenericXmlSecurityToken;

            Trace.WriteLine("Received the token (OnBehalfOf):");
            Trace.WriteLine(xmlSecurityToken.TokenXml.InnerXml);

            return token;
        }
        #endregion

        #region Automatic (Option 2)
        private string CallWebServiceAutomaticOption(SecurityToken callerToken)
        {
            //demonstrate how to call the target webservice - the ActAs/onBehalfToken is automatically requested by the ChannelFactory   

            //we need to specify how to call the STS
            WS2007HttpBinding stsBinding = new WS2007HttpBinding();
            stsBinding.Security.Mode = SecurityMode.Transport;
            stsBinding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;            

            //creating the channel and calling it                
            WS2007FederationHttpBinding federationBinding = new WS2007FederationHttpBinding();
            federationBinding.Security.Mode = WSFederationHttpSecurityMode.TransportWithMessageCredential;
            federationBinding.Security.Message.EstablishSecurityContext = false;
            federationBinding.Security.Message.NegotiateServiceCredential = false;
            //in order to have the automatic "token" retrieve we need to instruct the binding where to take the "onBehalfOf/ActAs" token from (STS)
            federationBinding.Security.Message.IssuedKeyType = SecurityKeyType.SymmetricKey;
            federationBinding.Security.Message.IssuerAddress = new EndpointAddress("https://sts.gianlucb.local/adfs/services/trust/13/windowstransport");
            federationBinding.Security.Message.IssuerBinding = stsBinding;
            

            EndpointAddress wcfServiceEndpoint = new EndpointAddress(Program.WCFAddress);
            ChannelFactory<ITestService> factory = new ChannelFactory<ITestService>(federationBinding, wcfServiceEndpoint);
            factory.Credentials.SupportInteractive = false;
            factory.Credentials.UseIdentityConfiguration = true;
                       
            //The CreateChannelWithOnBehalfOfToken method triggers a STS request automatically with the right token settings (OnBehalfOf)
            //we do not need to request this token ourself, it is WIF that do it for us
            ITestService client = factory.CreateChannelWithOnBehalfOfToken(callerToken); 
            string result = client.SayHello();
            ((IClientChannel)client).Close();

            return result;
        }
        #endregion

    
    }
}