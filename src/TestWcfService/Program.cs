using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;

namespace TestWcfService
{
    public class Program
    {
        public static Uri WCFBaseAddress = new Uri("https://gb-s10.gianlucb.local:9999");
        public static Uri WCFAddress = new Uri(WCFBaseAddress.AbsoluteUri + "TestService");

        static void Main(string[] args)
        {          
            try
            {
                //selfhosting WCF service (to be ran as administrator)               

                using (ServiceHost host = new ServiceHost(typeof(TestService), WCFBaseAddress))
                {                 
                    ConfigureHostForFederation(host);

                    host.Open();

                    Console.WriteLine("The service is ready at {0}", WCFAddress);
                    Console.WriteLine("Press <Enter> to stop the service.");
                    Console.ReadLine();
                         
                    host.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                Console.WriteLine(ex.StackTrace);
            }
            finally
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
            }


        }

        private static void ConfigureHostForFederation(ServiceHost host)
        {

            // this method demonstrate how to configure WCF by code instead of use the classic config file approach
                      
            //setting this service to use the right binding for WIF/ADFS
            WS2007FederationHttpBinding federationBinding = new WS2007FederationHttpBinding();
            federationBinding.Security.Mode = WSFederationHttpSecurityMode.TransportWithMessageCredential;
            federationBinding.Security.Message.EstablishSecurityContext = false;
            host.AddServiceEndpoint(typeof(ITestService), federationBinding, "TestService");

            //SERVICE CREDENTIAL
            //because WCF defaults to symmetric proof keys, we also need to specify a decryption certificate. 
            //This is different compared to WIF, and goes directly into the service credentials behavior:   
            /*
                 <serviceCredentials useIdentityConfiguration=“true“>
                                <serviceCertificate findValue=“XXXXXXXXXXXXXXX“
                                    storeLocation=“LocalMachine“
                                    storeName=“My“
                                    x509FindType=“FindByThumbprint“/>
                  </serviceCredentials> 
            */
            var serviceCredentialBehavior = new ServiceCredentials();
            serviceCredentialBehavior.UseIdentityConfiguration = true;
            serviceCredentialBehavior.ServiceCertificate.Certificate = GetServiceCertificate("D2BCA0B46D69360CA6DB328DEC6599B37ACFE724"); //must be on local machine, with private key
            host.Description.Behaviors.Add(serviceCredentialBehavior);


            //SERVICE AUTHORIZATION
            // tells WCF to populate Thread.CurrentPrincipal
            /*
                 <serviceAuthorization principalPermissionMode=“Always“ />
            */
            host.Description.Behaviors.Find<ServiceAuthorizationBehavior>().PrincipalPermissionMode = PrincipalPermissionMode.Always;

            ConfigureWIF(host);
            
        }

        private static void ConfigureWIF(ServiceHost host)
        {
            /*
              this method demonstrates how to configure WIF and WCF by code instead of use the classic config file approach
              Emulates the following config:

              WIF
              ----------------------------------
              <system.identityModel> 
                <identityConfiguration> 
                  <audienceUris> 
                    <add value="http://testWCFservice.gianlucb.local" /> 
                  </audienceUris> 
                  <issuerNameRegistry type="System.IdentityModel.Tokens.ConfigurationBasedIssuerNameRegistry, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"> 
                    <trustedIssuers> 
                      <add thumbprint="9b91b18206a805896b19c4ffd20a487db025d321" name="signing certificate sts" /> 
                    </trustedIssuers> 
                  </issuerNameRegistry> 
                  <certificateValidation certificateValidationMode="None" />
                </identityConfiguration> 
             </system.identityModel> 

             if you want ot use the config file approach do not call this method
            */

            //configure the WIF specific settings
            IdentityConfiguration identityConfig = new IdentityConfiguration(false);

            //AUDIENCE URI                
            //this value can be a fantasy name and not a real URL, it identifies our service whitin the ADFS server.
            //It must be equal to the one defined in ADFS Console ("RELAYING PARTY trust identifiers" section)
            //the token we receive contains this value, so if do not match we fail
            identityConfig.AudienceRestriction.AllowedAudienceUris.Add(new Uri("http://testWCFservice.gianlucb.local")); //this is used manually
            identityConfig.AudienceRestriction.AllowedAudienceUris.Add(new Uri("https://gb-s10.gianlucb.local:9999/TestService"));  //this is used by FederationBdining, created automatically


            //ISSUER NAME REGISTRY explicit the thumbprint of the accepted certificates, if the token coming in is not signed with any of these certificates then is considered invalid
            var issuerNameRegistry = new ConfigurationBasedIssuerNameRegistry();
            issuerNameRegistry.AddTrustedIssuer("9b91b18206a805896b19c4ffd20a487db025d321", "signing certificate sts"); //STS signing certificate thumbprint
            identityConfig.IssuerNameRegistry = issuerNameRegistry;
            identityConfig.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;

            //attach our config to the service
            host.Credentials.IdentityConfiguration = identityConfig;
        }

        private static X509Certificate2 GetServiceCertificate(string thumbprint)
        {
            X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            certStore.Close();
            return certCollection[0];
        }
    }
}
