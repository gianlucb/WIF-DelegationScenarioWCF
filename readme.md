# WIF EXAMPLE #2 - DELEGATION SCENARIO WITH WCF SECURED SERVICE
This example use WIF with .NET 4.5 to demonstrate a delegation scenario. There are three actors here: the client (WEB application), the WCF service and the ADFS server (STS).
The WCF service is secured with WIF/ADFS, so the client must present a valid token to access the service methods.  
A delegation scenario means the client (WEB) retrieves the token from the ADFS server (STS) on behalf of the logged user, then the token is used to call the WCF service.
The target service will see the identity of the user. 

In this example you can see how to automatically and manually request an **OnBehalfOf** token to imporsonate the user at WCF service level

![Call flow](/img/delegation-wif.png)


## CALL FLOW
1. Client --> WEB = 401, redirection to STS (PASSIVE scenario)
2. Client --> STS = TOKEN_1
3. Client --(**TOKEN_1**)--> WEB = 200 OK
4. WEB --RST OnBehalfOf(**TOKEN_1**)--> STS = **TOKEN_2** (ACTIVE scenario)
5. WEB --(**TOKEN_2**)--> WCF service

In order to issue a **RST (Request Security Token)** message to the STS, we have two options:
1.  leverage the _WS2007FederationBinding_ automatic mechanism that contacts STS automatically to request the **OnBehalfOf/ActAs** token for us, then call the target web service with:
    * **CreateChannelWithOnBehalfOfToken(...bootstrap token...)**
    * **CreateChannelWithActAsToken(...bootstrap token...)**
2.  manually create a **RST** message (_WSTrustChannel_) to retrieve the **OnBehalfOf/ActAs** token and call the target WCF web service with:
    * **CreateChannelWithIssuedToken(...onbehalfof token...)**

*Notes:*
* this example includes:
    * Passive scenario = between the user's browser and the WEB application (passive means the user's browser is redirected back and forth between STS and the WEB application)
    This is done using the WIF authentication module (_WsFederationAuthenticationModule_ + _SessionAuthenticationModule_)
    * Active scenario = between the WEB application and the WCF Service
* By Default WCF uses **symmetric keys** for the tokens so we need a certificate to encrypt the token at ADFS side
    * the certificate must be configured as SSL certificate for the web service (installed with private key on the machine store) --> it will be used to decrypt the token  
    * the public key (.cer) must be set as _encryption certificate_ in the ADFS server (for this web service relying party only)
* The token we receive at web service side is then **encrypted** with the WCF certificate and **signed** with the **ADFS Server signing certificate** --> this is why we also need to set the ADFS server signing certificate thumbprint in the WIF configuration
* This sample uses the simple windows transport endpoint to authenticate the WEB application against the STS (works if on same domain)


## PREREQUISITES 
* ADSF server (STS)
* Domain Controller
* 1 web server with SSL certificate
             
             
## SETUP
1. register the WEB application with ADFS --> configure a new **Relying Party**
    * **Passive Endpoint** = must be equal to the listening address of the web application (this is where the user is redirected if the authentication completes successfully)
    * Add some claim rules (i.e: copy AD attributes to Claims) 
2. register the WCF service with ADFS --> configure a new **Relying Party**
    * **Relying party identifier** = a fantasy name (url) that identifies this service, the name used here must be set also on client side (as **EndpointReference**) and service side (as **AudienceUri**).
    In the case of the automatic RST creation, this identifier is set equal to the listening address of the web service (included the port). So you can add multiple entries to support all the behaviors. 
    * **Encryption** = select the certificate (.cer) used by this service (the same used to listen for HTTPS). We need this becasue WCF by default use symmetric tokens. If you switch to Bearer then this step is not necessary
    * Add some claim rules (i.e: copy AD attributes to Claims) to allow direct access to the service
    * being a delegation scenario the standard claim rule that copies the "LDAP values" to Token claims is not sufficent as the Relying party receives a token with the claims already filled. We need to copy over the claims from the caller's token, so we need to create a new Claim transformation rule of type "Pass Through" for each claim we want to copy to the final token (TOKEN_2)
3. because we are doing selfhost for WCF service we must manually bind the certificate for SSL (_these steps are not required if IIS is used to host the service_): 
    * *netsh http add sslcert ipport=0.0.0.0:9999 certhash=thumbprint_of_ssl_server_certificate appid={XXXXX-XXXXX-XXXXXX-XXXXX-XXXX-XXXXXX}*      
    * *netsh http add urlacl url=https://+:9999/ user=EVERYONE*
4. we need to GRANT delegation permissions to the Relying party (edit claims rules -> delegation authorization rules -> Permit access to all users) 
    * *set-ADFSProperties -AcceptableIdentifier http://testWCFService.gianlucb.local*
6. ADFS server does not allow delegation by default for a new RP, therefore we need to enable it via powershell
      *$rule = '@RuleTemplate = "AllowAllAuthzRule" => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",Value = "true");'*
      *Get-ADFSRelyingPartyTrust -Name TestWCFservice | Set-AdfsRelyingPartyTrust -ImpersonationAuthorizationRules $rule*
7. Change code and set the right certificate thumbprints for _IssuerNameRegistry_ (certificate of the STS signing certificate) and for the ServiceCertificate (cert used for SSL)
8. Host the website and the wcf service on the same machine (or change the WCF service endpoint address)


 
 
 