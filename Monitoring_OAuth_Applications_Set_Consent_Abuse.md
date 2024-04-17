## Monitoring OAuth Applications - Set Consent Abuse-  


###___###___###

This KQL query is crucial for security because it helps monitor and analyse user consent activities in Azure Active Directory (AAD). By examining the consented applications and associated endpoint calls, security teams can detect potentially risky behavior or unauthorised access.

###___###___###

https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent

https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/

###___###___###

Detecting Unauthorised Access: By analysing endpoint calls involving consent, security teams can identify instances where users have granted access to applications without proper authorisation or oversight. This could indicate potential security risks, such as unauthorised data access or application misuse.

Identifying Compliance Issues: Monitoring consent activities helps ensure compliance with organisational policies and regulations. Unauthorised access to sensitive resources or data can lead to compliance violations, making it crucial to detect and address such incidents promptly.

Mitigating Security Risks: Understanding the reasons behind consent errors (e.g., user declines, admin consent required, multi-factor authentication issues) allows security teams to address underlying security risks. For example, requiring admin consent for certain applications or enforcing multi-factor authentication can enhance security and prevent unauthorised access.

###KQL

```
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where EndpointCall contains "Consent"
//Get the locations from your Sign-in logs
| mv-expand Location = parse_json(NetworkLocationDetails)[0].networkNames
| where isnull( Location )
//Checking the device is managed by Azure AD or registered (Hybrid Azure AD joined or Azure AD registered) and if it is trusted, do not check it.
| where IsManaged == "0" and isempty( DeviceTrustType )
//
//Just some additional error information for investigations. (new column to table -Details- based on the Consent error codes)
| extend Details = case ( ErrorCode == "650057", "Invalid resource. The client has requested access to a resource which is not listed in the requested permissions in the client's application registration.",
                          ErrorCode == "530003", "The requested resource can only be accessed using a compliant device. The user is either using a device not managed by a Mobile-Device-Management (MDM) agent like Intune, or it's using an application that doesn't support device authentication. The user could enroll their devices with an approved MDM provider, or use a different app to sign in, or find the app vendor and ask them to update their app.",
                          ErrorCode == "90094", "Admin consent is required for the permissions requested by this application.",
                          ErrorCode == "65004", "User declined to consent to access the app.",
                          ErrorCode == "50097", "Device authentication is required.  this is an interrupt that triggers device authentication when required due to a Conditional Access policy or because the application or resource requested the device ID in a token.",
                          ErrorCode == "50074", "Strong Authentication is required. User needs to perform multi-factor authentication.",
                          ErrorCode == "50072", "Due to a configuration change made by your administrator, or because you moved to a new location, you must enroll in multi-factor authentication to access.",
                          ErrorCode == "50011", "Developer error - the app is attempting to sign in without the necessary or correct authentication parameters.",
                          ErrorCode == "0", "There is no error regarding this consent app attempt.",
                          "If the error code is not present here, please check this link to get details.. https://login.microsoftonline.com/error "
)
//Checking for MFA is applied or not. (Eliminating the MFA enabled auth.)
| where AuthenticationRequirement =="singleFactorAuthentication" and not( ErrorCode == "0")
//Join with DeviceNetwork info table to get name of the device or more details about device
| join kind=inner  (
DeviceNetworkInfo
| where IPAddresses != "[]"
| mv-expand IP_=parse_json(tostring(IPAddresses))
| extend (IPs) = tostring(IP_.IPAddress), Subnet = IP_.SubnetPrefix, Type = IP_.AddressType
) on $left.IPAddress == $right.IPs
| project Timestamp, Application,LogonType,AccountDisplayName,AccountUpn,EndpointCall,ErrorCode,IPAddress,Country,ClientAppUsed,UserAgent,Browser,AuthenticationRequirement,IsManaged,OSPlatform,Details, DeviceName1, MacAddress, NetworkAdapterStatus
```

