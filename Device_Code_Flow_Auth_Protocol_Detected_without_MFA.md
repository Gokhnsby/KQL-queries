## Device-Code Flow Auth Protocol Detected without MFA


###___###___###

monitoring the Device-Code Flow Auth Protocol without MFA is essential for maintaining a secure authentication environment, complying with regulations, mitigating risks, preventing unauthorised access, and protecting sensitive data. This KQL query shows the related application name as well.

###___###___###

https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code

https://cloudbrothers.info/en/protect-users-device-code-flow-abuse/

###___###___###

Security Risks: The Device-Code Flow allows devices with limited input capabilities to authenticate with online services such as Azure AD. Without MFA, attackers could potentially compromise user accounts using stolen or brute-forced credentials, as there is only one factor (typically a username/password) required for authentication.

Risk Mitigation: Enforcing MFA adds an additional layer of security, making it significantly harder for unauthorised users to gain access to sensitive resources even if they obtain valid credentials. Monitoring for instances where Device-Code Flow is used without MFA allows you to identify and mitigate potential security risks promptly.

Device-Code Flow increases the risk of unauthorised access to this sensitive data. Monitoring the usage of Device-Code Flow helps identify and address potential security gaps before they can be exploited.

###KQL

```
let critical_applications = dynamic(["Microsoft Azure CLI", "Azure Kubernetes Service AAD Client"]);
let app1= AADSignInEventsBeta
| where EndpointCall =="Cmsi:Cmsi"
| where (Application has_any (critical_applications)) 
| where AuthenticationRequirement != "multiFactorAuthentication"
| mv-expand parse_json(NetworkLocationDetails)
| evaluate bag_unpack(NetworkLocationDetails)
//| where not (networkNames contains "Office" )
| project Timestamp, ReportId, DeviceName, Application, ApplicationId, AccountUpn, AccountDisplayName, Browser, AuthenticationRequirement,ClientAppUsed, IPAddress, Country;
let app2 = AADSignInEventsBeta
| where Application =="Microsoft Intune Web Company Portal" // join the other critical apps (Microsoft Intune Web Company Portal)
| where EndpointCall =="Cmsi:Cmsi"
| project Timestamp, Application, ApplicationId, AccountUpn, AccountDisplayName, Browser, AuthenticationRequirement, ClientAppUsed, IPAddress, Country, ReportId, DeviceName;
app1
| join kind=fullouter app2 on ApplicationId
| project Timestamp = coalesce(Timestamp, Timestamp1), Application = coalesce(Application, Application1), 
                            ApplicationId = coalesce(ApplicationId, ApplicationId1), AccountUpn = coalesce(AccountUpn, AccountUpn1),
                            AccountDisplayName = coalesce(AccountDisplayName, AccountDisplayName1), Browser = coalesce(Browser, Browser1),
                            ClientAppUsed = coalesce(ClientAppUsed, ClientAppUsed1),
                            AuthenticationRequirement = coalesce(AuthenticationRequirement, AuthenticationRequirement1),
                            IPAddress = coalesce(IPAddress, IPAddress1), Country = coalesce(Country, Country1), DeviceName = coalesce(DeviceName, DeviceName1),
                            ReportId = coalesce(ReportId, ReportId1)
```

