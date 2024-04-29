## Detecting TOR IP/Nodes Connections within Your Environment


###___###___###

This KQL query helps monitor network events and identifies connections to Tor nodes-IPs by cross-referencing the events with external lists of known Tor nodes. Script fetchs lists of Tor nodes-IPs from two external sources:
The first source is from "https://secureupdates.checkpoint.com/IP-list/TOR.txt".

###___###___###

https://sc1.checkpoint.com/documents/R80.20SP/WebAdminGuides/EN/CP_R80.20SP_Chassis_AdminGuide/Topics-Chassis-AG/IP-Block-Feature.htm

https://www.dan.me.uk/tornodes

###___###___###

Security Monitoring: Tor is often used to anonymise network traffic, which can be exploited by attackers to hide malicious activities such as command and control (C2) communication, data exfiltration, or accessing malicious websites. Detecting Tor nodes-IPs helps in monitoring and identifying potential security threats within your network.

Risk Assessment: The presence of Tor nodes-IPs in your environment may indicate unauthorised or suspicious activities. Identifying and monitoring these nodes allows you to assess the level of risk associated with their presence and take appropriate actions to mitigate potential security risks.

Policy Enforcement: Many organisations have policies prohibiting the use of Tor or accessing Tor nodes-IPs due to security concerns. Detecting and blocking Tor nodes-IPs helps enforce these policies and maintain a secure network environment.

Compliance Requirements: Compliance standards and regulations such as PCI DSS, HIPAA, and GDPR often require organisations to monitor and protect against unauthorised network traffic, including traffic associated with anonymisation services like Tor. Detecting Tor nodes-IPs helps fulfil these compliance requirements.

Incident Response: In the event of a security incident or breach, identifying connections to Tor nodes-IPs can provide valuable insights for incident response teams to investigate and remediate the incident effectively

###KQL - Detection of TOR Connections from “Checkpoint” List

```
DeviceNetworkEvents
| where RemoteIP != ""
| where ActionType == "ConnectionSuccess"
| where RemoteIP in(externaldata (Nodes: string)[@"https://secureupdates.checkpoint.com/IP-list/TOR.txt"]with (format="txt", ignoreFirstRecord=false))
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessCommandLine
```

###KQL - Detection of TOR Connections from “dan.me.uk” List

```
DeviceNetworkEvents
| where RemoteIP != ""
| where ActionType == "ConnectionSuccess"
| where RemoteIP in(externaldata (Nodes: string)[@"https://www.dan.me.uk/torlist/?full"]with (format="txt", ignoreFirstRecord=false))
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessCommandLine

```

