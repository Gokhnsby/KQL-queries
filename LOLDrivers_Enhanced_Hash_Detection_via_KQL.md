## LOLDrivers Enhanced Hash Detection via KQL Script


###___###___###

This KQL query 
The KQL Query cross-references MD5, SHA256 and SHA1 hashes from the LOLDrivers repository to identify potential matches within our file environment. KQL query plays a crucial role in threat detection, risk mitigation, compliance adherence, and enhancing the security posture of your organisation's IT environment. KQL has the scenario for external data is to retrieve MD5, SHA256 and SHA1 hashes from external source of LOLDrivers github repository to be always up to date.

###___###___###

https://www.loldrivers.io/about/

https://github.com/magicsword-io/LOLDrivers

https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/externaldata-operator?pivots=azuredataexplorer

###___###___###

Security Threat Detection: It helps identify potentially malicious activities related to LOLBins (Living off the Land Binaries) within your file environment. LOLBins are legitimate system binaries that can be misused by attackers to execute malicious actions while evading detection.

Anomaly Detection: By cross-referencing hashes from the LOLDrivers repository, the query identifies potential matches within your environment. This helps detect anomalies in file activities that may indicate unauthorised or malicious usage of system binaries.

Risk Mitigation: Detecting and investigating the usage of LOLBins can help mitigate security risks by identifying and addressing potential security breaches or compromises in a timely manner.

Enhanced Security Posture: Implementing proactive measures, such as monitoring for LOLBins activities, strengthens the overall security posture of your organisation by reducing the likelihood of successful cyber attacks and minimising the impact of security incidents.

### KQL for MD5 Hashes

```
//The KQL Query cross-references MD5 hashes from the LOLDrivers repository to identify potential matches within our file environment.
//illegal executables to run drivers, 
//https://www.loldrivers.io/drivers/bb808089-5857-4df2-8998-753a7106cb44/?query=dbutildrv2.sys
let loaders = dynamic(["sc.exe", "services.exe", "net.exe"]);
DeviceFileEvents
| where FileName endswith ".sys"
| where InitiatingProcessCommandLine has_any (loaders)
| where Timestamp >= ago(24h)
//Check the FP values
| distinct SHA1, FileName
| where SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples.md5"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples_malicious.md5"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples_vulnerable.md5"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples.md5"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples_malicious.md5"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples_vulnerable.md5"])
```


### KQL for SHA256 Hashes

```
//The KQL Query cross-references SHA256 hashes from the LOLDrivers repository to identify potential matches within our file environment.
//illegal executables to run drivers, 
//https://www.loldrivers.io/drivers/bb808089-5857-4df2-8998-753a7106cb44/?query=dbutildrv2.sys
let loaders = dynamic(["sc.exe", "services.exe", "net.exe"]);
DeviceFileEvents
| where FileName endswith ".sys"
| where InitiatingProcessCommandLine has_any (loaders)
| where Timestamp >= ago(24h)
//Check the FP values
| distinct SHA1, FileName
| where SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples.sha256"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples_malicious.sha256"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples_vulnerable.sha256"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples.sha256"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples_malicious.sha256"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples_vulnerable.sha256"])

```

### KQL for SHA1 Hashes

```
//The KQL Query cross-references SHA1 hashes from the LOLDrivers repository to identify potential matches within our file environment.
//illegal executables to run drivers, 
//https://www.loldrivers.io/drivers/bb808089-5857-4df2-8998-753a7106cb44/?query=dbutildrv2.sys
let loaders = dynamic(["sc.exe", "services.exe", "net.exe"]);
DeviceFileEvents
| where FileName endswith ".sys"
| where InitiatingProcessCommandLine has_any (loaders)
| where Timestamp >= ago(24h)
//Check the FP values
| distinct SHA1, FileName
| where SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples.sha1"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples_malicious.sha1"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/authentihash_samples_vulnerable.sha1"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples.sha1"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples_malicious.sha1"])
or SHA1 in (externaldata(hash:string)["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/85d276420cf865d6dacb6b745848d34cb72a13c1/detections/hashes/samples_vulnerable.sha1"])
```
