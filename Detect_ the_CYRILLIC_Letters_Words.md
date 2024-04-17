## Detecting the CYRILLIC letters/words from Device File Events using KQL


###___###___###

This KQL query helps you to identify potential malicious activity involving the use of Cyrillic characters in file names. You can enhance your organisation's ability to detect, investigate, and respond to potential security threats and policy violations by detecting Cyrillic characters in file names and analysing associated file events. It is just an idea for your detection capacities. 

###___###___###

https://klizosolutions.medium.com/homograph-attack-using-cyrillic-characters-know-what-it-is-and-how-to-avoid-it-dec024e7cf70

https://www.bleepingcomputer.com/news/security/cyrillic-characters-are-favorites-for-idn-homograph-attacks/

###___###___###

Unicode-based Evasion Techniques: Malicious actors may use non-Latin characters, such as Cyrillic, to evade detection mechanisms that are primarily designed to handle ASCII characters. By detecting and monitoring file events involving Cyrillic characters, you can better defend against such evasion tactics.

Anomalous File Naming: File names containing Cyrillic characters may indicate attempts to disguise malicious files or payloads. These files could be part of malware propagation, data exfiltration, or other unauthorised activities within your environment.

Early Warning of Suspicious Behavior: Identifying and investigating file events with Cyrillic characters can provide an early warning of potential security incidents or policy violations. It allows security teams to proactively respond to and mitigate threats before they escalate.

Contextual Understanding: While some legitimate files or applications may legitimately use Cyrillic characters, especially in multinational environments, filtering out files that deviate from expected patterns can help identify outliers that warrant further investigation.

###KQL

```
//Detecting the CYRILLIC letters/words from Device FileEvents using KQL
//https://www.ssec.wisc.edu/~tomw/java/unicode.html
//let folder_paths = dynamic(["C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Program Files"]);
//define the normal chars in our scope to filter them
let normal_chars = (dynamic (["1089", "1040"]));
DeviceFileEvents
//| where FolderPath has_any (folder_paths)
| extend u_code = unicode_codepoints_from_string(FileName)
| mv-expand c = u_code
//Remove the possible false positives like 'c' char
| where not (u_code has_any ((normal_chars)))
| where toint(c) between (1024 .. 1154)
| project FileName, u_code
```



