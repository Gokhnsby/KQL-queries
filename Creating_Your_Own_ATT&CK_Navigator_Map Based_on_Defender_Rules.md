## Creating Your Own ATT&CK Navigator Map Based on Defender Rules


###___###___###

How can you quickly review your Defender rules' MITRE coverage with the ATT&CK Navigator map?

Create custom maps using KQL scripts to visualise coverage, identify gaps, and strengthen your cybersecurity posture.

###___###___###

https://mitre-attack.github.io/attack-navigator/

###___###___###

Creating your own ATT&CK Navigator map based on Defender rules is essential for visualising your coverage because it provides a clear and comprehensive view of how well your defenses align with the MITRE ATT&CK framework. This framework is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. By mapping your Defender rules to this framework, you can easily identify which techniques are effectively covered and which areas may have gaps. This visualisation helps to highlight potential vulnerabilities in your security posture, allowing you to prioritise and address them promptly.

Furthermore, having a tailored ATT&CK Navigator map enhances your threat detection and response capabilities. When you can see how your existing Defender rules correlate with specific adversary tactics and techniques, it becomes easier to fine-tune your security measures. This alignment ensures that your defenses are not only comprehensive but also targeted and efficient, improving your ability to detect and mitigate threats. Additionally, this visualisation aids in streamlining your security operations, making it simpler to communicate your coverage and any identified gaps to stakeholders and decision-makers.

To facilitate this process, you can use a KQL script to export your Defender rules into a JSON format that is ready to be submitted as input to the MITRE ATT&CK Navigator. This JSON export enables you to quickly and easily visualise your Defender MDE rules within the ATT&CK framework, providing a powerful tool for assessing and enhancing your security coverage.

###KQL - Detection of TOR Connections from “Checkpoint” List

```
let dynamicAttributes_first = dynamic({
    "name": "layer",
    "versions": {
        "attack": "15",
        "navigator": "5.0.1",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "",
    "filters": {
        "platforms": [
            "Windows",
            "Linux",
            "macOS",
            "Network",
            "PRE",
            "Containers",
            "Office 365",
            "SaaS",
            "Google Workspace",
            "IaaS",
            "Azure AD"
        ]
    }
});
let  dynamicAttributes_last = dynamic({
    "gradient": {
        "colors": [
            "#ff6666ff",
            "#ffe766ff",
            "#8ec843ff"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": false,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": true,
    "selectSubtechniquesWithParent": false,
    "selectVisibleTechniques": false
});
AlertInfo
| where AttackTechniques != ""
//| where DetectionSource == "Custom detection" //you can filter your source detection method
| extend ParsedAttack = parse_json(AttackTechniques)
| mv-expand ParsedAttack
| extend techniqueID = extract("T[0-9]+(?:\\.[0-9]+)?", 0, tostring(ParsedAttack))
| extend tactic = Category
| extend color = "#e60d0d" //red background
| extend comment = ""
| extend enabled = true
//| extend metadata = dynamic([])
//| extend links = dynamic([])
| extend showSubtechniques = true
| project-away ParsedAttack
| distinct techniqueID, tactic, color, comment, enabled, showSubtechniques //tostring(metadata), tostring(links)
| summarize techniques = make_list(pack(
    'techniqueID', techniqueID, //tThe important point here is that this ID value highlights what we have as coverage in our custom map.
//    'tactic', tactic,
    'color', color,
    'comment', comment,
    'enabled', enabled,
//    'metadata', metadata,
//    'links', links,
    'showSubtechniques', showSubtechniques
))
| extend jsonOutput = bag_merge(dynamicAttributes_first, pack('techniques', techniques))
| extend finalOutput = bag_merge(jsonOutput, dynamicAttributes_last)
| project ourjsonOutput = tostring(finalOutput)
```

###KQL - Output JSON file which is already ready to submit as MITRE Navigator MAP input file.

```json
{
  "name": "layer",
  "versions": {
    "attack": "15",
    "navigator": "5.0.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "",
  "filters": {
    "platforms": [
      "Windows",
      "Linux",
      "macOS",
      "Network",
      "PRE",
      "Containers",
      "Office 365",
      "SaaS",
      "Google Workspace",
      "IaaS",
      "Azure AD"
    ]
  },
  "techniques": [
    {
      "techniqueID": "T1566",
      "tactic": "InitialAccess",
      "color": "#e60d0d",
      "comment": "",
      "enabled": true,
      "showSubtechniques": true
    },
   .....
    {
      "techniqueID": "T1566.001",
      "tactic": "InitialAccess",
      "color": "#e60d0d",
      "comment": "",
      "enabled": true,
      "showSubtechniques": true
    },
    {
      "techniqueID": "T1053.002",
      "tactic": "Persistence",
      "color": "#e60d0d",
      "comment": "",
      "enabled": true,
      "showSubtechniques": true
    }
  ]
}
```

