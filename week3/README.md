# Week 3 Report: Data Normalization, MISP Ingestion Preparation & Detection Engineering

**Project Title:** Detection Engineering and Threat Intelligence Analysis of Vidar Stealer Distributed via Cracked Software, SEO Poisoning, and Fake YouTube Downloads

---

## 1. IOC Data Normalization (Python Script)

To process raw threat intelligence data collected during Week 2, a custom Python script was developed. The script cleans raw IoCs, strips unnecessary whitespaces, converts domains/IPs to lowercase, and formats them into clean JSON/CSV structures for platform ingestion.

### Python Normalization Script (`normalize_iocs.py`):

```python
import json
import re

# Raw IoC dataset collected from OSINT stage
raw_data = {
    "hashes": [
        " E93511363F7781C4C7FF3ED0698DB6C4634092FE7E93CA96D666509A9412E73E ",
        "e93511363f7781c4c7ff3ed0698db6c4634092fe7e93ca96d666509a9412e73e"
    ],
    "ips": [
        " 31.59.44.104 ",
        "31.59.44.104:80"
    ],
    "domains": [
        " Https://t.me/vidar_c2_channel ",
        "[steamcommunity.com/id/vidar_drop](https://steamcommunity.com/id/vidar_drop)"
    ]
}

def clean_hash(hash_str):
    cleaned = hash_str.strip().lower()
    if re.match(r"^[a-f0-9]{64}$", cleaned):
        return cleaned
    return None

def clean_ip(ip_str):
    cleaned = ip_str.strip().split(':')[0]
    return cleaned

# Process IoCs
normalized_iocs = {
    "sha256": list(set(filter(None, [clean_hash(h) for h in raw_data["hashes"]]))),
    "c2_ip": list(set([clean_ip(ip) for ip in raw_data["ips"]])),
    "dead_drop_urls": [d.strip() for d in raw_data["domains"]]
}

# Output normalized JSON
print(json.dumps(normalized_iocs, indent=4))
```

<img width="767" height="773" alt="image" src="https://github.com/user-attachments/assets/e5850e33-f085-4ece-a199-ea9d922339f3" />

## 2. MISP Event Ingestion Preparation

Normalized IoCs are structured into MISP-compatible attribute formats for seamless threat sharing.

| Attribute Type | Value | Category | MISP To-IDS Flag |
| :--- | :--- | :--- | :--- |
| `sha256` | `e93511363f7781c4c7ff3ed0698db6c4634092fe7e93ca96d666509a9412E73E` | Payload delivery | `Yes` |
| `ip-dst` | `31.59.44.104` | Network activity | `Yes` |
| `url` | `https://t.me/vidar_c2_channel` | Antivirus detection | `No (Dead Drop)` |

3. Detection Engineering: Sigma Rule Generation
To detect Vidar Stealer execution in Windows environments via suspicious process creation and temp folder activity, the following Sigma Rule was crafted:

---

## 3. Detection Engineering: Sigma Rule Generation

To detect Vidar Stealer execution in Windows environments via suspicious process creation and temp folder activity, the following **Sigma Rule** was crafted:

```yaml
title: Suspicious Process Spawning from Fake Crack Utility (Vidar Stealer)
id: f47ac10b-58cc-4372-a567-0e02b2c3d479
status: experimental
description: Detects Vidar Stealer execution originating from suspicious temp folders often used by pirated software installers.
author: CTI Student Team
date: 2026/09/23
references:
    - https://virustotal.com
tags:
    - attack.execution
    - attack.t1055
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\AppData\Local\Temp\*.exe'
            - '\Downloads\*.exe'
        CommandLine|contains:
            - 'passwords.txt'
            - 'cookies.sqlite'
    condition: selection
falsepositives:
    - Legitimate administrative software bundlers
level: high
```
<img width="1902" height="771" alt="image" src="https://github.com/user-attachments/assets/c524dfe8-ceb2-470d-9593-476f558a9fc6" />




