import json
import re

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
        "steamcommunity.com/id/vidar_drop"
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

normalized_iocs = {
    "sha256": list(set(filter(None, [clean_hash(h) for h in raw_data["hashes"]]))),
    "c2_ip": list(set([clean_ip(ip) for ip in raw_data["ips"]])),
    "dead_drop_urls": [d.strip() for d in raw_data["domains"]]
}

print(json.dumps(normalized_iocs, indent=4))
