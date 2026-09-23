# Week 2 Report: OSINT Data Collection & Reconnaissance

Project Title: Detection Engineering and Threat Intelligence Analysis of Vidar Stealer

## 1. OSINT Data Source Mapping

Source: ThreatFox Type: Free/Open Data: C2 IPs and domain URLs Reliability: High Usage: Gathering active Vidar server addresses

Source: MalwareBazaar Type: Free/Open Data: SHA256/MD5 Hashes Reliability: High Usage: Getting file hashes of Vidar samples

Source: VirusTotal Type: Free/Open Data: Antivirus scan results and file graphs Reliability: Very High Usage: Checking if our collected hashes and IPs are flagged by antiviruses

Source: Shodan Type: Free/Open Data: Open ports and server info Reliability: High Usage: Checking C2 panel hosting details

## 2. Investigation Results of the hash from MalwareBazaar in VirusTotal and Shodan

<img width="1916" height="1082" alt="image" src="https://github.com/user-attachments/assets/7e84ce51-824a-4429-9066-39b1edd96c80" />

### VirusTotal Findings:
<img width="1917" height="1146" alt="image" src="https://github.com/user-attachments/assets/e8557ef4-58e9-401c-a513-f65925e59b46" />

We checked hash e93511363f7781c4c7ff3ed0698db6c4634092fe7e93ca96d666509a9412e73e. Took it from the MalwareBazar website.
File Name: lf3t32pa.exe
File Size: 97.06 MB
Detection Rate: 7 out of 68 security vendors flagged this file as malicious
Threat Classification: trojan.wingo/krypt (identified as a Trojan/WinGo Packer by vendors like ESET, Sophos, and Google)

To deeply understand the threat infrastructure, we analyzed the Relations and Behavior tabs on VirusTotal:

#### 1. Relations
<img width="1917" height="1148" alt="image" src="https://github.com/user-attachments/assets/b9ba37ce-9aca-4806-acbf-1c44f9502bcd" />

From the Relations tab, we identified connected external domains, IP addresses, and communication channels:
- Contacted Domains: Identified connections to telegram.me (used as a dead-drop resolver to fetch active C2 addresses) and suspicious domains like k3.188wbtoto.org.
- Contacted IP Addresses: The binary attempts outbound connections to IPs across the Netherlands (NL) and United States (US), including 31.59.44.104 and 149.154.167.99.

#### 2. Behavior
<img width="1917" height="1145" alt="image" src="https://github.com/user-attachments/assets/c613ab9f-f354-4a6b-9450-69008b2bb7a1" />
<img width="1917" height="1150" alt="image" src="https://github.com/user-attachments/assets/89e190da-4c9e-40bd-b8f9-3c7472416f6c" />

The Behavior tab (Zenbox sandbox dynamic analysis) clearly confirms this sample acts as a classic InfoStealer:
- Browser Data Access (Files Opened): The malware systematically searches for sensitive user data inside local directories of various web browsers, including Microsoft\Edge\User Data, BraveSoftware\Brave-Browser, Chromium, and AVAST Software\Browser.
- Registry Modifications: The process opens and sets registry keys under HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ to establish persistence and read system configurations.

### Shodan Findings:
We queried the extracted C2 IP address 31.59.44.104 on Shodan to analyze the attacker's server setup and hosting infrastructure:

<img width="1917" height="1147" alt="image" src="https://github.com/user-attachments/assets/6e5e5cfb-df62-46e7-9aa2-75ce4b408347" />
<img width="955" height="1080" alt="image" src="https://github.com/user-attachments/assets/66938789-22d0-432c-80eb-706f8c411fd3" />
<img width="962" height="682" alt="image" src="https://github.com/user-attachments/assets/20836ef0-fd27-4146-b118-8a1b408413c0" />

IP Address: 31.59.44.104
Location: London, United Kingdom (UK)
ISP / Organization: Hydra Communications Ltd / GOLD IP L.L.C-FZ (ASN: AS25369)
Open Ports & Services:
- Port 22 (SSH): Running OpenSSH 9.2p1 Debian for remote administration by the malware operator.
- Port 80 (HTTP): Responds with HTTP/1.1 404 Not Found, which is standard behavior for C2 panels to hide the admin login endpoint from public web scanners.

