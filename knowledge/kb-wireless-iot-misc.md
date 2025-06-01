# KB: Wireless, IoT, Thick Client, Source Code Review, OSINT
# Applies to: WiFi pentesting, IoT/embedded, desktop app, code review, recon

## Wireless / Wi-Fi Security Testing
| Finding | CVSS | CWE | Test |
|---|---|---|---|
| WEP encryption in use | 9.8 | CWE-327 | Capture IVs, aircrack-ng crack |
| WPA2-TKIP in use | 7.5 | CWE-327 | TKIP deprecated, downgrade attack |
| WPS enabled (PIN brute-force) | 8.1 | CWE-307 | Reaver, Bully WPS attack |
| Evil twin / rogue AP attack vector | 7.5 | CWE-290 | hostapd-wpe, eaphammer |
| PEAP/EAP-TTLS without cert validation | 8.1 | CWE-295 | hostapd-wpe credential capture |
| Guest Wi-Fi access to corp network | 8.1 | CWE-284 | VLAN isolation bypass test |
| Default AP admin credentials | 8.8 | CWE-798 | Web interface default login |

## IoT / Embedded Device Security
| Finding | CVSS | CWE | Test Method |
|---|---|---|---|
| Default credentials on device | 9.8 | CWE-798 | Web/SSH/Telnet default login |
| UART/JTAG debug interface exposed | 8.8 | CWE-284 | Physical debug port root shell |
| Unencrypted firmware | 7.5 | CWE-311 | Binwalk extraction, filesystem analysis |
| Hardcoded credentials in firmware | 9.1 | CWE-798 | strings analysis on firmware binary |
| Command injection via web interface | 9.8 | CWE-78 | OS commands in web input fields |
| Insecure MQTT (no auth/TLS) | 8.1 | CWE-306 | MQTT subscribe all topics unauthenticated |
| Telnet enabled on device | 8.1 | CWE-319 | Network scan, cleartext telnet |

## Thick Client / Desktop Application Testing
| Finding | CVSS | CWE | Test Method |
|---|---|---|---|
| Credentials in plaintext config/registry | 9.1 | CWE-312 | Strings on config files, registry |
| DLL hijacking | 8.8 | CWE-427 | Process Monitor, missing DLL path |
| Insecure cleartext protocol traffic | 7.5 | CWE-319 | Wireshark/Burp proxy intercept |
| Memory credential exposure | 7.5 | CWE-316 | Process dump, strings analysis |
| Missing ASLR/DEP binary protections | 7.0 | CWE-119 | PE analysis with checksec |
| Broken client-side access control | 8.8 | CWE-602 | Bypass UI via direct API calls |

## Source Code Review — Vulnerability Patterns
| Language | Dangerous Pattern | Vulnerability | CWE |
|---|---|---|---|
| Java | String.format(input) in SQL | SQL Injection | CWE-89 |
| Python | os.system(user_input) | Command Injection | CWE-78 |
| PHP | echo $_GET['param'] unescaped | XSS | CWE-79 |
| JavaScript | eval(userInput) | Code Injection | CWE-94 |
| Any | MD5/SHA1 for passwords | Weak Hashing | CWE-916 |
| Any | Random().nextInt() for tokens | Weak Randomness | CWE-330 |
| Any | API key in source file | Hardcoded Credential | CWE-798 |
| Java/PHP | XMLReader(userInput) | XXE | CWE-611 |
| Any | fetch(request.param) | SSRF | CWE-918 |
| Any | deserialize(userInput) | Insecure Deserialization | CWE-502 |

## OSINT & Reconnaissance Findings
| Finding | CVSS | Description |
|---|---|---|
| Employee credentials in breach databases | 9.1 | Valid creds found on HaveIBeenPwned/dehashed |
| Sensitive documents indexed by search engines | 7.5 | Google dork: site:target.com filetype:pdf |
| Admin/dev subdomains exposed publicly | 7.5 | admin., staging., dev., internal. reachable |
| GitHub/GitLab secrets in public repos | 9.1 | API keys, DB passwords in commit history |
| Shodan-exposed internal services | 7.5 | Internet-exposed management interfaces |
| LinkedIn-derived org chart + tech stack | 3.7 | Attack surface and target identification |
