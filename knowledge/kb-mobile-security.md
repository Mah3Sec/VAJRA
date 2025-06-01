# KB: Mobile Application Security Testing
# Applies to: iOS, Android, mobile API, MASVS, MASTG

## OWASP Mobile Top 10 (2024)
| ID | Category | CWE | Key Test Cases |
|---|---|---|---|
| M1 | Improper Credential Usage | CWE-798,259 | Hardcoded creds in APK/IPA, insecure storage |
| M2 | Inadequate Supply Chain Security | CWE-1104 | Malicious SDK, outdated dependencies |
| M3 | Insecure Authentication/Authorisation | CWE-287,639 | Biometric bypass, token manipulation |
| M4 | Insufficient Input/Output Validation | CWE-20,89,79 | SQL injection in local DB, XSS in WebView |
| M5 | Insecure Communication | CWE-295,319 | No cert pinning, cleartext traffic, weak TLS |
| M6 | Inadequate Privacy Controls | CWE-200 | PII in logs, clipboard exposure, screenshots |
| M7 | Insufficient Binary Protections | CWE-693 | No root/jailbreak detection, no obfuscation |
| M8 | Security Misconfiguration | CWE-16 | Debug mode, adb backup enabled, exported components |
| M9 | Insecure Data Storage | CWE-312,313 | Cleartext in SharedPrefs, SQLite, keychain |
| M10 | Insufficient Cryptography | CWE-326,327 | Hardcoded keys, ECB mode, custom crypto |

## Android-Specific Findings
| Finding | CVSS | CWE | Test Method |
|---|---|---|---|
| Exported Activity / ContentProvider / BroadcastReceiver | 7.5 | CWE-284 | AndroidManifest.xml, adb activity launch |
| Insecure SharedPreferences (world-readable) | 7.5 | CWE-312 | Pull SharedPrefs, check for sensitive data |
| SQLite database unencrypted with PII | 7.5 | CWE-313 | adb pull /data/data/pkg/databases/ |
| Hardcoded API keys / secrets in APK | 9.1 | CWE-798 | apktool, jadx, grep for key patterns |
| Backup enabled (android:allowBackup=true) | 6.5 | CWE-312 | adb backup, extract app data |
| No root detection | 5.3 | CWE-693 | Magisk/RootBeer bypass, Frida hook |
| Webview JavaScript enabled with file access | 8.8 | CWE-79 | UXSS, local file read via WebView |
| Logcat PII leakage | 5.3 | CWE-532 | adb logcat grep for tokens/PII |
| Certificate pinning absent | 7.5 | CWE-295 | Burp proxy intercept without bypass |
| Insecure deeplink handling | 6.5 | CWE-601 | Craft malicious deeplink URI |

## iOS-Specific Findings
| Finding | CVSS | CWE | Test Method |
|---|---|---|---|
| Sensitive data in NSUserDefaults | 7.5 | CWE-312 | objection/Frida dump UserDefaults |
| Keychain data with kSecAttrAccessibleAlways | 6.5 | CWE-312 | Extract keychain on jailbroken device |
| No jailbreak detection | 5.3 | CWE-693 | Liberty Lite bypass, Frida hook |
| Insecure NSLog / print statements with PII | 5.3 | CWE-532 | Xcode Console / syslog monitoring |
| Clipboard exposure of sensitive data | 5.3 | CWE-200 | Paste sensitive data, check clipboard |
| Screen capture / backgrounding data in screenshot | 5.3 | CWE-200 | App switcher screenshot of sensitive screen |
| Weak biometric implementation | 7.5 | CWE-287 | Frida hook LocalAuthentication bypass |
| Hardcoded secrets in binary | 9.1 | CWE-798 | strings, otool, class-dump, MobSF |
| ATS (App Transport Security) disabled | 5.9 | CWE-319 | Info.plist: NSAllowsArbitraryLoads |
| Insecure WKWebView (JS injection) | 8.8 | CWE-79 | WebView XSS, cookie theft |

## Mobile Testing Tools
| Tool | Platform | Purpose |
|---|---|---|
| MobSF | Both | Static and dynamic analysis, automated |
| Frida | Both | Dynamic instrumentation, runtime hooks |
| objection | Both | Frida-based runtime exploration |
| apktool + jadx | Android | APK decompilation and analysis |
| class-dump / Hopper | iOS | Binary analysis and class headers |
| Burp Suite + cert bypass | Both | HTTP/HTTPS traffic interception |
| adb | Android | Device interaction, file system access |
| iDevice (iProxy/ifuse) | iOS | File system access on jailbroken device |

## MASVS (Mobile Application Security Verification Standard) Levels
- MASVS-L1: Basic security — storage, network, platform interaction
- MASVS-L2: Defence in depth — root/jailbreak detection, pinning, obfuscation
- MASVS-R: Resilience — anti-tampering, anti-debugging, obfuscation

## Remediation Guidance
- Certificate pinning: Implement with backup pins; handle pin rotation gracefully
- Root/jailbreak detection: Use multi-layered detection (file checks, hook detection, integrity)
- Secure storage: Android Keystore / iOS Keychain with appropriate accessibility attributes
- Sensitive data: Never log PII; clear clipboard after sensitive paste; blur backgrounding screenshots
- Exported components: Explicitly set exported=false; add permission checks to exported components
