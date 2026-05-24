# MITRE ATT&CK Coverage Matrix

> This file tracks all detection rules in this repository mapped against the MITRE ATT&CK Framework (v15).
> Each row represents a Technique or Sub-technique with a corresponding rule, platform, severity, and SIEM availability.

**Last Updated:** 2025-01-01  
**Framework Version:** MITRE ATT&CK v15  
**Total Techniques Covered:** 20  
**Total Rules:** 28  

---

## 📊 Coverage Summary

| Tactic | Techniques Covered | Rules Available |
|---|---|---|
| Initial Access | 3 | 4 |
| Execution | 3 | 5 |
| Persistence | 3 | 4 |
| Privilege Escalation | 2 | 3 |
| Defense Evasion | 2 | 3 |
| Credential Access | 3 | 4 |
| Lateral Movement | 2 | 3 |
| Command & Control | 2 | 2 |
| **Total** | **20** | **28** |

---

## Full Coverage Table

### TA0001 — Initial Access

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1078 | Valid Accounts | Successful Login Outside Business Hours | Windows | Medium | ✅ | ✅ | ✅ | ✅ |
| T1078 | Valid Accounts | Disabled Account Login Attempt | Windows | High | ✅ | ✅ | ✅ | ✅ |
| T1190 | Exploit Public-Facing Application | Web Shell Upload Detected | Linux | Critical | ✅ | ✅ | ✅ | ❌ |
| T1566.001 | Spearphishing Attachment | Suspicious Office Macro Execution | Windows | High | ✅ | ✅ | ✅ | ✅ |

---

### TA0002 — Execution

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1059.001 | PowerShell | PowerShell Encoded Command Execution | Windows | High | ✅ | ✅ | ✅ | ✅ |
| T1059.001 | PowerShell | PowerShell Download Cradle Detected | Windows | High | ✅ | ✅ | ✅ | ✅ |
| T1059.004 | Unix Shell | Reverse Shell via Bash | Linux | Critical | ✅ | ✅ | ✅ | ❌ |
| T1053.003 | Cron | Crontab Modification by Non-Root User | Linux | Medium | ✅ | ✅ | ✅ | ❌ |
| T1053.005 | Scheduled Task | Suspicious Scheduled Task Creation | Windows | Medium | ✅ | ✅ | ✅ | ✅ |

---

### TA0003 — Persistence

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1547.001 | Registry Run Keys | Registry Run Key Persistence | Windows | Medium | ✅ | ✅ | ✅ | ✅ |
| T1053.003 | Cron | New Cron Job Added by Non-Root | Linux | Medium | ✅ | ✅ | ✅ | ❌ |
| T1053.005 | Scheduled Task | Hidden Scheduled Task via schtasks.exe | Windows | High | ✅ | ✅ | ✅ | ✅ |
| T1136.001 | Local Account | New Local Admin Account Created | Windows | High | ✅ | ✅ | ✅ | ✅ |

---

### TA0004 — Privilege Escalation

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1548.001 | Setuid and Setgid | SUID Binary Execution | Linux | High | ✅ | ✅ | ✅ | ❌ |
| T1548.003 | Sudo and Sudo Caching | Sudo Privilege Escalation Attempt | Linux | High | ✅ | ✅ | ✅ | ❌ |
| T1055.001 | DLL Injection | Suspicious DLL Injection via CreateRemoteThread | Windows | Critical | ✅ | ✅ | ✅ | ✅ |

---

### TA0005 — Defense Evasion

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1218.005 | Mshta | Malicious MSHTA Execution | Windows | High | ✅ | ✅ | ✅ | ✅ |
| T1027.001 | Binary Padding | Obfuscated Script Execution Detected | Windows | Medium | ✅ | ✅ | ✅ | ✅ |
| T1070.001 | Clear Windows Event Logs | Windows Event Log Cleared | Windows | Critical | ✅ | ✅ | ✅ | ✅ |

---

### TA0006 — Credential Access

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1003.001 | LSASS Memory | LSASS Memory Dump Attempt | Windows | Critical | ✅ | ✅ | ✅ | ✅ |
| T1003.008 | /etc/passwd and /etc/shadow | /etc/passwd or /etc/shadow Read | Linux | High | ✅ | ✅ | ✅ | ❌ |
| T1110.001 | Password Guessing | SSH Brute Force, Multiple Failed Logins | Linux | Medium | ✅ | ✅ | ✅ | ❌ |
| T1110.003 | Password Spraying | Windows Password Spray Detection | Windows | High | ✅ | ✅ | ✅ | ✅ |

---

### TA0008 — Lateral Movement

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1550.002 | Pass the Hash | Pass-the-Hash Lateral Movement | Windows | Critical | ✅ | ✅ | ✅ | ✅ |
| T1021.001 | Remote Desktop Protocol | Unusual RDP Login from New Source IP | Windows | Medium | ✅ | ✅ | ✅ | ✅ |
| T1021.004 | SSH | SSH Lateral Movement Between Internal Hosts | Linux | High | ✅ | ✅ | ✅ | ❌ |

---

### TA0011 — Command and Control

| Technique ID | Technique Name | Rule Name | Platform | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|---|---|
| T1571 | Non-Standard Port | Outbound Traffic on Uncommon Port | Linux / Windows | Medium | ✅ | ✅ | ✅ | ✅ |
| T1059.004 | Unix Shell | Reverse Shell Callback Detected | Linux | Critical | ✅ | ✅ | ✅ | ❌ |

---

## Coverage Gaps (Planned)

The following high-priority techniques are **not yet covered** and are on the roadmap:

| Technique ID | Technique Name | Tactic | Priority |
|---|---|---|---|
| T1071.001 | Web Protocols (C2 over HTTP/S) | Command & Control | High |
| T1105 | Ingress Tool Transfer | Command & Control | High |
| T1562.001 | Disable or Modify Tools | Defense Evasion | High |
| T1036.005 | Match Legitimate Name or Location | Defense Evasion | Medium |
| T1087.001 | Local Account Discovery | Discovery | Medium |
| T1057 | Process Discovery | Discovery | Medium |
| T1018 | Remote System Discovery | Discovery | Medium |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | High |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | High |

---

## Severity Reference

| Level | Definition |
|---|---|
| **Critical** | Immediate response required — direct evidence of active attack or data breach risk |
| **High** | Strong indicator of compromise — investigate within 1 hour |
| **Medium** | Suspicious activity — investigate within 4 hours; may be legitimate with context |
| **Low** | Informational or low-confidence signal — review during normal triage |

---

## How to Read This Matrix

- ✅ **Available**:  Rule exists and is tested for this SIEM
- ❌ **Not Available**: Rule not yet translated for this SIEM (contributions welcome)
- **Sentinel column** only applies to Windows-origin log sources (Azure/Defender)
- Rules marked **Critical** should be treated as high-fidelity and trigger immediate SOC triage

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Sigma Rule Format](https://sigmahq.io/)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
- [Microsoft Sentinel Analytics Rules](https://docs.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)

---

*This matrix is maintained alongside the rule files. When a new rule is added to any platform folder, this file must be updated to reflect the new coverage.*