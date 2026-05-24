# 🛡️ Blue Team Detection Rules

> Production-grade detection rules for Linux and Windows — with translations for Elastic SIEM, Splunk, Microsoft Sentinel, and more. MITRE ATT&CK mapped.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-red)](https://attack.mitre.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)]()
[![SIEM](https://img.shields.io/badge/SIEM-Elastic%20%7C%20Splunk%20%7C%20Sentinel-purple)]()
[![Maintained](https://img.shields.io/badge/Maintained-Yes-green)]()

---

## 📖 About

This repository is a structured library of **production-ready detection rules**, built for real SOC environments. Rules are organized by OS platform and translated across major SIEM platforms so you can drop them into your environment without starting from scratch.

Each rule is:
- **MITRE ATT&CK mapped** — Tactic, Technique, and Sub-technique referenced
- **Platform-specific** — Tested against Linux and Windows log sources
- **Multi-SIEM** — Available in Sigma (vendor-agnostic), Elastic EQL/KQL, Splunk SPL, and Microsoft Sentinel KQL
- **Documented** — Every rule includes a description, log source, severity, false positive guidance, and response notes

Built by a Blue Teamer, for Blue Teamers.

---

## 📁 Repository Structure

```
detection-rules/
│
├── linux/
│   ├── sigma/              # Vendor-agnostic Sigma format (.yml)
│   ├── elastic/            # EQL / KQL for Elastic SIEM
│   └── splunk/             # SPL queries
│
├── windows/
│   ├── sigma/              # Vendor-agnostic Sigma format (.yml)
│   ├── elastic/            # EQL / KQL for Elastic SIEM
│   ├── splunk/             # SPL queries
│   └── sentinel/           # KQL for Microsoft Sentinel
│
├── mappings/
│   └── mitre-coverage.md   # MITRE ATT&CK coverage matrix
│
├── docs/
│   ├── rule-template.md    # Standard rule writing template
│   ├── contributing.md     # Contribution guidelines
│   └── log-sources.md      # Supported log sources reference
│
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/rehmanwaraich07/detection-rules.git
cd detection-rules
```

### 2. Navigate to your platform and SIEM

```bash
# Example: Windows rules for Microsoft Sentinel
cd windows/sentinel/

# Example: Linux rules in Sigma format
cd linux/sigma/
```

### 3. Import into your SIEM

Each rule file contains the query and a header comment block with full metadata. Copy the query directly into your SIEM's detection or alert rule editor.

---

## 🔍 Rule Format

Every rule follows this standard structure regardless of SIEM format:

```yaml
# -----------------------------------------------------------
# Rule Name     : Suspicious PowerShell Encoded Command
# Platform      : Windows
# SIEM          : Microsoft Sentinel (KQL)
# MITRE Tactic  : Execution
# MITRE Tech    : T1059.001 - PowerShell
# Severity      : High
# Log Source    : Microsoft-Windows-PowerShell/Operational
# Author        : Misbah (Cyber with Misbah)
# Last Updated  : 2025-01-01
# Description   : Detects PowerShell processes launched with Base64
#                 encoded commands, commonly used for defense evasion
#                 and payload delivery.
# False Positives: Some legitimate admin scripts, software installers
# Response Notes: Investigate parent process, decode the Base64 
#                 payload, check for lateral movement indicators.
# -----------------------------------------------------------

SecurityEvent
| where EventID == 4688
| where ProcessCommandLine has "-EncodedCommand"
    or ProcessCommandLine has "-enc"
    or ProcessCommandLine has "-ec"
| project TimeGenerated, Computer, Account, ProcessName, ProcessCommandLine
| order by TimeGenerated desc
```

---

## 🗂️ Coverage by Platform

### 🐧 Linux

| Rule Name | MITRE Technique | Severity | Sigma | Elastic | Splunk |
|---|---|---|---|---|---|
| Sudo Privilege Escalation Attempt | T1548.003 | High | ✅ | ✅ | ✅ |
| SSH Brute Force — Multiple Failed Logins | T1110.001 | Medium | ✅ | ✅ | ✅ |
| Crontab Modification by Non-Root User | T1053.003 | Medium | ✅ | ✅ | ✅ |
| Reverse Shell via Bash | T1059.004 | Critical | ✅ | ✅ | ✅ |
| /etc/passwd or /etc/shadow Read | T1003.008 | High | ✅ | ✅ | ✅ |
| SUID Binary Execution | T1548.001 | High | ✅ | ✅ | ✅ |

### 🪟 Windows

| Rule Name | MITRE Technique | Severity | Sigma | Elastic | Splunk | Sentinel |
|---|---|---|---|---|---|---|
| PowerShell Encoded Command Execution | T1059.001 | High | ✅ | ✅ | ✅ | ✅ |
| LSASS Memory Dump Attempt | T1003.001 | Critical | ✅ | ✅ | ✅ | ✅ |
| Suspicious Scheduled Task Creation | T1053.005 | Medium | ✅ | ✅ | ✅ | ✅ |
| Pass-the-Hash Lateral Movement | T1550.002 | Critical | ✅ | ✅ | ✅ | ✅ |
| Malicious MSHTA Execution | T1218.005 | High | ✅ | ✅ | ✅ | ✅ |
| Registry Run Key Persistence | T1547.001 | Medium | ✅ | ✅ | ✅ | ✅ |

> **Note:** More rules are added continuously. Check each platform folder for the full and most current list.

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|---|---|
| Initial Access | T1078, T1190, T1566 |
| Execution | T1059.001, T1059.004, T1053 |
| Persistence | T1547.001, T1053.003, T1053.005 |
| Privilege Escalation | T1548.001, T1548.003 |
| Defense Evasion | T1218.005, T1027 |
| Credential Access | T1003.001, T1003.008, T1110.001 |
| Lateral Movement | T1550.002, T1021 |
| Command & Control | T1571, T1059.004 |

Full coverage matrix: [`mappings/mitre-coverage.md`](mappings/mitre-coverage.md)

---

## 🛠️ Supported Log Sources

| Platform | Log Sources |
|---|---|
| Linux | `/var/log/auth.log`, `/var/log/syslog`, auditd, journald, bash history |
| Windows | Security Event Log (4624, 4625, 4688, 4698, 4720), PowerShell logs, Sysmon |
| Elastic | Filebeat, Winlogbeat, Auditbeat, Elastic Agent |
| Splunk | Splunk Universal Forwarder, Windows TA, Linux TA |
| Microsoft Sentinel | Microsoft Defender for Endpoint, Azure AD, Security Events |

---

## 📌 Roadmap

- [x] Linux — Initial rule set (Sigma, Elastic, Splunk)
- [x] Windows — Initial rule set (Sigma, Elastic, Splunk, Sentinel)
- [ ] Windows Defender for Endpoint (MDE) KQL rules
- [ ] Azure AD / Entra ID rules
- [ ] Wazuh rule translations
- [ ] MITRE ATT&CK Navigator layer export (`.json`)
- [ ] Automated Sigma → SIEM conversion pipeline
- [ ] CI/CD validation for rule syntax on push

---

## 🤝 Contributing

Contributions are welcome. If you have a detection rule to add or an improvement to an existing one:

1. Fork the repository
2. Create a new branch (`git checkout -b rule/your-rule-name`)
3. Follow the rule template in [`docs/rule-template.md`](docs/rule-template.md)
4. Submit a pull request with a clear description

Please ensure all rules include MITRE ATT&CK mapping, a description, and false positive guidance before submitting.

See [`docs/contributing.md`](docs/contributing.md) for full guidelines.

---

## 👤 Author

**Misbah** — SOC Analyst | Detection Engineer | Blue Team Content Creator

- 🌐 Portfolio: [defendwithmisbah.vercel.app](https://defendwithmisbah.vercel.app)
- 💼 LinkedIn: [linkedin.com/in/rehmanwaraich07](https://linkedin.com/in/rehmanwaraich07)
- ✍️ Medium: [medium.com/@rehmanwaraich107](https://medium.com/@rehmanwaraich107)
- 🐙 GitHub: [github.com/rehmanwaraich07](https://github.com/rehmanwaraich07)
- 📺 YouTube: [Cyber with Misbah](https://youtube.com/@cyberwithmisbah)

---

## 📜 License

This project is licensed under the [MIT License](LICENSE). You are free to use, adapt, and share these rules — attribution appreciated.

---

## ⭐ Support

If this repository helped you detect something in your environment or saved you time building detections, consider giving it a star. It helps others in the community find it.

---

*"Detection is not about collecting logs. It's about knowing what to look for."*