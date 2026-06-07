# YARA Detection Rules

A collection of YARA rules for malware detection and threat hunting, covering ransomware, webshells, persistence mechanisms, and command & control indicators.

## 📋 Overview

This repository contains detection rules organized by threat category, mapped to MITRE ATT&CK tactics and techniques. Each rule is thoroughly documented with:
- Logic explanation
- Strings and patterns detected
- MITRE ATT&CK mapping
- Usage examples
- Real-world samples (where applicable)

## 📁 Repository Structure

```
yara-detection-rules/
├── rules/
│   ├── ransomware/          # Ransomware behavior detection
│   ├── webshells/           # Web shell detection (PHP, ASP, JSP)
│   ├── persistence/         # Persistence mechanism detection
│   ├── command_control/     # C2 and lateral movement detection
│   └── README.md            # Rules documentation index
├── docs/
│   ├── INSTALLATION.md      # YARA installation guide
│   ├── USAGE.md             # How to run and test rules
│   └── MITRE_MAPPING.md     # MITRE ATT&CK reference
├── samples/                 # Malware samples for testing (if applicable)
├── .gitignore
├── LICENSE
└── README.md                # This file
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/leonardosmoutinho/yara-detection-rules.git
cd yara-detection-rules

# Install YARA (Ubuntu/Debian)
sudo apt-get install yara

# Install YARA (macOS)
brew install yara
```

### Run All Rules

```bash
# Scan a file
yara -r rules/ /path/to/file

# Scan a directory recursively
yara -r rules/ /path/to/directory/

# Generate results in JSON format
yara -r rules/ -f json /path/to/target > results.json
```

### Run Specific Category

```bash
# Scan for ransomware
yara -r rules/ransomware/ /path/to/file

# Scan for webshells
yara -r rules/webshells/ /path/to/directory/
```

## 📊 Rule Categories

### 1. **Ransomware Detection** (`rules/ransomware/`)
Detects common ransomware behaviors:
- File encryption patterns
- Registry modifications
- Ransom note creation
- Process termination (anti-forensics)

**MITRE ATT&CK Mappings:**
- T1486 - Data Encrypted for Impact
- T1565 - Data Manipulation
- T1490 - Inhibit System Recovery

### 2. **Webshell Detection** (`rules/webshells/`)
Identifies web-based shells:
- PHP shells (common shells, obfuscation patterns)
- ASP.NET shells
- JSP shells
- Cold Fusion shells

**MITRE ATT&CK Mappings:**
- T1190 - Exploit Public-Facing Application
- T1505 - Server Software Component
- T1569 - Service Execution

### 3. **Persistence Mechanisms** (`rules/persistence/`)
Detects installation and persistence techniques:
- Scheduled tasks
- Registry Run keys
- Startup folder modifications
- WMI event subscriptions
- Cron jobs (Linux)

**MITRE ATT&CK Mappings:**
- T1547 - Boot or Logon Autostart Execution
- T1053 - Scheduled Task/Job
- T1546 - Event Triggered Execution

### 4. **Command & Control** (`rules/command_control/`)
Identifies C2 communication and lateral movement:
- Known C2 frameworks (Cobalt Strike, Mimikatz)
- Beacon traffic patterns
- DNS tunneling indicators
- Dynamic DNS services

**MITRE ATT&CK Mappings:**
- T1071 - Application Layer Protocol
- T1008 - Fallback Channels
- T1573 - Encrypted Channel

## 🔍 Rule Writing Standards

Each rule follows this format:

```yara
rule RuleName {
    meta:
        description = "What this rule detects"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1234 - Technique Name"
        severity = "high"
    
    strings:
        $str1 = "pattern" nocase
        $hex1 = { 4D 5A 90 00 }
        $re1 = /regex_pattern/i
    
    condition:
        all of them
}
```

## 🧪 Testing Rules

```bash
# Dry run (show what would match without modifying)
yara -r rules/ -s /path/to/test/file

# Match only (show rule names that match)
yara -r rules/ -m /path/to/test/file

# Print matched strings
yara -r rules/ -s /path/to/test/file
```

## 📈 Validation

All rules have been tested against:
- Benign system files (false positive testing)
- Known malware samples (true positive testing)
- Live production environments

## 🤝 Contributing

Contributions welcome! When submitting:
1. Follow the rule writing standards
2. Include MITRE ATT&CK mappings
3. Test against benign files for false positives
4. Document the rule logic clearly
5. Include detection rationale

## 📚 Resources

- [YARA Documentation](https://yara.readthedocs.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [VirusTotal YARA Rules](https://github.com/VirusTotal/yara-rules)
- [Florian Roth's YARA Rules](https://github.com/Neo23x0/signature-base)

## ⚖️ License

MIT License - See LICENSE file for details

## 👤 Author

**Leonardo da Silveira Moutinho**
- LinkedIn: [linkedin.com/in/leonardomoutinho](https://linkedin.com/in/leonardomoutinho)
- GitHub: [github.com/leonardosmoutinho](https://github.com/leonardosmoutinho)
- Aspiring SOC Analyst | Security+ | Network+ | SC-900

---

**Last Updated:** June 2026  
**Total Rules:** [Will be updated as rules are added]
