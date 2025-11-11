# 👻 GhostIDOR v2.5

<div align="center">

![Version](https://img.shields.io/badge/version-2.5-purple)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen)

**Comprehensive IDOR Vulnerability Scanner & Exploitation Framework**

*From Discovery to Exploitation in One Command*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Wiki](../../wiki)

</div>

---

## 📋 Overview

GhostIDOR is an advanced Insecure Direct Object Reference (IDOR) vulnerability scanner and exploitation framework designed for penetration testers, red teams, and bug bounty hunters. It combines intelligent reconnaissance, multi-threaded fuzzing, and automated exploitation into a single powerful tool.

**Developed by Ghost Ops Security**

### What Makes GhostIDOR Different?

- 🧙 **Auto Mode**: Intelligent wizard that handles complete attack chains
- 🎯 **Smart Recon**: Automatically detects encoding patterns and generates exploits
- 🔥 **API Testing**: Comprehensive REST API security testing with role escalation detection
- ⚡ **High-Speed**: Multi-threaded fuzzing with up to 50 concurrent threads
- 🎨 **User-Friendly**: Clear, color-coded output with actionable next steps
- 🔗 **Attack Chaining**: Automatically chains multiple IDOR vulnerabilities

---

## ✨ Features

### Core Capabilities

- **Auto Mode** - Intelligent attack wizard (discovery → analysis → exploitation)
- **Smart Recon** - Pattern detection with automatic encoding chain discovery
- **API IDOR Testing** - Complete REST API security assessment
- **Path Fuzzing** - Test URL paths with custom wordlists
- **Parameter Fuzzing** - Fuzz URL parameters and POST data
- **Multi-Method Testing** - GET, POST, PUT, DELETE, PATCH support
- **JavaScript Analysis** - Extract API endpoints and patterns from JS files
- **JWT Manipulation** - Test JWT-based authentication bypass
- **Encoding Detection** - Auto-detect Base64, MD5, SHA1, SHA256, hex, UUID
- **File Extraction** - Automatically save discovered files
- **Mass Exploitation** - Target multiple users simultaneously

### Advanced Features

- **Role Escalation Detection** - Automatically identifies privilege escalation paths
- **User Enumeration** - Discovers all users via API or path traversal
- **UUID Extraction** - Captures and uses correct UUIDs for exploitation
- **Two-Stage Attacks** - Extract data, then exploit with precision
- **Admin Targeting** - Automatically identifies and targets admin accounts
- **Cookie/Header Support** - Full authentication support
- **Rate Limiting** - Configurable delays to avoid detection
- **Detailed Reporting** - JSON output with curl reproduction commands

---

## 🚀 Installation

### Requirements

- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/ghostidor.git
cd ghostidor

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x ghostidoor_v2.5_API.py

# Verify installation
python3 ghostidoor_v2.5_API.py -h
```

### Dependencies

Create `requirements.txt`:
```
requests>=2.28.0
urllib3>=1.26.0
```

---

## 💻 Usage

### Quick Start

```bash
# Auto mode - complete attack wizard
python3 ghostidoor_v2.5_API.py --auto -u "http://target.com/profile/FUZZ"

# Smart recon for file downloads
python3 ghostidoor_v2.5_API.py --smart-recon -u "http://target.com/download?file=MQ=="

# API security testing
python3 ghostidoor_v2.5_API.py --api-test -u "http://target.com/api/users"
```

For complete usage documentation, see the [Wiki](../../wiki).

---

## 📚 Examples

### Example 1: Auto Mode

```bash
python3 ghostidoor_v2.5_API.py --auto -u "http://api.target.com/users/FUZZ"
```

### Example 2: Smart Recon

```bash
python3 ghostidoor_v2.5_API.py --smart-recon \
  -u "http://target.com/download?contract=MQ%3D%3D" \
  -v
```

### Example 3: API Testing

```bash
python3 ghostidoor_v2.5_API.py --api-test \
  -u "http://target.com/api/profile" \
  -c "role=employee" \
  -v
```

For more examples, see the [Examples Wiki](../../wiki/Examples).

---

## 🛡️ Responsible Use

This tool is intended for authorized penetration testing, bug bounty hunting, and security research only.

**Always get written permission before testing any system.**

---

## 📖 Documentation

Full documentation available in the [Wiki](../../wiki):

- [Getting Started](../../wiki/Getting-Started)
- [Auto Mode Guide](../../wiki/Auto-Mode)
- [Smart Recon Guide](../../wiki/Smart-Recon)
- [API Testing Guide](../../wiki/API-Testing)
- [Troubleshooting](../../wiki/Troubleshooting)

---

## 📝 Changelog

### v2.5
- ✨ Auto Mode wizard
- ✨ Enhanced Smart Recon
- ✨ Comprehensive API testing
- ✨ UUID-aware exploitation

---

## 👤 Author

**Ghost Ops Security** - Veteran-Owned Penetration Testing Company

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file

---

<div align="center">

**Made with 👻 by Ghost Ops Security**

⭐ Star this repo if you find it useful!

</div>
