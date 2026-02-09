# 🔒 ShadowIT Detector

A high-fidelity, network-based unauthorized SaaS detection tool that passively monitors network traffic to identify Shadow IT usage via DNS queries and TLS SNI (Server Name Indication) fields.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Proof%20of%20Concept-orange.svg)

---

## 📋 Overview

ShadowIT Detector is a cybersecurity proof-of-concept tool designed to help corporate security teams identify unauthorized SaaS application usage on their networks without requiring invasive agent installations on every endpoint.

### Key Features

- **Passive Network Monitoring**: Captures DNS and TLS traffic without endpoint agents
- **Real-time Detection**: Identifies unauthorized services as they are accessed
- **Risk Scoring**: Assigns risk scores (1-10) based on service categories
- **Beautiful Dashboard**: Rich terminal UI with live event tracking
- **Comprehensive Database**: Pre-configured with 50+ unauthorized services

---

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+** installed
2. **TShark/Wireshark** installed on the system
3. **Root/Administrator privileges** (required for packet capture)

### Install TShark

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
```powershell
choco install wireshark
```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Run the Detector

```bash
# Use default network interface
sudo python main.py

# Use specific interface
sudo python main.py -i eth0

# List available interfaces
sudo python main.py --list-interfaces
```

---

## 📊 Risk Scoring System

| Score | Level | Category | Description |
|-------|-------|----------|-------------|
| 9-10 | 🔴 Critical | File Sharing | High data exfiltration risk (Dropbox, Mega, WeTransfer) |
| 6-8 | 🟠 High | Unapproved Chat/Email | Communication risk (Discord, Gmail, Telegram) |
| 4-5 | 🟡 Medium | Unknown | Unclassified services |
| 1-3 | 🟢 Low | Streaming/Social | Productivity risk (YouTube, Netflix, Facebook) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ShadowIT Detector Architecture                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   DNS Path   │    │   TLS Path   │    │   Sanctioned │      │
│  │  (dns.qry)   │    │  (SNI ext)   │    │   Services   │      │
│  └──────┬───────┘    └──────┬───────┘    └──────────────┘      │
│         │                   │                                    │
│         └─────────┬─────────┘                                    │
│                   ▼                                              │
│         ┌──────────────────┐                                    │
│         │ Domain Extractor │                                    │
│         └────────┬─────────┘                                    │
│                  ▼                                               │
│         ┌──────────────────┐                                    │
│         │ Risk Classifier  │                                    │
│         └────────┬─────────┘                                    │
│                  ▼                                               │
│         ┌──────────────────┐                                    │
│         │  Alert Engine    │                                    │
│         └────────┬─────────┘                                    │
│                  ▼                                               │
│         ┌──────────────────┐                                    │
│         │    Dashboard     │                                    │
│         └──────────────────┘                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
shadowit_detector/
├── main.py              # Main application entry point
├── requirements.txt     # Python dependencies
├── README.md           # This file
└── .gitignore          # Git ignore rules
```

---

## ⚙️ Configuration

### Sanctioned Services

Edit `SANCTIONED_SERVICES` dictionary in `main.py` to add your corporate-approved services:

```python
SANCTIONED_SERVICES = {
    "company-email.com": "Corporate Email",
    "internal-jira.io": "Corporate JIRA",
    # Add your services here
}
```

### Unauthorized Services

Add new unauthorized services to `UNAUTHORIZED_SERVICES`:

```python
UNAUTHORIZED_SERVICES = {
    "newservice.com": ("New Service", "File Sharing"),
}
```

### Risk Categories

Modify risk scores in `CATEGORY_RISKS`:

```python
CATEGORY_RISKS = {
    "File Sharing": ServiceCategory(
        name="File Sharing",
        risk_score=9,  # Adjust as needed
        risk_level=RiskLevel.CRITICAL,
        description="High data exfiltration risk"
    ),
}
```

---

## 🖥️ Dashboard Preview

```
╔══════════════════════════════════════════════════════════════════╗
║     🔒 ShadowIT Detector - Network Security Monitoring           ║
╚══════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────┐
│ 🚨 ShadowIT Detection Events                                     │
├──────────┬──────────┬──────────────┬──────────┬────────┬─────────┤
│Timestamp │Source IP │Service       │Category  │Risk    │Method   │
├──────────┼──────────┼──────────────┼──────────┼────────┼─────────┤
│10:23:45  │192.168.1 │Dropbox       │File Share│9/10    │DNS      │
│10:23:12  │192.168.2 │Discord       │Unapproved│6/10    │TLS-SNI  │
│10:22:58  │192.168.3 │Gmail         │Personal  │6/10    │DNS      │
└──────────┴──────────┴──────────────┴──────────┴────────┴─────────┘

┌─────────────────┐  ┌─────────────────┐
│ 📊 Statistics   │  │ ⚠️ Risk Legend  │
├─────────────────┤  ├─────────────────┤
│ Total: 15       │  │ 9-10 = Critical │
│ File Sharing: 5 │  │ 6-8  = High     │
│ Chat: 7         │  │ 4-5  = Medium   │
│ Email: 3        │  │ 1-3  = Low      │
└─────────────────┘  └─────────────────┘
```

---

## 🔧 Troubleshooting

### Permission Denied

```bash
# Make sure you're running with sudo
sudo python main.py
```

### TShark Not Found

```bash
# Verify TShark installation
tshark --version

# If not found, install it:
# Ubuntu/Debian
sudo apt-get install tshark

# macOS
brew install wireshark
```

### No Packets Captured

1. Verify network interface is correct:
   ```bash
   sudo python main.py --list-interfaces
   ```

2. Check if interface has traffic:
   ```bash
   sudo tshark -i eth0 -c 10
   ```

3. Ensure firewall isn't blocking capture

---

## 📜 License

MIT License - See LICENSE file for details.

---

## ⚠️ Disclaimer

This tool is provided as a **Proof of Concept** for educational and authorized security testing purposes only. Always ensure you have proper authorization before monitoring network traffic.

**Use responsibly and in compliance with your organization's security policies and applicable laws.**

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## 📧 Contact

For questions or support, contact the Cybersecurity Engineering Team.
