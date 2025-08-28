
# OTSec — Offensive OT/IoT Security Toolkit

**OTSec** is a professional-grade toolkit designed for offensive security testing and auditing of OT (Operational Technology) and IoT (Internet of Things) environments. It enables red teamers, security researchers, and industrial penetration testers to interact with and assess real-world OT/ICS/IoT networks in a safe and modular manner.

---

## 🧭 Introduction

Operational Technology systems power critical infrastructure like factories, smart buildings, utilities, and transport systems. Many of these systems rely on insecure-by-design protocols and legacy devices with minimal authentication, leaving them vulnerable to attacks.

**OTSec** is a Python-based toolkit built to bridge the gap between offensive security needs and OT protocol understanding. It gives professionals a modular, scriptable, and extensible interface for scanning, fingerprinting, and manipulating OT/IoT protocols like Modbus, BACnet, MQTT, and more.

OTSec is suitable for:

- Industrial penetration tests
- Smart building assessments
- Red team infrastructure compromise
- Embedded system testing
- OT/IoT protocol experimentation

---

## 🚀 Features

| Feature               | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| Device Discovery       | Perform fast discovery of OT/IoT devices using active fingerprinting        |
| Protocol Detection     | Identify exposed services and protocols (Modbus, MQTT, BACnet, RTSP, etc.) |
| Vulnerability Mapping  | Match banners with known CVEs or risky patterns                            |
| Packet Injection       | Send custom Modbus packets to simulate attacks (lab safe only)             |
| Auth & Config Checks   | Discover default credentials and legacy services                           |
| Interactive Shell      | Use the OTSec command shell for quick commands & module chaining           |
| YAML-Based DB          | Customizable vulnerability and protocol hints DB                           |
| Screenshot Friendly    | Color-coded output and banners for clear visual representation             |

---

## 📦 Installation

### Recommended (Simple Usage)

```bash
git clone https://github.com/omar-tamerr/OTSec
cd OTSec
pip install -r requirements.txt
python3 run_otsec.py shell
```

> ✅ No virtual environment needed — just install requirements and start the tool.

---

## 🔧 Usage

### Start the Shell

```bash
python3 run_otsec.py shell
```

### Run a Safe Scan

```bash
python3 run_otsec.py scan 192.168.1.0/24 --safe
```

### Read Modbus Registers

```bash
python3 run_otsec.py modbus-read --host 192.168.1.50 --start 0 --count 5
```

### Inject Modbus Command (lab use only)

```bash
python3 run_otsec.py inject --host 192.168.1.50 --function write_single_register --address 1 --value 1234
```

---

## 🖼️ Screenshots (With Descriptions)

### 1. Interactive Shell Launch
![Shell Launch](src/otsec/img/normal-tool.png)  
The entry point into the interactive mode of OTSec. Commands like `scan`, `inject`, or `modbus-read` can be typed here.

### 2. Help Page
![Help Page](src/otsec/img/help-page.png)  
Full command help with descriptions and parameters.

### 3. Modbus Read
![Modbus Read](src/otsec/img/modbus-read.png)  
Reads Modbus holding registers from an OT device.

### 4. Inject Modbus (Lab Safe)
![Inject Modbus](src/otsec/img/inject-modbus.png)  
Sends custom Modbus write operations (safe in lab only).

### 5. Safe Scan
![Safe Scan](src/otsec/img/safe-scan.png)  
Performs TCP banner grabbing to identify OT/IoT protocols safely.

### 6. Vulnerability Scan
![Vuln Scan](src/otsec/img/vuln-scan.png)  
Matches banners with known CVEs and weak configurations.

### 7. Info Pages
![Info Page 1](src/otsec/img/info-page1.png)  
Quick protocol hints and threat intelligence built into the shell.

---

## 📁 Directory Structure

```
src/
├── otsec/
│   ├── cli.py            # CLI entry point
│   ├── core/             # Scanning, injection, shell modules
│   ├── data/vulns.yaml   # Fingerprints and CVEs
│   └── img/              # Screenshots and documentation visuals
run_otsec.py              # Unified entry point script
requirements.txt          # Required packages
```

---

## 📄 License

All rights reserved © Omar Tamer  
This software is intended for authorized testing, training, and research only.

---

## 🌐 Author

- **Name**: Omar Tamer  
- **Title**: Offensive Security Researcher | ICS/IoT Pentester  
- **Website**: [omar-tamerr.github.io](https://omar-tamerr.github.io)  
- **LinkedIn**: [linkedin.com/in/omar-tamer](https://www.linkedin.com/in/omar-tamer-1a986b2a7)  
- **YouTube**: [OTSec Channel](https://www.youtube.com/@OTSec)  
- **GitHub**: [github.com/omar-tamerr](https://github.com/omar-tamerr)  
- **Contact**: Available on website or via LinkedIn

