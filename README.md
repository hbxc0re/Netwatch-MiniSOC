# 🛡️ NetWatch Unified Cybersecurity Mini-SOC (v3.0)

![License](https://img.shields.io/badge/license-MIT-purple.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)

> **Attribution & Acknowledgement:** This project is a containerized, expanded adaptation and modern telemetry enhancement of **[NetWatch](https://github.com/matthart1983/netwatch)**, originally created by **[matthart1983](https://github.com/matthart1983)**.

**NetWatch Unified Mini-SOC** is a containerized Security Operations Center (SOC) dashboard, live honeypot telemetry visualizer, and interactive Blue/Red Team field encyclopedia. Built with **FastAPI**, **TailwindCSS**, and **Leaflet.js**, it integrates side-by-side with **T-Pot Honeypot** sensors (`Cowrie`, `Dionaea`) and open-source threat intelligence feeds.

Coded with the assistance of Gemini Argon mostly to clean up anything that was broken along the way and suggestive changes. 
This was mostly a learning experience and to test the capabilities of Gemini Argon. 

---

## ✨ Core Capabilities

* **🍯 Live T-Pot Honeypot Telemetry & Map HUD:** Real-time visualization of SSH/Telnet (`Cowrie`) and SMB (`Dionaea`) traps with color-coded animated laser trajectories and live HUD counters.
* **⚡ Dual-Engine Real-Time Telemetry:** Combines asynchronous WebSocket streaming with client-side resilience so your live threat feed and map animations never stall.
* **🔬 Deep Packet & Playbook Forensics Modal:** Click any incoming alert row to inspect captured payloads, risk scores, AI Security Copilot triage summaries, and **Tier 1 / Tier 2 / Tier 3 SOC Analyst Playbooks**.
* **📚 Built-In Cybersecurity Encyclopedias:** Searchable reference guides for Blue Team IR, Red Team/OSINT, SANS SEC401 Network Security, MITRE ATT&CK® v16, Sigma Detection Rules, and TLD Risk Intelligence.
* **🔍 Live IOC Reputation Lookup:** Query IPv4 addresses, domains, and file hashes directly from the Threat Intelligence Platform (TIP) tab.

---

## 📂 Repository Structure

```text
netwatch-soc/
├── app.py                   # FastAPI backend, WebSocket broadcaster & IOC lookup API
├── Dockerfile               # Python 3.11-slim container definition
├── docker-compose.yml       # Multi-container orchestration (NetWatch + Cowrie + Dionaea)
├── requirements.txt         # Python dependencies
├── .env.example             # Template for custom coordinates, display IP, and API keys
├── .gitignore               # Excludes secrets, logs, and runtime configs
└── static/
    ├── index.html           # Unified Mini-SOC frontend (TailwindCSS + Leaflet.js)
    ├── kb_data.json         # Blue Team IR Encyclopedia dataset
    ├── rt_data.json         # Red Team & OSINT dataset
    ├── netsec_data.json     # SANS SEC401 Network Security dataset
    ├── mitre_data.json      # MITRE ATT&CK v16 dataset
    ├── sigma_rules.json     # Sigma Detection Engineering dataset
    ├── tld_data.json        # TLD Threat Intelligence dataset
    └── tip_ioc_data.json    # Synchronized Global IOCs dataset
