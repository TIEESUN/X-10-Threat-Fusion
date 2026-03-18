# X-10 ThreatFusion

**Intelligence Command Platform** &nbsp;|&nbsp; 16 Sources. Total Control.

<img width="1536" height="672" alt="fusion" src="https://github.com/user-attachments/assets/581de173-d6ac-4c63-8b3c-98d57f7b88cb" />

![Python](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)
![Streamlit](https://img.shields.io/badge/streamlit-1.31.1-orange?style=flat-square)
![License](https://img.shields.io/badge/license-not%20specified-lightgrey?style=flat-square)
![Last Commit](https://img.shields.io/github/last-commit/user/x10-threatfusion?style=flat-square)
![Stars](https://img.shields.io/github/stars/user/x10-threatfusion?style=flat-square)

X-10 ThreatFusion is a modular, enterprise-grade threat intelligence platform built on Streamlit and Python, enabling centralized correlation and investigation across multi-source CTI feeds. It helps you analyze and contextualize observables and ransomware groups by aggregating data from VirusTotal, Shodan, AlienVault OTX, IPInfo, AbuseIPDB, URLhaus, URLscan, IP Detective, GetIPIntel, Ransomware.live, Hunter.io, Malware Bazaar, ThreatFox, YARAify, SSLBL, and Feodo Tracker.

---

## Table of Contents

- [Features](#features)
- [Supported Intelligence Sources](#supported-intelligence-sources)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Use Cases](#use-cases)
- [Project Structure](#project-structure)
- [Screenshots](#screenshots)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| Multi-source CTI | Query and correlate 16 intelligence sources simultaneously from a single interface |
| Observable types | IP addresses, domains, URLs, file hashes (MD5 / SHA1 / SHA256), email addresses, ransomware groups |
| Batch mode | Upload a TXT or CSV file, validate indicators, and run bulk enrichment across all enabled sources |
| Ransomware two-phase analysis | Group intelligence query → victim extraction → victim domain correlation via Ransomware.live |
| Threat scoring | Unified scoring engine aggregating malicious and suspicious counts with heuristic weighting across sources |
| Export | JSON and plain-text export for individual indicators and full batch runs |
| Streamlit dashboard | Tabbed layout, per-source detail panes, metrics cards, and sidebar service status |
| Config-driven activation | API keys loaded from `.env` with automatic service enable/disable and key masking in UI |
| CSV-based feed support | SSLBL and Feodo Tracker local cache with automated refresh on stale data |

---

## Supported Intelligence Sources

| Source | Auth | What it provides |
|---|---|---|
| VirusTotal | API key | IP / domain / URL / hash reputation, detection ratios, categories, ASN, country |
| Shodan | API key | Host fingerprint, open ports, services, geolocation, ISP, OS, honeyscore |
| AlienVault OTX | API key | Reputation, threat pulses, geolocation, passive DNS, WHOIS, HTTP scans |
| IPInfo | API key | Geolocation, ASN, organisation, hostname, privacy flags |
| AbuseIPDB | API key | Abuse confidence score, usage type, report count, whitelist status |
| URLhaus | API key | URL and domain malware status, threat classification, tags, associated URL list |
| URLscan | API key | URL / domain / IP scan results, threat verdicts, scan history |
| IP Detective | API key | Bot, VPN, and proxy detection; threat level, ASN, country |
| GetIPIntel | Contact email | Proxy and VPN probability score, threat labels (critical / high / medium / low) |
| Ransomware.live | Public (key optional) | Group metadata, victim count, victim domain correlation |
| Hunter.io | API key | Domain email discovery, company info, email verification and enrichment |
| Malware Bazaar | API key | Hash, tag, and signature lookup; sample metadata, YARA rules |
| ThreatFox | API key | IOC search across domain / IP / URL / hash, malware family, confidence score |
| YARAify | API key | Hash lookup, YARA rule hits, malware detection metadata, file characteristics |
| SSLBL | None | SSL certificate, IP, and JA3 fingerprint blacklist from abuse.ch feeds |
| Feodo Tracker | None | Botnet C2 IP blocklist lookup across multiple block tiers |

---

## Installation

**Requirements:** Python 3.11 or higher

```bash
# Clone the repository
git clone https://github.com/user/x10-threatfusion.git
cd x10-threatfusion

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

Copy the example environment file and populate your API keys:

```bash
copy .env.example .env
```

Open `.env` and fill in the keys for the services you want to activate. Services with missing or empty keys are automatically disabled in the UI.

```env
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
OTX_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
URLHAUS_API_KEY=your_key_here
IPDETECTIVE_API_KEY=your_key_here
GETIPINTEL_CONTACT=your_email_here
RANSOMWARE_LIVE_API_KEY=your_key_here   # optional
HUNTER_API_KEY=your_key_here
MALWARE_BAZAAR_API_KEY=your_key_here
THREATFOX_API_KEY=your_key_here
YARAIFY_API_KEY=your_key_here
# SSLBL and Feodo Tracker require no keys
```

### API Key Reference

| Environment Variable | Service | Free Tier | Registration |
|---|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal | Yes (limited) | https://www.virustotal.com/gui/settings/api |
| `SHODAN_API_KEY` | Shodan | Yes (limited) | https://shodan.io |
| `OTX_API_KEY` | AlienVault OTX | Yes | https://otx.alienvault.com |
| `IPINFO_API_KEY` | IPInfo | Yes | https://ipinfo.io |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Yes | https://www.abuseipdb.com |
| `URLSCAN_API_KEY` | URLscan | Yes | https://urlscan.io |
| `URLHAUS_API_KEY` | URLhaus | Yes | https://urlhaus.abuse.ch |
| `IPDETECTIVE_API_KEY` | IP Detective | Yes | https://www.ipdetective.io |
| `GETIPINTEL_CONTACT` | GetIPIntel | Yes | http://check.getipintel.net |
| `RANSOMWARE_LIVE_API_KEY` | Ransomware.live | Optional | https://my.ransomware.live |
| `HUNTER_API_KEY` | Hunter.io | Yes | https://hunter.io |
| `MALWARE_BAZAAR_API_KEY` | Malware Bazaar | Free | https://auth.abuse.ch |
| `THREATFOX_API_KEY` | ThreatFox | Yes | https://threatfox.abuse.ch |
| `YARAIFY_API_KEY` | YARAify | Yes | https://yaraify.abuse.ch |

---

## Quick Start

```bash
streamlit run app.py
```

Navigate to `http://localhost:8501` in your browser.

---

## Usage

### Single Indicator Analysis

1. Select **Single Indicator** mode from the sidebar.
2. Enter an observable — IP address, domain, URL, file hash, or email address.
3. Select the intelligence sources to query (one or all sixteen).
4. Click **Analyze**.
5. Review the summary metrics and drill into per-source tabs for full detail.
6. Export results as JSON or plain text.

### Ransomware Group Two-Phase Analysis

This mode runs a two-stage correlation: group-level intelligence first, then victim domain follow-up.

1. Select **Single Indicator** mode and choose **Threat Group** as the indicator type.
2. Enter a ransomware group name (e.g. `lockbit`, `blackcat`).
3. Run the analysis. Ransomware.live returns group metadata and a list of known victims.
4. Victim domains are automatically extracted and re-queried across all enabled sources.
5. Review the correlated multi-source report and export the combined output.

### Batch Processing

1. Select **Batch Analysis** mode.
2. Upload a `.txt` or `.csv` file containing one observable per line.
3. Indicators are validated and deduplicated automatically.
4. Select sources and run. Results are aggregated per indicator.
5. Download the full batch report in JSON or plain text.

---

## Use Cases

| Use Case | Input | Recommended Sources |
|---|---|---|
| Incident response | IP, domain, URL, hash | VirusTotal, Shodan, OTX, AbuseIPDB, IPInfo |
| IOC validation | Single or batch observables | VirusTotal, ThreatFox, Malware Bazaar, URLhaus, SSLBL, Feodo Tracker |
| Ransomware tracking | Group name + victim domains | Ransomware.live, OTX, VirusTotal, URLscan, ThreatFox |
| OSINT investigation | Domain, email, IP | Hunter.io, OTX, URLscan, IPInfo, Shodan |
| Bulk enrichment | CSV or TXT indicator list | All enabled sources + GetIPIntel + SSLBL + Feodo Tracker |
| Malware sample triage | File hash | Malware Bazaar, YARAify, VirusTotal, ThreatFox |
| Infrastructure analysis | IP or domain | Shodan, IPInfo, IP Detective, GetIPIntel, SSLBL, Feodo Tracker |

---

## Project Structure

```
x10-threatfusion/
├── app.py                  # Main Streamlit application and UI entrypoint
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template for API keys
├── apis/                   # Modular API client classes (one per intelligence source)
│   ├── virustotal.py
│   ├── shodan.py
│   ├── otx.py
│   ├── ipinfo.py
│   ├── abuseipdb.py
│   ├── urlhaus.py
│   ├── urlscan.py
│   ├── ipdetective.py
│   ├── getipintel.py
│   ├── ransomware_live.py
│   ├── hunter.py
│   ├── malware_bazaar.py
│   ├── threatfox.py
│   ├── yaraify.py
│   ├── sslbl.py
│   └── feodo.py
└── utils/                  # Data processing and helper modules
    ├── scoring.py          # Unified threat scoring logic
    ├── export.py           # JSON and TXT export handlers
    └── validators.py       # Observable type detection and input validation
```

---

## Screenshots

### Main Dashboard

<img width="1353" height="569" alt="image" src="https://github.com/user-attachments/assets/d23d0ecf-16fe-4c25-8993-6f67ccbfe470" />

### Single Indicator Analysis

<img width="1042" height="486" alt="image" src="https://github.com/user-attachments/assets/43cfbbbd-281b-4495-8688-c5f1e0f4703f" />
<img width="1011" height="543" alt="image" src="https://github.com/user-attachments/assets/ec1735d1-95de-4123-897d-fd58ae3a4448" />

### Ransomware Group Tracking

<img width="1025" height="544" alt="image" src="https://github.com/user-attachments/assets/d101fdfd-3c82-4557-9fdc-e20007d5ec0b" />
<img width="1033" height="567" alt="image" src="https://github.com/user-attachments/assets/68a751ed-7cb7-496d-a083-38d82dee7fd1" />

### Batch Processing

<img width="1027" height="568" alt="image" src="https://github.com/user-attachments/assets/4549599a-ec5c-4f39-9b5c-440193f3e616" />
<img width="876" height="547" alt="image" src="https://github.com/user-attachments/assets/fa488206-abf5-4a8b-8389-1371ae3db3e5" />
<img width="1060" height="378" alt="image" src="https://github.com/user-attachments/assets/efa2903d-7ebb-40fc-a0fa-c5397b704cf2" />
<img width="1022" height="539" alt="image" src="https://github.com/user-attachments/assets/67c2bd55-09be-44c8-96f3-2bcc79f1fc7e" />
<img width="1065" height="545" alt="image" src="https://github.com/user-attachments/assets/ed9c93d7-f34a-48a6-86c5-264fbfb29174" />
<img width="964" height="467" alt="image" src="https://github.com/user-attachments/assets/253d13d7-ac74-44ff-9dd6-4f1c4ef4347a" />
<img width="936" height="450" alt="image" src="https://github.com/user-attachments/assets/58c0e632-d350-4b20-a55f-959f78ef3bea" />


### Export

<img width="856" height="164" alt="image" src="https://github.com/user-attachments/assets/adccaf5d-8281-471d-afe1-9dd7256d0fb2" />
<img width="687" height="662" alt="image" src="https://github.com/user-attachments/assets/501713c6-ea95-466d-89b9-6a0e2f19c16f" />

---

*Command your intelligence. Dominate the threat landscape.*



