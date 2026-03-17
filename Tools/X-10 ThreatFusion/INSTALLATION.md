# Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Git

---

## Installation Steps

### 1. Clone Repository
```bash
git clone <repo-url>
cd <folder-name>
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
# Copy example environment file
cp .env.example .env
```

Edit `.env` file and add your API keys:
```env
VIRUSTOTAL_API_KEY=your_vt_key_here
SHODAN_API_KEY=your_shodan_key_here
OTX_API_KEY=your_otx_key_here
IPINFO_API_KEY=your_ipinfo_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
URLSCAN_API_KEY=your_urlscan_key_here
GETIPINTEL_EMAIL=your_email_here
IP_DETECTIVE_API_KEY=your_ipdetective_key_here
URLHAUS_API_KEY=your_urlhaus_key_here
HUNTER_API_KEY=your_hunter_key_here
MALWARE_BAZAAR_API_KEY=your_malwarebazaar_key_here
THREATFOX_API_KEY=your_threatfox_key_here
YARAIFY_API_KEY=your_yaraify_key_here

```

### 4. Launch Application
```bash
streamlit run app.py
```

### 5. Access Platform

Open browser at: `http://localhost:8501`

---

## Usage

### Analyze Observable (IP/Domain/Hash)

1. Select **"Observable (IP/Domain/Hash)"** input type
2. Enter indicator (e.g., `8.8.8.8`, `example.com`, hash)
3. Select intelligence sources to query
4. Click **"Analyze"**
5. View correlated results

### Track Ransomware Group

1. Select **"Threat Group"** input type
2. Enter group name (e.g., `LockBit`, `BlackCat`)
3. Click **"Analyze"**
4. View group intelligence + victim domain analysis

### Batch Processing

1. Select **"Batch Mode"**
2. Upload file or paste indicators (one per line)
3. Select sources
4. Click **"Analyze Batch"**
5. Export results (JSON/TXT)

---
