# ASM-NG Setup SOP — Kali Linux + Tailscale Deployment

> Complete setup guide for deploying ASM-NG on a dedicated Kali Linux VM with
> Tailscale VPN access, all 15 external security tools, and 47+ free API integrations.
>
> **Audience:** Operator standing up a new client VM from scratch.
> **OS Target:** Kali Linux (latest rolling release).
> **Estimated time:** ~60 minutes (excluding API signups).

---

## Table of Contents

- [Part 1 — Kali VM Base Setup](#part-1--kali-vm-base-setup)
- [Part 2 — ASM-NG Installation](#part-2--asm-ng-installation)
- [Part 3 — External Tool Installation (15 Tools)](#part-3--external-tool-installation-15-tools)
- [Part 4 — Free API Account Signup Checklist](#part-4--free-api-account-signup-checklist)
- [Part 5 — Ready-to-Import Configuration Template](#part-5--ready-to-import-configuration-template)
- [Part 6 — Verification Checklist](#part-6--verification-checklist)
- [Appendix A — Systemd Service Unit](#appendix-a--systemd-service-unit)
- [Appendix B — Troubleshooting](#appendix-b--troubleshooting)

---

## Prerequisites

Before you begin, confirm you have:

- [ ] A Kali Linux VM (bare-metal, VMware, VirtualBox, or cloud) with at least 4 GB RAM and 40 GB disk
- [ ] Root / sudo access on the VM
- [ ] Internet connectivity from the VM
- [ ] A Tailscale account at https://login.tailscale.com

---

## Part 1 — Kali VM Base Setup

### 1.1 System Update

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot
```

### 1.2 Install Tailscale (Beacon Node)

Tailscale turns this VM into a persistent, always-reachable node on your private mesh network.

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --ssh
```

Record the Tailscale IP — you will use this to reach ASM-NG remotely:

```bash
tailscale ip -4
# Example output: 100.64.x.y
```

**Enable as a "beacon"** in the Tailscale admin console (https://login.tailscale.com/admin/machines):
1. Find this machine in the list
2. Click the `...` menu → **Edit route settings**
3. Ensure "Allow incoming connections" is on (this is the default)
4. Optionally, disable key expiry so the node stays connected permanently

### 1.3 System Dependencies

```bash
sudo apt install -y \
  python3 python3-pip python3-venv python3-dev \
  git nodejs npm curl wget unzip \
  build-essential libxml2-dev libxslt-dev libffi-dev libssl-dev \
  libjpeg-dev zlib1g-dev swig ruby
```

Verify:

```bash
python3 --version   # Must be 3.9+
node --version
npm --version
git --version
```

> **Kali-specific: PEP 668**
> Kali Linux marks its system Python as "externally managed." You **must** use a
> virtual environment for all pip installs. Never run bare `pip install` outside
> a venv on Kali. This entire SOP uses a venv.

---

## Part 2 — ASM-NG Installation

### 2.1 Clone Repository and Create Virtual Environment

```bash
git clone https://github.com/0x31i/asm-ng.git ~/asm-ng
cd ~/asm-ng
python3 -m venv venv
source venv/bin/activate
```

> From this point forward, **always activate the venv** before running any
> ASM-NG commands: `source ~/asm-ng/venv/bin/activate`

### 2.2 Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

All dependencies (including advanced features such as database monitoring, AI
threat intelligence, and security hardening) are included in the main
`requirements.txt`. No separate install step is needed.

### 2.3 PostgreSQL Database Backend (Automatic)

ASM-NG uses PostgreSQL as its default database backend for better performance,
concurrency, and reliability on production deployments. **On first launch,
ASM-NG will automatically install and configure PostgreSQL** if the following
conditions are met:

- Running on a Debian/Kali Linux system (with `apt-get` available)
- Running as root, or passwordless `sudo` is configured
- PostgreSQL is not already running on localhost:5432

The auto-setup performs these steps automatically:
1. Installs PostgreSQL via `apt-get` (if not already installed)
2. Starts and enables the PostgreSQL service
3. Creates the `admin` user and `asmng` database
4. Configures `pg_hba.conf` for local password authentication

**Default credentials:** `admin:admin` — change after first login!

```bash
sudo -u postgres psql -c "ALTER USER admin PASSWORD 'new_password';"
```

#### Verify PostgreSQL is Active

After first launch, check the logs for:
```
PostgreSQL is now available after auto-setup. Using PostgreSQL backend.
```

If you see `PostgreSQL not available. Using SQLite backend.` instead, check:

```bash
sudo systemctl status postgresql
sudo -u postgres psql -c "SELECT 1;"
```

#### Manual Setup (if auto-setup was skipped)

If auto-setup could not run (e.g., no root access, non-Debian system), you can
set up PostgreSQL manually:

```bash
sudo ./setup-postgresql.sh
```

Or install PostgreSQL yourself and set environment variables:

```bash
export ASMNG_DATABASE_URL="postgresql://user:pass@localhost:5432/asmng"
```

#### Disabling Auto-Setup

To prevent auto-setup from running (e.g., in CI or container environments):

```bash
export ASMNG_PG_AUTO_SETUP=0
```

#### Forcing SQLite

To explicitly use SQLite regardless of PostgreSQL availability:

```bash
export ASMNG_DB_TYPE=sqlite
```

#### Troubleshooting Auto-Setup

The auto-setup writes a sentinel file to prevent re-running on every restart.
To check the status or retry:

```bash
# Check what happened:
cat ~/asm-ng/data/.pg_setup_attempted

# To retry auto-setup, delete the sentinel and restart:
rm ~/asm-ng/data/.pg_setup_attempted
python3 sf.py -l 0.0.0.0:5001
```

### 2.4 Grant Nmap Raw Socket Capabilities

This allows nmap to perform SYN scans without running ASM-NG as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
```

### 2.5 First Launch and Credential Capture

```bash
source ~/asm-ng/venv/bin/activate
cd ~/asm-ng
python3 sf.py -l 0.0.0.0:5001
```

**IMPORTANT:** On first launch, ASM-NG auto-generates an admin account. The
password is printed to the console output. It will look something like:

```
[*] Admin account created. Username: admin  Password: aBcDeFgH1234
```

**Copy this password immediately.** Then open your browser:

```
http://<TAILSCALE_IP>:5001
```

Log in with `admin` / `<generated password>`, then change your password in the
top-right user menu.

Stop the server with `Ctrl+C`.

### 2.6 Verify Default Configuration

All advanced features (database monitoring, threat intelligence, security
hardening, and thorough scanning options) are enabled by default. No
configuration import is needed. You can review or adjust these settings in
the web UI under **Settings**.

### 2.7 Shell Alias (Optional)

Add to `~/.bashrc` for convenience:

```bash
echo 'alias asm-start="source ~/asm-ng/venv/bin/activate && cd ~/asm-ng && python3 sf.py -l 0.0.0.0:5001"' >> ~/.bashrc
source ~/.bashrc
```

---

## Part 3 — External Tool Installation (15 Tools)

ASM-NG integrates with 15 external tools. Each tool needs to be installed on
the system and then have its **path configured in the Settings page**.

Tools are grouped by install method so you can batch the installations efficiently.

---

### 3.1 APT Packages (5 tools — one command)

```bash
sudo apt install -y nmap gobuster whatweb nbtscan onesixtyone
```

**Settings page values to paste:**

| # | Tool | Settings Tab | Setting Name | Value to Paste |
|---|------|-------------|-------------|----------------|
| 1 | Nmap | Tool - Nmap | `nmappath` | `/usr/bin/nmap` |
| 2 | Gobuster | Tools - Gobuster | `gobuster_path` | `/usr/bin/gobuster` |
| 2b | (Gobuster wordlist) | Tools - Gobuster | `wordlist` | `/usr/share/wordlists/dirb/common.txt` |
| 3 | WhatWeb | Tool - WhatWeb | `whatweb_path` | `/usr/bin/whatweb` |
| 4 | NBTScan | Tool - nbtscan | `nbtscan_path` | `/usr/bin/nbtscan` |
| 5 | onesixtyone | Tool - onesixtyone | `onesixtyone_path` | `/usr/bin/onesixtyone` |

---

### 3.2 pip Packages (4 tools — inside venv)

```bash
source ~/asm-ng/venv/bin/activate
pip install dnstwist wafw00f snallygaster trufflehog
```

> **Note:** Since these are installed inside the ASM-NG venv, and ASM-NG runs
> in the same venv, you can use bare command names. If you need full paths,
> they are at `~/asm-ng/venv/bin/<tool>`.

**Settings page values to paste:**

| # | Tool | Settings Tab | Setting Name(s) | Value(s) to Paste |
|---|------|-------------|-----------------|-------------------|
| 6 | DNSTwist | Tool - DNSTwist | `pythonpath` | `python3` |
| | | | `dnstwistpath` | _(leave blank — auto-detected via PATH)_ |
| 7 | WAFW00F | Tool - WAFW00F | `python_path` | `python3` |
| | | | `wafw00f_path` | `wafw00f` |
| 8 | Snallygaster | Tool - snallygaster | `snallygaster_path` | `snallygaster` |
| 9 | TruffleHog | Tool - TruffleHog | `trufflehog_path` | `trufflehog` |

---

### 3.3 Manual Installs (4 tools — binary download / git clone)

#### Tool 10: Nuclei (Vulnerability Scanner)

```bash
# Download binary (check https://github.com/projectdiscovery/nuclei/releases for latest version)
NUCLEI_VERSION="3.3.9"
wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip -d /tmp
sudo mv /tmp/nuclei /usr/local/bin/nuclei
sudo chmod +x /usr/local/bin/nuclei
rm nuclei_${NUCLEI_VERSION}_linux_amd64.zip

# Download templates
sudo git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates
```

Verify: `nuclei --version`

| Settings Tab | Setting Name | Value to Paste |
|-------------|-------------|----------------|
| Tool - Nuclei | `nuclei_path` | `/usr/local/bin/nuclei` |
| Tool - Nuclei | `template_path` | `/opt/nuclei-templates` |

#### Tool 11: testssl.sh (SSL/TLS Testing)

```bash
sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
```

Verify: `/opt/testssl.sh/testssl.sh --help | head -3`

| Settings Tab | Setting Name | Value to Paste |
|-------------|-------------|----------------|
| Tool - testssl.sh | `testsslsh_path` | `/opt/testssl.sh/testssl.sh` |

#### Tool 12: CMSeeK (CMS Detection)

```bash
sudo git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /opt/CMSeeK
source ~/asm-ng/venv/bin/activate
pip install -r /opt/CMSeeK/requirements.txt
sudo mkdir -p /opt/CMSeeK/Results
```

Verify: `python3 /opt/CMSeeK/cmseek.py --help | head -3`

| Settings Tab | Setting Name | Value to Paste |
|-------------|-------------|----------------|
| Tool - CMSeeK | `pythonpath` | `python3` |
| Tool - CMSeeK | `cmseekpath` | `/opt/CMSeeK/cmseek.py` |

#### Tool 13: Retire.js (JavaScript Vulnerability Scanner)

```bash
sudo npm install -g retire
```

Verify: `retire --version`

| Settings Tab | Setting Name | Value to Paste |
|-------------|-------------|----------------|
| Tool - Retire.js | `retirejs_path` | `/usr/local/bin/retire` |

> If `which retire` returns a different path, use that path instead.

---

### 3.4 API-Only Tools (2 tools — no binary to install)

#### Tool 14: PhoneInfoga (Phone Number OSINT)

PhoneInfoga runs as a local API server. Install is optional — skip if phone
number OSINT is not needed for this client.

To install:
```bash
# Check https://github.com/sundowndev/phoneinfoga/releases for the latest version
PHONEINFOGA_VERSION="v2.11.0"
wget -q "https://github.com/sundowndev/phoneinfoga/releases/download/${PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz"
tar xzf phoneinfoga_Linux_x86_64.tar.gz
sudo mv phoneinfoga /usr/local/bin/phoneinfoga
rm phoneinfoga_Linux_x86_64.tar.gz
```

To run as a background API server:
```bash
phoneinfoga serve -p 5000 &
```

| Settings Tab | Setting Name | Value to Paste |
|-------------|-------------|----------------|
| Tools - PhoneInfoga | `api_endpoint` | `http://localhost:5000/api/v2/scan` |
| Tools - PhoneInfoga | `api_key` | _(leave blank unless you set one)_ |

#### Tool 15: Wappalyzer (Technology Identification — API Only)

No binary to install. Requires a Wappalyzer API key (see Part 4).

| Settings Tab | Setting Name | Value to Paste |
|-------------|-------------|----------------|
| Tool - Wappalyzer (API) | `wappalyzer_api_key` | _(your API key from Part 4)_ |
| Tool - Wappalyzer (API) | `wappalyzer_api_url` | `https://api.wappalyzer.com/v2/lookup/` |

---

### 3.5 Tool Verification Script

Run this after completing all tool installs to verify everything is in place:

```bash
#!/bin/bash
echo "========================================="
echo " ASM-NG External Tool Verification"
echo "========================================="

source ~/asm-ng/venv/bin/activate

check_tool() {
    local name="$1"
    local cmd="$2"
    if command -v "$cmd" &>/dev/null || [ -x "$cmd" ]; then
        echo -e "  [OK]    $name  ($cmd)"
    else
        echo -e "  [MISS]  $name  ($cmd)"
    fi
}

echo ""
echo "--- APT Tools ---"
check_tool "Nmap"         "/usr/bin/nmap"
check_tool "Gobuster"     "/usr/bin/gobuster"
check_tool "WhatWeb"      "/usr/bin/whatweb"
check_tool "NBTScan"      "/usr/bin/nbtscan"
check_tool "onesixtyone"  "/usr/bin/onesixtyone"

echo ""
echo "--- pip Tools (venv) ---"
check_tool "DNSTwist"     "dnstwist"
check_tool "WAFW00F"      "wafw00f"
check_tool "Snallygaster" "snallygaster"
check_tool "TruffleHog"   "trufflehog"

echo ""
echo "--- Manual Installs ---"
check_tool "Nuclei"       "/usr/local/bin/nuclei"
check_tool "testssl.sh"   "/opt/testssl.sh/testssl.sh"
check_tool "CMSeeK"       "/opt/CMSeeK/cmseek.py"
check_tool "Retire.js"    "retire"

echo ""
echo "--- Nuclei Templates ---"
if [ -d "/opt/nuclei-templates" ]; then
    count=$(find /opt/nuclei-templates -name "*.yaml" | wc -l)
    echo -e "  [OK]    Nuclei templates: $count templates found"
else
    echo -e "  [MISS]  Nuclei templates: /opt/nuclei-templates not found"
fi

echo ""
echo "--- Gobuster Wordlist ---"
if [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
    echo -e "  [OK]    Wordlist: /usr/share/wordlists/dirb/common.txt"
else
    echo -e "  [MISS]  Wordlist: /usr/share/wordlists/dirb/common.txt"
fi

echo ""
echo "========================================="
echo " Verification Complete"
echo "========================================="
```

Save as `~/verify-tools.sh`, run with `bash ~/verify-tools.sh`. All 13 binary
tools should show `[OK]`.

---

## Part 4 — Free API Account Signup Checklist

These are all the API-based modules that offer **free tier** accounts. Sign up
for each, obtain the API key, and enter it in the ASM-NG Settings page under
the corresponding module tab.

**Priority legend:** ★ = High-value for most engagements (sign up for these first)

**Workflow tip:** Open each signup URL in a new browser tab, create accounts in
batch, then come back and collect all the API keys at once.

### Tier 1: Core OSINT APIs (Sign Up First)

| # | Service | Signup URL | Module Tab | Setting Key(s) | Where to Find Key |
|---|---------|-----------|-----------|----------------|-------------------|
| 1 | ★ Shodan | https://shodan.io | Shodan | `api_key` | Account → top of page |
| 2 | ★ Censys | https://censys.io | Censys | `censys_api_key_uid` + `censys_api_key_secret` | Account → API tab |
| 3 | ★ VirusTotal | https://www.virustotal.com | VirusTotal | `api_key` | Menu → API Key |
| 4 | ★ SecurityTrails | https://securitytrails.com | SecurityTrails | `api_key` | Account → API |
| 5 | ★ AbuseIPDB | https://www.abuseipdb.com | AbuseIPDB | `api_key` | Account → API → Keys |
| 6 | ★ AlienVault OTX | https://otx.alienvault.com | AlienVault OTX | `api_key` | Settings → API |
| 7 | ★ BinaryEdge | https://www.binaryedge.io | BinaryEdge | `binaryedge_api_key` | Account → API Access |
| 8 | ★ GreyNoise | https://viz.greynoise.io/signup | GreyNoise | `api_key` | Account → API Key |
| 9 | ★ Hybrid Analysis | https://www.hybrid-analysis.com/signup | Hybrid Analysis | `api_key` | Account → API Key tab |
| 10 | ★ IntelligenceX | https://intelx.io | IntelligenceX | `api_key` | Account → Developer tab |

### Tier 2: Extended Intelligence APIs

| # | Service | Signup URL | Module Tab | Setting Key(s) | Where to Find Key |
|---|---------|-----------|-----------|----------------|-------------------|
| 11 | IPInfo | https://ipinfo.io | IPInfo | `api_key` | Account → above "access token" |
| 12 | IPStack | https://ipstack.com | ipstack | `api_key` | Dashboard → API Access Key |
| 13 | ipapi.com | https://ipapi.com | ipapi.com | `api_key` | Dashboard → API Access Key |
| 14 | IPQualityScore | https://www.ipqualityscore.com | IPQualityScore | `api_key` | Account → API Settings |
| 15 | FullHunt | https://fullhunt.io | FullHunt | `api_key` | Settings → API Access |
| 16 | Pulsedive | https://pulsedive.com | Pulsedive | `api_key` | Account → API Key |
| 17 | CertSpotter | https://sslmate.com/signup?for=ct_search_api | CertSpotter | `api_key` | Account → API Credentials |
| 18 | BuiltWith | https://api.builtwith.com/free-api | BuiltWith | `api_key` | Free API page → Your API Key |
| 19 | Hunter.io | https://hunter.io | Hunter.io | `api_key` | Account Settings → API |
| 20 | Netlas | https://netlas.io | Netlas | `api_key` | Dashboard → API Key |

### Tier 3: Specialized & Niche APIs

| # | Service | Signup URL | Module Tab | Setting Key(s) | Where to Find Key |
|---|---------|-----------|-----------|----------------|-------------------|
| 21 | CriminalIP | https://www.criminalip.io | CriminalIP | `api_key` | My Page → API Key |
| 22 | Zoomeye | https://www.zoomeye.org | ZoomEye | `api_key` | Account → API |
| 23 | ONYPHE | https://www.onyphe.io | ONYPHE | `api_key` | Account → API |
| 24 | MetaDefender | https://metadefender.opswat.com | MetaDefender | `api_key` | Dashboard → API Key |
| 25 | FullContact | https://fullcontact.com | FullContact | `api_key` | Dashboard → API Keys |
| 26 | EmailCrawlr | https://emailcrawlr.com | EmailCrawlr | `api_key` | Dashboard → API Key |
| 27 | EmailRep | https://emailrep.io/free | EmailRep | `api_key` | Emailed after approval |
| 28 | BotScout | http://botscout.com/getkey.htm | BotScout | `api_key` | Emailed to account |
| 29 | LeakIX | https://leakix.net | LeakIX | `api_key` | Account → API |
| 30 | Leak-Lookup | https://leak-lookup.com | Leak-Lookup | `api_key` | Account → API → API Key |
| 31 | GrayHatWarfare | https://grayhatwarfare.com | GrayHatWarfare | `api_key` | Account → API |
| 32 | Etherscan | https://etherscan.io | Etherscan | `api_key` | My API Keys → Add → Token |
| 33 | BitcoinWhoWho | https://bitcoinwhoswho.com/signup | Bitcoin Who's Who | `api_key` | API → Request Key |
| 34 | FraudGuard | https://fraudguard.io | FraudGuard | `fraudguard_api_key_account` + `fraudguard_api_key_password` | Dashboard |
| 35 | Snov.io | https://snov.io | Snov | `api_key_client_id` + `api_key_client_secret` | Account → API |
| 36 | RocketReach | https://rocketreach.co | RocketReach | `api_key` | Account → API |
| 37 | NameAPI | https://www.nameapi.org | NameAPI | `api_key` | Dashboard → API Key |
| 38 | NumVerify | https://numverify.com | numverify | `api_key` | Dashboard → API Key |
| 39 | AbstractAPI | https://app.abstractapi.com/users/signup | AbstractAPI | `companyenrichment_api_key`, `phonevalidation_api_key`, `ipgeolocation_api_key` | Each API page → Try It → Key |
| 40 | Wappalyzer | https://www.wappalyzer.com/api/ | Tool - Wappalyzer (API) | `wappalyzer_api_key` | API dashboard |

### Tier 4: Google & Azure APIs (Create One Project, Enable Multiple APIs)

**Google Cloud (3 APIs — one GCP project):**

1. Go to https://console.cloud.google.com
2. Create a new project (e.g., "ASM-NG")
3. Enable these three APIs and create an API key for each:

| # | API | Enable URL | Module Tab | Setting Key |
|---|-----|-----------|-----------|-------------|
| 41 | Custom Search | https://console.cloud.google.com/apis/library/customsearch.googleapis.com | Google | `api_key` |
| 42 | Maps Geocoding | https://console.cloud.google.com/apis/library/geocoding-backend.googleapis.com | Google Maps | `api_key` |
| 43 | Safe Browsing | https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com | Google SafeBrowsing | `api_key` |

> For Google Custom Search, you also need a Custom Search Engine ID.
> Create one at: https://programmablesearchengine.google.com/

**Azure (1 API):**

| # | API | Signup URL | Module Tab | Setting Key |
|---|-----|-----------|-----------|-------------|
| 44 | Bing Web Search | https://azure.microsoft.com/en-us/services/cognitive-services/bing-web-search-api/ | Bing | `api_key` |

### Tier 5: Requires Manual Approval

| # | Service | Contact URL | Module Tab | Setting Key(s) | Notes |
|---|---------|------------|-----------|----------------|-------|
| 45 | CIRCL.lu | https://www.circl.lu/contact/ | CIRCL Passive DNS/SSL | `api_key_login` + `api_key_password` | Email to request access |
| 46 | NeutrinoAPI | https://www.neutrinoapi.com | NeutrinoAPI | `user_id` + `api_key` | Free after registration |
| 47 | FOFA | https://fofa.info/user/register | FOFA | `api_email` + `api_key` | Chinese service; free tier available |

### GreyNoise Community (Bonus — Separate Module)

| # | Service | Signup URL | Module Tab | Setting Key |
|---|---------|-----------|-----------|-------------|
| 48 | GreyNoise Community | https://viz.greynoise.io/signup | GreyNoise Community | `api_key` |

> This is a **separate module** from the main GreyNoise module. The Community
> API is free and does not require a paid plan. Use the same account/key.

---

## Part 5 — Ready-to-Import Configuration Template

Copy the entire block below into a file called `kali-setup.cfg` on your Kali VM.
Fill in your API keys, then import it via **Settings → IMPORT API KEYS**.

The `.cfg` format is: `module_name:option_name=value` (one per line, `#` = comment).
This merges with existing settings — it will not overwrite options you don't include.

```ini
# ==============================================================================
# ASM-NG Kali Setup Configuration
# ==============================================================================
# Import via: Settings > IMPORT API KEYS > Upload this file
#
# Instructions:
#   1. Replace YOUR_KEY_HERE with actual API keys (from Part 4)
#   2. Uncomment lines (remove leading #) for keys you have obtained
#   3. Save the file and import it
# ==============================================================================


# ==============================================================================
# SECTION 1: EXTERNAL TOOL PATHS (from Part 3)
# ==============================================================================
# These are pre-filled with standard Kali Linux paths.
# No changes needed if you followed Part 3 exactly.

# --- APT Tools ---
sfp_tool_nmap:nmappath=/usr/bin/nmap
sfp_tool_gobuster:gobuster_path=/usr/bin/gobuster
sfp_tool_gobuster:wordlist=/usr/share/wordlists/dirb/common.txt
sfp_tool_whatweb:whatweb_path=/usr/bin/whatweb
sfp_tool_nbtscan:nbtscan_path=/usr/bin/nbtscan
sfp_tool_onesixtyone:onesixtyone_path=/usr/bin/onesixtyone

# --- pip Tools (inside venv, bare names work) ---
sfp_tool_dnstwist:pythonpath=python3
sfp_tool_wafw00f:python_path=python3
sfp_tool_wafw00f:wafw00f_path=wafw00f
sfp_tool_snallygaster:snallygaster_path=snallygaster
sfp_tool_trufflehog:trufflehog_path=trufflehog

# --- Manual Installs ---
sfp_tool_nuclei:nuclei_path=/usr/local/bin/nuclei
sfp_tool_nuclei:template_path=/opt/nuclei-templates
sfp_tool_testsslsh:testsslsh_path=/opt/testssl.sh/testssl.sh
sfp_tool_cmseek:pythonpath=python3
sfp_tool_cmseek:cmseekpath=/opt/CMSeeK/cmseek.py
sfp_tool_retirejs:retirejs_path=retire

# --- TruffleHog extra options ---
sfp_tool_trufflehog:entropy=1
sfp_tool_trufflehog:allrepos=1


# ==============================================================================
# SECTION 2: MODULE OPTIMIZATIONS
# ==============================================================================
# These advanced features are now enabled by default. This section is provided
# for reference only — you do not need to import these settings manually.
# No API keys needed — just better defaults.

sfp__stor_db:enable_auto_recovery=1
sfp__stor_db:enable_connection_monitoring=1
sfp__stor_db:enable_performance_monitoring=1
sfp__stor_db:enable_graceful_shutdown=1
sfp__stor_db:enable_health_monitoring=1

sfp_dnsbrute:top10000=1
sfp_tldsearch:activeonly=1
sfp_spider:reportduplicates=1
sfp_robtex:cohostsamedomain=1
sfp_robtex:subnetlookup=1
sfp_threatminer:netblocklookup=1
sfp_threatminer:subnetlookup=1
sfp_hackertarget:cohostsamedomain=1
sfp_hackertarget:http_headers=1
sfp_mnemonic:cohostsamedomain=1
sfp_accounts:permutate=1
sfp_countryname:similardomain=1
sfp_archiveorg:formpages=1
sfp_archiveorg:flashpages=1
sfp_archiveorg:javapages=1
sfp_archiveorg:staticpages=1
sfp_archiveorg:webframeworkpages=1
sfp_archiveorg:javascriptpages=1


# ==============================================================================
# SECTION 3: API KEYS
# ==============================================================================
# Uncomment each line and replace YOUR_KEY_HERE as you sign up for accounts.
# Lines starting with # are ignored during import.

# --- Tier 1: Core OSINT (★ High Priority) ---
# sfp_shodan:api_key=YOUR_KEY_HERE
# sfp_censys:censys_api_key_uid=YOUR_UID_HERE
# sfp_censys:censys_api_key_secret=YOUR_SECRET_HERE
# sfp_virustotal:api_key=YOUR_KEY_HERE
# sfp_securitytrails:api_key=YOUR_KEY_HERE
# sfp_abuseipdb:api_key=YOUR_KEY_HERE
# sfp_alienvault:api_key=YOUR_KEY_HERE
# sfp_binaryedge:binaryedge_api_key=YOUR_KEY_HERE
# sfp_greynoise:api_key=YOUR_KEY_HERE
# sfp_hybrid_analysis:api_key=YOUR_KEY_HERE
# sfp_intelx:api_key=YOUR_KEY_HERE

# --- Tier 2: Extended Intelligence ---
# sfp_ipinfo:api_key=YOUR_KEY_HERE
# sfp_ipstack:api_key=YOUR_KEY_HERE
# sfp_ipapicom:api_key=YOUR_KEY_HERE
# sfp_ipqualityscore:api_key=YOUR_KEY_HERE
# sfp_fullhunt:api_key=YOUR_KEY_HERE
# sfp_pulsedive:api_key=YOUR_KEY_HERE
# sfp_certspotter:api_key=YOUR_KEY_HERE
# sfp_builtwith:api_key=YOUR_KEY_HERE
# sfp_hunter:api_key=YOUR_KEY_HERE
# sfp_netlas:api_key=YOUR_KEY_HERE

# --- Tier 3: Specialized ---
# sfp_criminalip:api_key=YOUR_KEY_HERE
# sfp_zoomeye:api_key=YOUR_KEY_HERE
# sfp_onyphe:api_key=YOUR_KEY_HERE
# sfp_metadefender:api_key=YOUR_KEY_HERE
# sfp_fullcontact:api_key=YOUR_KEY_HERE
# sfp_emailcrawlr:api_key=YOUR_KEY_HERE
# sfp_emailrep:api_key=YOUR_KEY_HERE
# sfp_botscout:api_key=YOUR_KEY_HERE
# sfp_leakix:api_key=YOUR_KEY_HERE
# sfp_citadel:api_key=YOUR_KEY_HERE
# sfp_grayhatwarfare:api_key=YOUR_KEY_HERE
# sfp_etherscan:api_key=YOUR_KEY_HERE
# sfp_bitcoinwhoswho:api_key=YOUR_KEY_HERE
# sfp_fraudguard:fraudguard_api_key_account=YOUR_USERNAME_HERE
# sfp_fraudguard:fraudguard_api_key_password=YOUR_PASSWORD_HERE
# sfp_snov:api_key_client_id=YOUR_CLIENT_ID_HERE
# sfp_snov:api_key_client_secret=YOUR_CLIENT_SECRET_HERE
# sfp_rocketreach:api_key=YOUR_KEY_HERE
# sfp_nameapi:api_key=YOUR_KEY_HERE
# sfp_numverify:api_key=YOUR_KEY_HERE
# sfp_abstractapi:companyenrichment_api_key=YOUR_KEY_HERE
# sfp_abstractapi:phonevalidation_api_key=YOUR_KEY_HERE
# sfp_abstractapi:ipgeolocation_api_key=YOUR_KEY_HERE
# sfp_tool_wappalyzer:wappalyzer_api_key=YOUR_KEY_HERE
# sfp_greynoise_community:api_key=YOUR_KEY_HERE

# --- Tier 4: Google & Azure ---
# sfp_googlesearch:api_key=YOUR_KEY_HERE
# sfp_googlemaps:api_key=YOUR_KEY_HERE
# sfp_googlesafebrowsing:api_key=YOUR_KEY_HERE
# sfp_bingsearch:api_key=YOUR_KEY_HERE

# --- Tier 5: Manual Approval ---
# sfp_circllu:api_key_login=YOUR_LOGIN_HERE
# sfp_circllu:api_key_password=YOUR_PASSWORD_HERE
# sfp_neutrinoapi:user_id=YOUR_USER_ID_HERE
# sfp_neutrinoapi:api_key=YOUR_KEY_HERE
# sfp_fofa:api_email=YOUR_EMAIL_HERE
# sfp_fofa:api_key=YOUR_KEY_HERE
```

**How to use:**

1. Copy the block above into a file: `nano ~/kali-setup.cfg`
2. Fill in your API keys (uncomment lines and replace placeholders)
3. In ASM-NG web UI: **Settings → IMPORT API KEYS → Upload `kali-setup.cfg`**
4. Click **Save** at the bottom of the Settings page

> You can re-import this file any time — it merges with existing settings without
> overwriting anything you have not included in the file.

---

## Part 6 — Verification Checklist

After completing Parts 1-5, work through this checklist:

### Core Functionality

- [ ] ASM-NG web UI loads at `http://<TAILSCALE_IP>:5001`
- [ ] Can log in with admin credentials
- [ ] Settings page shows all advanced modules enabled
- [ ] All 15 tool tabs in Settings show configured paths (no empty path fields)

### Tool Verification

- [ ] Run `bash ~/verify-tools.sh` — all 13 binary tools show `[OK]`
- [ ] Nuclei templates directory has 1000+ `.yaml` files

### Quick Scan Test

Run a test scan to verify tools work end-to-end:

1. In ASM-NG, click **New Scan**
2. Target: `scanme.nmap.org`
3. Select use case: **Footprint**
4. Enable these specific modules (at minimum):
   - Tool - Nmap
   - Tool - WhatWeb
   - Tool - testssl.sh
5. Start the scan
6. Verify events appear in the scan results (should see OS info, web tech, SSL findings)

### API Verification

- [ ] In Settings, modules with API keys show a lock icon (not a warning)
- [ ] Run a scan with Shodan enabled → verify Shodan results appear
- [ ] Run a scan with VirusTotal enabled → verify VT results appear

### Remote Access

- [ ] From another device on Tailscale, navigate to `http://<TAILSCALE_IP>:5001`
- [ ] Confirm login works from the remote device
- [ ] Confirm a scan can be launched from the remote device

### Persistence

- [ ] Reboot the VM: `sudo reboot`
- [ ] After reboot, verify Tailscale reconnects: `tailscale status`
- [ ] Start ASM-NG (or verify systemd service started automatically)
- [ ] Confirm previous scan data is still present

---

## Appendix A — Systemd Service Unit

To run ASM-NG as a persistent background service that starts on boot:

```bash
sudo tee /etc/systemd/system/asm-ng.service > /dev/null << 'EOF'
[Unit]
Description=ASM-NG Attack Surface Management Platform
After=network-online.target postgresql.service
Wants=network-online.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/asm-ng
Environment="PATH=/root/asm-ng/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="VIRTUAL_ENV=/root/asm-ng/venv"
ExecStart=/root/asm-ng/venv/bin/python3 sf.py -l 0.0.0.0:5001
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable asm-ng
sudo systemctl start asm-ng
sudo systemctl status asm-ng
```

Check logs:

```bash
sudo journalctl -u asm-ng -f
```

---

## Appendix B — Troubleshooting

### "Externally managed environment" error when running pip

You forgot to activate the virtual environment. Always run:
```bash
source ~/asm-ng/venv/bin/activate
```

### "Address already in use" on port 5001

Another instance of ASM-NG (or another service) is using the port:
```bash
sudo lsof -i :5001
# Kill the process if it is a stale ASM-NG instance
sudo kill <PID>
```

### Tool shows "tool not found" in scan logs

The path in Settings does not match the actual binary location. Verify with:
```bash
which <tool_name>
# Then paste the output into the corresponding Settings field
```

### Tailscale not connecting after reboot

```bash
sudo tailscale status
# If disconnected:
sudo tailscale up --ssh
```

Check if the Tailscale service is running:
```bash
sudo systemctl status tailscaled
sudo systemctl enable tailscaled
```

### Nmap scan returns "permission denied" or no OS detection

The nmap capabilities were not set. Re-run:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
```

### Nuclei templates outdated

Update the templates:
```bash
cd /opt/nuclei-templates && sudo git pull
```

Or use nuclei's built-in update:
```bash
nuclei -update-templates
```

### Settings not saving

Make sure you click **Save** at the bottom of the Settings page after making
changes. The IMPORT API KEYS function loads values into the form but you still
need to click Save to persist them.

### Database locked (SQLite)

Only one instance of ASM-NG should run at a time when using SQLite. Check for
duplicate processes:
```bash
ps aux | grep sf.py
```
