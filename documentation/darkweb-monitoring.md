# Dark Web / Deep Web External Exposure Monitoring

ASM-NG includes comprehensive dark web monitoring capabilities through 12 dedicated modules, 7 custom event types, and 5 correlation rules designed to detect external exposure of your organization's assets on the dark web.

## Quick Start

1. Create a new scan and select the **"Dark Web Exposure"** use case
2. All dark web modules will be auto-selected
3. Configure API keys for modules that require them (optional but recommended)
4. Start the scan

## Modules Overview

### No API Key Required (Free)

| Module | Source | What It Finds |
|--------|--------|---------------|
| **sfp_xposedornot** | XposedOrNot | Email breach exposure (free); domain breaches (API key) |
| **sfp_ransomwatch** | ransomware.live | Ransomware group leak site victim mentions (300+ groups) |
| **sfp_darkweb_aggregate** | Haystak, Tor66 | Dark web search engine mentions (**requires Tor**) |
| **sfp_stealerlog_check** | Hudson Rock | Infostealer log credential matches |
| **sfp_deepdarkcti** | deepdarkCTI | Known ransomware/forum/market indicators |
| **sfp_brand_darkweb** | Ahmia + permutations | Brand impersonation on .onion sites |
| **sfp_ahmia** | Ahmia.fi | Tor search engine mentions |
| **sfp_torch** | TORCH | Tor search engine mentions |
| **sfp_onionsearchengine** | OnionSearchEngine | Tor search engine mentions |

### API Key Required (or Optional)

| Module | Source | Key Type | What It Finds |
|--------|--------|----------|---------------|
| **sfp_xposedornot** | XposedOrNot | Free API key (optional) | Domain-level breach lookups (email lookups work without key) |
| **sfp_snusbase** | Snusbase | Commercial API | Breached credentials (email, password, hash) |
| **sfp_pasterack** | Multiple paste sites | Google CSE API | Paste site mentions (Gists, Rentry, dpaste, etc.) |
| **sfp_tool_h8mail** | h8mail | Config file | Email OSINT breach hunting |
| **sfp_misp** | MISP instance | Private API | Threat intelligence platform IOC matching |
| **sfp_opencti** | OpenCTI instance | Private API | Threat intelligence platform IOC matching |

### Pre-Existing Dark Web Modules (Enhanced)

These existing modules now include the "Dark Web Exposure" use case:

- **sfp_haveibeenpwned** — HaveIBeenPwned breach check
- **sfp_intelx** — IntelligenceX deep/dark web archive
- **sfp_leakix** — LeakIX data leak detection
- **sfp_leakcheck** — LeakCheck breach database
- **sfp_citadel** — Leak-Lookup breach database
- **sfp_dehashed** — Dehashed breach database
- **sfp_pastebin** — PasteBin monitoring via Google CSE
- **sfp_psbdmp** — PasteBin dump monitoring
- **sfp_apileak** — API key leak detection
- **sfp_torexits** — Tor exit node detection
- **sfp_wikileaks** — Wikileaks mentions
- **sfp_telegram** — Telegram channel monitoring (with leak channel detection)

## Event Types

| Event Type | Description | Severity |
|------------|-------------|----------|
| `RANSOMWARE_LEAK_MENTION` | Target found on ransomware group leak site | Critical (-25 pts) |
| `STEALER_LOG_MATCH` | Credentials found in infostealer logs | Critical (-20 pts) |
| `DARKWEB_BRAND_MENTION` | Brand impersonation on dark web | High (-15 pts) |
| `DARKWEB_FORUM_MENTION` | Target discussed in dark web forums | High (-10 pts) |
| `TELEGRAM_LEAK_MENTION` | Target mentioned in Telegram leak channels | High (-10 pts) |
| `THREAT_INTEL_FEED_MATCH` | Match in MISP/OpenCTI/deepdarkCTI | High (-10 pts) |
| `ONION_SERVICE_DETECTED` | .onion service discovered | Informational (-5 pts) |

## Correlation Rules

Five correlation rules automatically detect compound threats:

1. **darkweb_multi_source_mention** — Target mentioned across 2+ independent dark web sources
2. **credential_leak_cross_platform** — Email compromised in 3+ breach databases
3. **ransomware_leak_with_breach** — Ransomware leak + credential breach = active compromise
4. **darkweb_brand_abuse_cluster** — Brand impersonation across dark web + clearnet
5. **darkweb_escalation** — Progressive targeting pattern: paste → forum → ransomware/stealer

## Installation

### Python Dependencies (all platforms)

All Python dependencies (h8mail, pymisp, telethon) are included in `requirements.txt`
and install automatically via `pip install -r requirements.txt` or `./run.sh`.

### Tor Installation (optional — for direct .onion access)

Most modules use clearnet APIs and portals — **no Tor setup required** for basic
functionality. Install Tor only if you want direct .onion crawling.

**Debian / Kali Linux / ParrotOS:**
```bash
sudo apt update && sudo apt install -y tor
sudo systemctl enable tor && sudo systemctl start tor
```

**Ubuntu (22.04 / 24.04):**
```bash
sudo apt update && sudo apt install -y tor
sudo systemctl enable tor && sudo systemctl start tor
```

**macOS (Homebrew):**
```bash
brew install tor
brew services start tor
```

**RHEL / Fedora / Rocky Linux:**
```bash
sudo dnf install -y tor
sudo systemctl enable tor && sudo systemctl start tor
```

**Arch / BlackArch:**
```bash
sudo pacman -S tor
sudo systemctl enable tor && sudo systemctl start tor
```

**Verify Tor is running:**
```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Expected: {"IsTor":true,"IP":"..."}
```

### h8mail Installation

h8mail is installed automatically via `requirements.txt`. If you need to install
it manually or verify the installation:

```bash
# Inside the ASM-NG venv:
pip install h8mail
h8mail --version

# macOS users: if installed via pip3 --user, the binary may be at:
# ~/Library/Python/3.x/bin/h8mail
# ASM-NG auto-detects this location.
```

### Platform-Specific Notes

| Platform | Package Manager | Tor Package | Notes |
|----------|----------------|-------------|-------|
| Kali Linux | apt | `tor` | Pre-installed on many Kali images |
| ParrotOS | apt | `tor` | Pre-installed on security edition |
| Ubuntu | apt | `tor` | Works on 20.04, 22.04, 24.04 |
| Debian | apt | `tor` | Works on Bullseye, Bookworm |
| macOS | Homebrew | `tor` | Use `brew services start tor` |
| Fedora | dnf | `tor` | Works on Fedora 38+ |
| Arch | pacman | `tor` | Works on Arch and BlackArch |
| Docker | N/A | Built into image | Tor included in Dockerfile |

## Tor Configuration

After installing Tor, configure the SOCKS proxy in ASM-NG scan settings:

- **SOCKS Type**: `TOR`
- **SOCKS Address**: `127.0.0.1`
- **SOCKS Port**: `9050`

### Docker Tor Proxy

The `docker-compose.yml` includes an optional tor-proxy service. Enable with:

```bash
docker compose --profile darkweb up
```

Or add manually:

```yaml
tor-proxy:
  image: dperson/torproxy:latest
  ports:
    - "9050:9050"
    - "9051:9051"
```

## Legal Considerations

- Only scan targets you own or have written authorization to test
- Some dark web data sources may contain sensitive or illegal content
- Ransomware leak site data is collected from public monitoring APIs, not from direct interaction with criminal infrastructure
- MISP and OpenCTI integrations connect only to your private instances
- The Telegram module requires your own API credentials and monitors only channels you configure

## Recommended Configuration

### Minimal (No API Keys)

Enable: `sfp_xposedornot`, `sfp_ransomwatch`, `sfp_darkweb_aggregate`, `sfp_stealerlog_check`, `sfp_deepdarkcti`, `sfp_ahmia`

### Standard (Free + Google CSE)

Add: `sfp_pasterack`, `sfp_pastebin`, `sfp_brand_darkweb`, `sfp_psbdmp`

### Full (All Sources)

Add: `sfp_snusbase`, `sfp_tool_h8mail`, `sfp_haveibeenpwned`, `sfp_intelx`, `sfp_leakcheck`, `sfp_dehashed`, `sfp_telegram`, `sfp_misp`, `sfp_opencti`

## Grading Impact

Dark web findings significantly impact the overall scan grade:

- **Ransomware leak mentions** are ranked as critical findings (-25 points)
- **Infostealer log matches** are ranked as critical findings (-20 points)
- **Brand mentions** scale with count (more mentions = more points deducted)
- Correlation rules can trigger additional alerts when compound threats are detected

## Verification & Testing

Run the dark web module test suite to verify everything is configured correctly:

```bash
# Dry-run validation (no network, fast)
python3 test/darkweb_exposure_test.py

# Live test against a domain you own
python3 test/darkweb_exposure_test.py --live --target yourdomain.com
```

The test suite validates:
1. All 11 new modules import without errors
2. All modules have correct metadata and "Dark Web Exposure" use case
3. All 16 enhanced modules have the use case tag
4. All 7 event types are registered in `db.py`
5. All 7 event types have explicit grading rules
6. All 5 correlation rules exist and parse correctly
7. All modules can be `setup()` without errors
8. The newscan template has the Dark Web Exposure radio button
9. All dependencies (h8mail, pymisp, telethon, tor) are installed
10. (Live mode) Free modules can query APIs and return results
