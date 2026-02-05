# SpiderFoot Enterprise Features

This directory contains everything needed to enable enterprise features on a fresh or existing SpiderFoot installation.

## Quick Start

```bash
# 1. Install all enterprise dependencies
bash enterprise/install-deps.sh

# 2. Start SpiderFoot
python3 sf.py -l 0.0.0.0:5001

# 3. Go to Settings > IMPORT API KEYS > select enterprise/enterprise-full.cfg
```

That's it. All enterprise features are now active.

---

## What's Included

| File | Purpose |
|------|---------|
| `enterprise-full.cfg` | Config that enables ALL enterprise features (requires deps installed) |
| `enterprise-lite.cfg` | Config that enables only zero-dependency features (no pip install needed) |
| `install-deps.sh` | Installs all required Python packages |
| `requirements-enterprise.txt` | pip requirements file for manual installation |

---

## Enterprise Modules

### Database Storage (Enterprise Stubs)
**Module:** `sfp__stor_db` | **Dependencies:** None (SQLite), `psycopg2` (PostgreSQL)

Adds monitoring, recovery, and optimization to the base storage module.

| Feature | What It Does |
|---------|-------------|
| Auto Recovery | Automatic error recovery on database failures |
| Connection Monitoring | Health monitoring for database connections |
| Performance Monitoring | Track database operation performance |
| Graceful Shutdown | Clean shutdown procedures |
| Health Monitoring | Overall system health checks |
| Connection Pooling | Reuse database connections |
| Load Balancing | Distribute queries across connections |
| Auto Scaling | Scale connections based on load |
| Query Optimization | Optimize database queries |
| Performance Benchmarking | Benchmark database performance |
| Metrics Collection | Collect operational metrics |

### Advanced Database Storage
**Module:** `sfp__stor_db_advanced` | **Dependencies:** None (basic), `psycopg2` (full)

Enterprise-grade storage with connection pooling, load balancing, auto-scaling, and AI-powered query optimization. Features are enabled by default in this module.

### AI Threat Intelligence Engine
**Module:** `sfp__ai_threat_intel` | **Dependencies:** `numpy`, `scikit-learn`, `pandas`, `nltk`

| Feature | What It Does |
|---------|-------------|
| Pattern Recognition | AI-powered attack pattern detection |
| Predictive Analytics | Threat forecasting based on historical data |
| IOC Correlation | Automated indicator-of-compromise correlation |
| Threat Scoring | Dynamic ML-based threat severity scoring |
| NLP Analysis | Natural language processing for unstructured threat data |

**Tunable Parameters:**
- `anomaly_detection_threshold` (0.0-1.0, default: 0.1)
- `threat_score_threshold` (0-100, default: 70)
- `correlation_min_strength` (0.0-1.0, default: 0.3)
- `prediction_time_horizon` (hours, default: 24)
- `ml_model_update_interval` (seconds, default: 3600)

### Security Hardening Engine
**Module:** `sfp__security_hardening` | **Dependencies:** `cryptography`, `PyJWT`, `pyotp`

| Feature | Dependencies Required |
|---------|----------------------|
| E2E Encryption | `cryptography`, `cffi` |
| Multi-Factor Auth (MFA) | `PyJWT`, `pyotp` |
| Role-Based Access Control | None |
| Audit Logging | None |
| Zero-Trust Architecture | None |

**Note:** RBAC, audit logging, and zero-trust work without any extra packages. Only encryption and MFA need the crypto/auth libraries.

### ElasticSearch Storage
**Module:** `sfp__stor_elasticsearch` | **Dependencies:** `elasticsearch`

Stores scan results into an external ElasticSearch instance for indexing and visualization. Requires a running ElasticSearch server. After importing the config, configure the host/port/credentials on the Settings page.

### 4chan Monitor
**Module:** `sfp_4chan` | **Dependencies:** None (uses `requests`, already installed)

Free board monitoring via the public 4chan JSON API. No API key needed. Configure which boards to monitor (e.g., `pol,b,g,k,biz`).

---

## Installation Options

### Option A: Full Install (Recommended)
Installs all dependencies for every enterprise module.

```bash
bash enterprise/install-deps.sh --full
```

### Option B: Selective Install
Install only what you need:

```bash
bash enterprise/install-deps.sh --ai             # AI Threat Intelligence
bash enterprise/install-deps.sh --security        # Security Hardening
bash enterprise/install-deps.sh --elasticsearch   # ElasticSearch Storage
bash enterprise/install-deps.sh --postgresql      # PostgreSQL Backend
```

### Option C: pip requirements
```bash
pip install -r enterprise/requirements-enterprise.txt
```

### Option D: Zero Dependencies (Lite Mode)
Skip the install entirely and import `enterprise-lite.cfg` instead. This enables everything that works out of the box:
- All Database Storage enterprise features
- Advanced DB query optimization + performance monitoring
- RBAC, audit logging, zero-trust (no encryption/MFA)
- 4chan monitoring

---

## Importing the Config

### Via Web UI
1. Open SpiderFoot in your browser
2. Navigate to **Settings**
3. Click **IMPORT API KEYS**
4. Select either `enterprise-full.cfg` or `enterprise-lite.cfg`
5. Settings are applied immediately

### Via Config File on Launch
You can also apply settings by placing them in the SpiderFoot database. The import via web UI is the simplest method for fresh installs.

---

## Verifying Features Are Active

After importing the config, check the Settings page. Navigate to each enterprise module tab:
- **DATABASE STORAGE** - Enterprise options should show as enabled
- **ADVANCED DATABASE STORAGE (ENTERPRISE)** - Features should be ON
- **AI THREAT INTELLIGENCE ENGINE** - All 5 engines should be enabled
- **SECURITY HARDENING ENGINE** - Features should be enabled per your config
- **4CHAN MONITOR** - Boards field should be populated

If a module shows as having issues during scans, check the scan logs for dependency errors. The most common issue is missing Python packages -- run `install-deps.sh` to resolve.

---

## FAQ

**Q: There's no `--enterprise` flag for `sf.py`?**
A: Correct. Enterprise features are configured through the Settings page, not CLI flags. The config import files in this directory are the intended way to enable them.

**Q: What do the lock icons mean on the Settings page?**
A: Lock icons indicate a module has an `api_key` field, meaning it can optionally use an API key. It does NOT mean the module is locked or requires payment.

**Q: Can I customize the config before importing?**
A: Yes. The `.cfg` files are plain text. Edit them to enable/disable specific features or change parameter values before importing. Lines starting with `#` are comments.

**Q: Will importing overwrite my existing settings?**
A: It merges with existing settings. Only the keys present in the config file are updated. Your other settings (API keys, global config, etc.) are preserved.
