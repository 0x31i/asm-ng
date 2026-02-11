# ASM-NG (Attack Surface Management - Next Generation)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/0x31i/asm-ng/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9+-green)](https://www.python.org)
[![Stable Release](https://img.shields.io/badge/version-5.2.9-blue.svg)](https://github.com/0x31i/asm-ng/releases/tag/v5.2.9)
[![Production Grade](https://img.shields.io/badge/Production-Grade-blue.svg)](https://github.com/0x31i/asm-ng)
[![CI status](https://github.com/0x31i/asm-ng/workflows/Tests/badge.svg)](https://github.com/0x31i/asm-ng/actions?query=workflow%3A"Tests")
[![Docker CI Build](https://github.com/0x31i/asm-ng/workflows/Docker%20Image%20CI/badge.svg)](https://github.com/0x31i/asm-ng/actions?query=workflow%3A"Docker%20Image%20CI")
[![Code QL](https://github.com/0x31i/asm-ng/workflows/CodeQL/badge.svg)](https://github.com/0x31i/asm-ng/actions?query=workflow%3A"CodeQL")
[![Last Commit](https://img.shields.io/github/last-commit/0x31i/asm-ng)](https://github.com/0x31i/asm-ng/commits/master)
[![Discord](https://img.shields.io/discord/770524432464216074)](https://discord.gg/vyvztrG)
![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)

**ASM-NG** is a production-ready attack surface management and OSINT platform. Built on a battle-tested scanning engine with 200+ modules, it extends far beyond traditional OSINT with **workspace management**, **security grading**, **false positive tracking**, **known asset management**, **external vulnerability tool integration** (Burp Suite Pro, Nessus Pro, Nuclei), and **multi-layered cross-scan correlation** — making intelligence data truly navigable and actionable.

ASM-NG features an embedded web server with a clean, modern interface and can also be used entirely via the command line. Written in **Python 3** and **MIT-licensed**.

> **Note:** ASM-NG is built on the SpiderFoot OSINT engine. Core scanning modules retain their original naming for stability. All user-facing features, branding, and tooling have been updated to ASM-NG.

![ASM-NG v5](./documentation/images/v5.png)

---

## What's New vs. SpiderFoot v4.0

ASM-NG is a ground-up transformation of SpiderFoot into a full attack surface management platform. Here's what we've added:

| Category | SpiderFoot v4.0 | ASM-NG |
|---|---|---|
| **Target Management** | Single target per scan | Workspaces with multi-target scanning |
| **Security Grading** | None | Full A-F grading system with 7 categories, weighted scoring, and per-event breakdowns |
| **False Positive Tracking** | Basic FP flag per result | Three-state system (Unvalidated/FP/Validated) with target-level persistence and cross-scan sync |
| **Asset Management** | None | Known asset tracking with bulk import, matching, and export |
| **External Vuln Tools** | None | Burp Suite Pro, Nessus Pro, Nuclei integration with import/export |
| **Historical Data Sync** | None | Auto-import from previous scans, SYNC/RESYNC, deduplication |
| **Bulk Operations** | None | Bulk status editing, select-all, cascade to children |
| **Authentication** | Basic HTTP auth | Full user accounts with sessions, login page, user management |
| **Audit Logging** | None | Comprehensive audit trail with username, action, IP, timestamp |
| **Correlation Engine** | Basic YAML rules | YAML rules + single-scan IOC correlation + cross-scan historical correlation + CTI report generation |
| **Data Import** | None | Legacy CSV, Scan Backup, Nessus XML, Burp XML/HTML, Excel findings |
| **Export** | CSV/JSON | CSV/JSON/XLSX/GEXF with multi-scan export, vulnerability export, asset export |
| **Database** | SQLite only | SQLite + PostgreSQL with 9 new tables and auto-migration |
| **Modules** | ~200 | 274 modules including security hardening and threat intel modules |
| **Correlation Rules** | 37 YAML rules | 51 YAML rules + automated single-scan and cross-scan correlation |

---

## Feature Deep-Dives

### Workspace Management & Multi-Target Scanning

Workspaces let you organize targets, scans, and results into logical groups for ongoing attack surface monitoring.

**Capabilities:**
- **Create and manage workspaces** with name, description, and multiple targets
- **Multi-target scanning** — launch scans across all workspace targets simultaneously with one click
- **Target management** — add/remove targets with auto-type detection (domain, IP, CIDR, email, etc.)
- **Import existing scans** into workspaces to consolidate historical data
- **Workspace cloning** — duplicate a workspace's target configuration for templating
- **Workspace merging** — combine two workspaces, deduplicating targets and scans
- **Workspace export** — export all workspace data as JSON including scan results
- **Summary dashboard** — at-a-glance statistics on targets, scans, events, and correlations
- **Cross-workspace search** — search events across all scans in a workspace
- **Timing configuration** — set timezone, business hours, scheduling preferences, and retention policies
- **CTI report generation** — generate threat assessment, infrastructure analysis, or attack surface reports for the entire workspace
- **Dedicated workspace views** — full UI for workspace list and workspace detail pages

```mermaid
graph LR;
    A[Workspace] --> B[Target 1];
    A --> C[Target 2];
    A --> D[Target N];
    B --> E[Scan 1a];
    B --> F[Scan 1b];
    C --> G[Scan 2a];
    D --> H[Scan Na];
    E --> I[Cross-Scan Correlation];
    F --> I;
    G --> I;
    H --> I;
    I --> J[Workspace Report];
```

---

### Security Grading System

Every scan gets an overall letter grade (A through F) based on a weighted analysis of findings across 7 security categories.

**How it works:**
1. Each of 130+ event types maps to a **category** with a **scoring rule** and **point value**
2. Points are summed per category to produce a **raw score**
3. Raw scores are multiplied by the category **weight** to produce an **adjusted score**
4. Category score = `max(0, 100 + adjusted_score)` out of 100
5. **Overall grade** = weighted average of all category scores
6. Letter grade from thresholds: **A** (90+), **B** (80+), **C** (70+), **D** (60+), **F** (<60)

**Grade Categories:**

| Category | Weight | Description |
|---|---|---|
| Network Security | 1.0 | Open ports, CVEs, internal IP exposure, defacements |
| Web App Security | 1.0 | Web vulnerabilities, forms, uploads, frameworks |
| Information Leakage | 0.8 | Exposed credentials, emails, personal data, passwords |
| General Health | 0.8 | SSL certificates, code repos, coordinates, app stores |
| External Account Exposure | 0.7 | External accounts, social media, compromised accounts |
| DNS Health | 0.7 | DNS records, SPF, domain registration, WHOIS |
| IP Reputation | 0.6 | Blacklisted IPs, malicious IPs, malicious subnets |
| Information / Reference | 0.0 | Informational only — does not affect grade |

**5 Scoring Logic Types:**
- `unverified_exists` — deduct points if any unvalidated findings exist
- `zero_entries_fail` — deduct heavy penalty if expected records (like SPF) are missing entirely
- `crit_high_med` — tiered scoring for vulnerabilities (Critical: -20, High: -10, Medium: -5)
- `count_scaled` — points multiplied by unique count (with cap)
- `informational` — no penalty, purely informational

**Fully configurable** — override category weights, event type rules, and grade thresholds via JSON settings.

---

### False Positive & Validation Management

A three-state status system that persists across scans, ensuring your review work is never lost.

**Three status states:**
- **Unvalidated** (0) — default, not yet reviewed
- **False Positive** (1) — confirmed does not belong to the organization
- **Validated** (2) — confirmed belongs to the organization

**Key capabilities:**
- **Target-level persistence** — FP and Validated status is stored at the target level, so it carries forward to every future scan of the same target
- **Cross-scan sync** — changing FP status on one scan automatically syncs to all other scans for that target
- **Auto-enable persistence** — when multiple scans exist for a target, persistence activates automatically
- **Bulk status editing** — select multiple results and set FP/Validated/Unvalidated in one operation
- **Cascade to children** — marking a parent as FP automatically cascades to all child elements
- **Force override** — bypass parent element checks when unsetting FPs
- **Visual status badges** — color-coded badges (orange FP, blue Validated, gray Unvalidated) with `LEGACY` suffix for items detected from previous scan persistence
- **Client-side filtering** — toggle visibility of FP, Validated, and Imported rows in the results table
- **Target FP management** — dedicated API to list, add, and remove target-level false positives

---

### Known Asset Management

Track your organization's known IPs, domains, and employees. Match scan results against your asset inventory to quickly identify what belongs to you.

**Asset types:** IPs, Domains, Employees/Emails

**Capabilities:**
- **Bulk import** from `.txt`, `.csv`, or `.xlsx` files with auto-header detection
- **Individual CRUD** — add, update, remove, and list assets per target
- **Bulk remove** — remove multiple assets at once
- **Scan result matching** — find scan results that match known assets (Potential Matches view)
- **Two-way validation sync** — validating a scan result automatically adds it to known assets as `ANALYST_CONFIRMED`
- **Back-fill sync** — sync existing validated scan results into known assets retroactively
- **Export** — download known assets as CSV or XLSX
- **Import history** — full audit trail of import operations (file name, count, user, date)
- **Asset count dashboard** — per-target counts broken down by type and source

---

### External Vulnerability Tool Integration

Import results from industry-standard vulnerability scanners directly into ASM-NG for unified tracking and reporting.

#### Burp Suite Pro

- **Import Burp XML reports** — full parse of Burp Suite scan results with all fields (severity, host, path, location, confidence, issue background, issue detail, solutions, references, vulnerability classifications, request, response)
- **Import Burp HTML reports** — enhance existing XML data with additional detail from HTML reports (issue_detail, issue_background, solutions, references merged by plugin_name)
- **Tracking statuses** — mark each vulnerability as `OPEN`, `CLOSED`, or `TICKETED`
- **Dedicated storage** — `tbl_scan_burp_results` with 20 structured fields
- **API endpoints** — list, count, check enhanced status, set tracking, export

#### Nessus Pro

- **Import `.nessus` XML files** — full parse with all fields (severity, plugin name/ID, host IP/name, OS, description, synopsis, solution, see also, service name, port, protocol, request, plugin output, CVSS3 base score)
- **Tracking statuses** — mark each vulnerability as `OPEN`, `CLOSED`, or `TICKETED`
- **Dedicated storage** — `tbl_scan_nessus_results` with 18 structured fields
- **API endpoints** — list, count, set tracking, export

#### Nuclei

- **Native scanner module** (`sfp_tool_nuclei`) — runs Nuclei as part of the scan pipeline
- **Local and remote execution** — run locally or via SSH on remote hosts
- **Full template support** — point to any Nuclei template directory
- **Structured JSON parsing** — results parsed and stored as standard scan events

#### Generic Findings Import

- **Import from Excel** (`.xlsx`) with columns: Priority, Category, Tab, Item, Description, Recommendation
- **Dedicated storage** — `tbl_scan_findings` with structured fields
- **Export** — findings export as XLSX

#### Combined Vulnerability Export

- **XLSX** — single Excel file with `EXT-VULNS` (Nessus) and `WEBAPP-VULNS` (Burp) tabs
- **CSV** — ZIP archive containing separate CSV files per vulnerability type
- **Tracking labels** — OPEN/CLOSED/TICKETED status included in exports

---

### Auto-Sync Legacy & Historical Scan Data

Never lose previously captured data. ASM-NG automatically detects when you're viewing the latest scan for a target and imports relevant entries from all previous scans.

**Capabilities:**
- **Latest scan detection** — `LATEST` badge shown when viewing the most recent scan for a target
- **Auto-import** — when viewing the latest scan, entries from older scans are automatically imported
- **SYNC / RESYNC badges** — visual indicators for import status; click to trigger sync
- **Manual sync** — manually trigger import from older scans at any time
- **Resync** — delete previously imported entries and re-import fresh from all older scans
- **Deduplication** — remove duplicate entries while preserving FP status on kept rows
- **Provenance tracking** — every imported entry tracks which scan it came from (`imported_from_scan`)
- **Filter imported rows** — toggle visibility of imported rows in the UI

**Data Import Page:**
- **Legacy CSV Import** — import CSV exports from older SpiderFoot versions
- **Scan Backup Restore** — restore scans from ASM-NG/SpiderFoot CSV backups
- **Nessus Import** — import `.nessus` XML files
- **Burp XML Import** — import Burp Suite XML reports
- **Burp HTML Enhance** — enrich existing Burp data with HTML report details
- **FP preservation** — all F/P and validated status flags maintained during import
- **Discovery path reconstruction** — source-to-target entity relationships rebuilt from CSV data
- **Dry-run validation** — preview every import before committing (row counts, event types, warnings)
- **Auto-detection** — target, scan name, and timestamps auto-detected from import data

**CLI Import Tool:**
```bash
python3 tools/import_legacy_csv.py --csv /path/to/export.csv --name "Imported Scan" --target example.com
python3 tools/import_legacy_csv.py --csv /path/to/export.csv --dry-run  # Validate without importing
```

---

### Authentication & User Management

Full user account system with session-based authentication, replacing SpiderFoot's basic HTTP auth.

- **User accounts** — username, salted password hash, display name, active/inactive status
- **Auto-setup** — default admin user created on first startup with a secure random password
- **Session authentication** — CherryPy session-based auth with login/logout
- **Login page** — dedicated login UI with authentication enforcement on all routes
- **User management** — admin UI for creating, updating, deactivating, and deleting users
- **Login tracking** — last login timestamp per user

---

### Audit Logging

Comprehensive audit trail for compliance and forensic analysis.

- **Tracked fields** — username, action type, detail, client IP address, timestamp
- **Dedicated UI** — filterable audit log page (filter by action type, username)
- **Indexed storage** — `tbl_audit_log` with indexes on username, timestamp, and action for fast queries

---

### Advanced Correlation Engine

Multi-layered correlation analysis that surfaces patterns across modules, event types, and historical scans — no black boxes, just deterministic logic you can inspect and customize.

**Three correlation layers:**

1. **YAML Rule-Based Correlation** — 51 pre-defined rules in `/correlations/` that match patterns across event types using declarative, auditable YAML definitions
2. **Single-Scan IOC Correlation** — groups IOCs by data value and flags when the same indicator is found by multiple modules or across multiple event types, boosting confidence through multi-source corroboration
3. **Cross-Scan Historical Correlation** — matches IOCs across native scan data and imported historical data, identifying persistent indicators that recur across scans over time

**Risk classification:**
- 5-tier risk: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`
- Risk derived from event type intrinsic risk + multi-module corroboration boost + occurrence count boost
- Each of 130+ event types has an intrinsic risk score (0-100) based on severity (e.g., `MALICIOUS_*` = 90, `VULNERABILITY_CVE_HIGH` = 70, `TCP_PORT_OPEN` = 50)
- Multi-module detection boosts: 2 modules +10, 3 modules +15, 4+ modules +20
- High occurrence boosts: 5+ occurrences +5, 10+ occurrences +10

**Features:**
- **Async processing** — correlations run in the background with polling for status
- **Expandable detail rows** — each correlation links to all associated events with full provenance
- **Export** — CSV export of correlation results
- **Per-correlation risk** — individual risk level per correlation with color coding
- **Meaningful headlines** — auto-generated descriptions like "Malicious IP corroborated by 3 modules" or "DNS record persists across 4 historical scans"

---

### Automated Threat Analysis & CTI Reporting

Structured analysis modules and report generation built on the correlation engine.

- **Cross-scan threat intel** (`sfp__ai_threat_intel`) — loads IOCs from previous scans against the same target, compares against current findings to detect historical threat patterns and persistent indicators
- **Scan result summarization** (`sfp_ai_summary`) — automated summarization of scan results into structured overviews
- **CTI report generation** — generate structured Cyber Threat Intelligence reports for workspaces via MCP integration:
  - **Threat Assessment** — executive summary, threat landscape, IOCs, risk assessment, recommendations
  - **Infrastructure Analysis** — infrastructure overview, exposed services, vulnerabilities, misconfigurations
  - **Attack Surface Report** — external exposure, data leakage, third-party risks, mitigation strategies
- **Traffic Light Protocol** — TLP level support (white, green, amber, red) for report classification
- **Multiple output formats** — JSON, Markdown, PDF, HTML

---

### Enhanced Export & Reporting

Multi-format, multi-scan export capabilities for professional reporting workflows.

- **Multi-scan CSV export** — export data from multiple scans at once in a single CSV
- **Multi-scan JSON export** — combined JSON export across selected scans
- **Multi-scan GEXF** — combined graph visualization across scans
- **Legacy-compatible export** — event type mapping translates new types to legacy equivalents for existing Excel pivot table workflows
- **Vulnerability XLSX** — combined Nessus + Burp results in one Excel workbook with separate tabs
- **Findings XLSX** — structured findings export
- **Known asset CSV/XLSX** — export asset inventory
- **Full and legacy export modes** — choose between complete data or backward-compatible format

---

### Security Hardening

- **Content Security Policy** — comprehensive CSP headers (script-src, style-src, img-src, connect-src, frame-src)
- **Referrer Policy** — `no-referrer` default
- **Cache Control** — `must-revalidate`
- **Server header** — generic server identification
- **Security hardening module** (`sfp__security_hardening`) — built-in security configuration module
- **Enhanced input validation** — comprehensive sanitization across all endpoints

---

### Database Architecture

ASM-NG supports both SQLite (default) and PostgreSQL, with 9 new database tables and automatic migration on upgrade.

**New tables beyond SpiderFoot v4.0:**

| Table | Purpose |
|---|---|
| `tbl_target_false_positives` | Target-level false positive persistence across scans |
| `tbl_target_validated` | Target-level validated status persistence across scans |
| `tbl_scan_findings` | Structured findings from Excel imports |
| `tbl_scan_nessus_results` | Nessus Pro vulnerability scan results (18 fields) |
| `tbl_scan_burp_results` | Burp Suite Pro vulnerability scan results (20 fields) |
| `tbl_users` | User accounts with salted password hashes |
| `tbl_audit_log` | Audit trail with username, action, IP, timestamp |
| `tbl_known_assets` | Known asset inventory (IPs, domains, employees) |
| `tbl_asset_import_history` | Asset import operation history |

Plus enhancements to existing tables:
- `tbl_scan_results` — new `imported_from_scan` column for provenance tracking
- Comprehensive indexing on all new tables for query performance
- Auto-migration handles schema upgrades seamlessly

---

## Platform Architecture

```mermaid
graph TD;
    A[User] -->|Web UI| B[ASM-NG Core Engine];
    A -->|CLI| B;
    B --> C[274 Modules];
    B --> D[Database - SQLite/PostgreSQL];
    B --> E[REST API];
    B --> F[Workspace Manager];
    B --> G[Grading Engine];
    B --> H[Correlation Engine];
    C --> I[External Data Sources];
    E --> J[SIEM/SOAR/Integrations];
    F --> K[Multi-Target Scans];
    H --> L[YAML Rules + Cross-Scan Correlation];
    B --> M[External Tool Import - Burp/Nessus/Nuclei];
    B --> N[Asset Manager];
    B --> O[Auth & Audit];
```

---

## Getting Started

### Standard Installation (Recommended for Kali/Debian/Ubuntu)

```bash
git clone https://github.com/0x31i/asm-ng.git
cd asm-ng
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 ./sf.py -l 127.0.0.1:5001
```

On first startup, ASM-NG will create a default admin account and print the credentials to the console. Change the password after first login.

### Update Existing Installation

```bash
cd asm-ng
git pull origin master
source venv/bin/activate
pip3 install -r requirements.txt
python3 ./sf.py -l 127.0.0.1:5001
```

> **Note for Kali/Debian 12+ users:** These systems use "externally managed" Python environments. You must use a virtual environment (`python3 -m venv venv`) to install packages with pip.

### Docker Deployment

```bash
# Production deployment
docker-compose -f docker-compose-prod.yml up -d

# Development environment
docker-compose up -d
```

### CLI Command Aliases

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
alias asm-ng='python3 /path/to/asm-ng/sf.py'
alias asm-ng-cli='python3 /path/to/asm-ng/sfcli.py'
alias asm-ng-api='python3 /path/to/asm-ng/sfapi.py'
```

Or install via `pip install .` / `setup.py` which registers both legacy (`spiderfoot`) and new (`asm-ng`) CLI commands automatically.

---

## Database Configuration

### SQLite (Default)

Works out of the box. Database stored at `~/.spiderfoot/spiderfoot.db`.

### PostgreSQL

```bash
sudo apt-get install postgresql postgresql-contrib

sudo -u postgres psql
CREATE DATABASE asm_ng;
CREATE USER asm_ng_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE asm_ng TO asm_ng_user;
\q

python3 ./sf.py --init-db postgresql://asm_ng_user:secure_password@localhost/asm_ng
```

---

## Scan Targets

You can target the following entities:

- IP address
- Domain/sub-domain name
- Hostname
- Network subnet (CIDR)
- ASN
- E-mail address
- Phone number
- Username
- Person's name
- Bitcoin address

---

## REST API

### Key Endpoints

**Scans:**
- `GET /scanlist` — list all scans
- `POST /startscan` — start a new scan
- `GET /stopscan` — stop an active scan
- `GET /scaninfo` — scan detail view
- `GET /scangrade` — get scan grade with category breakdowns
- `GET /scanislatest` — check if scan is latest for target
- `GET /scanhistory` — scan result history
- `GET /scancorrelations` — get correlation results

**Results & Status:**
- `GET /scaneventresults` — get scan event results (filterable by type, FP, correlation)
- `POST /resultsetfppersist` — set FP/Validated status with target-level persistence
- `GET /scaneventresultexportmulti` — multi-scan CSV/JSON export
- `GET /scanvulnsexport` — export Nessus + Burp results as XLSX/CSV

**External Tools:**
- `POST /importnessus` — import Nessus .nessus file
- `POST /importburp` — import Burp XML
- `POST /importburphtml` — enhance Burp data with HTML report
- `POST /importfindings` — import findings from Excel
- `GET /scannessuslist` / `GET /scanburplist` — list vulnerability results

**Assets:**
- `GET /knownassetlist` — list known assets
- `POST /knownassetadd` — add an asset
- `POST /knownassetimport` — bulk import from file
- `GET /knownassetmatches` — match scan results against known assets
- `GET /knownassetexport` — export assets as CSV/XLSX

**Workspaces:**
- `GET /workspacelist` — list all workspaces
- `POST /workspacecreate` — create a workspace
- `GET /workspacesummary` — workspace statistics
- `POST /workspaceaddtarget` — add target to workspace
- `POST /workspacemultiscan` — launch multi-target scan
- `GET /workspacescancorrelations` — workspace-level correlations

**Sync & Import:**
- `POST /triggerscanmimport` — manually trigger historical import
- `POST /resyncscanentries` — delete and re-import from older scans
- `POST /deduplicatescan` — deduplicate scan results
- `POST /processimport` — process legacy CSV / Nessus / Burp import

**Admin:**
- `GET /users` — user management
- `GET /auditlog` — audit log viewer

---

## Modules & Integrations

ASM-NG has **274 modules**, most of which don't require API keys, and many that do have a free tier.

Module categories include:
- **OSINT Collection** — DNS, WHOIS, web scraping, port scanning, social media enumeration
- **Threat Intelligence** — SHODAN, HaveIBeenPwned, GreyNoise, AlienVault, SecurityTrails, and more
- **Vulnerability Scanning** — Nuclei, Nmap, CMSeeK, Whatweb, DNSTwist
- **Threat Analysis** — cross-scan threat intel, scan summarization
- **Security Hardening** — built-in hardening configuration module
- **Data Storage** — database, stdout, and custom storage backends

See the [Module Guide](documentation/modules.md) for the full list.

---

## Correlation Rules

ASM-NG includes **51 YAML correlation rules** plus automated single-scan and cross-scan correlation engines.

See the [Correlation Rules Reference](/correlations/README.md) and the [template.yaml](/correlations/template.yaml) for writing custom rules.

---

## Version Management

- **Single source of truth**: All versions controlled from the `VERSION` file
- **Automated updates**: `python update_version.py` updates all version references
- **Consistency checking**: `python update_version.py --check`
- **Release management**: `python update_version.py --set X.Y.Z`

---

## Documentation

- **[Installation Guide](documentation/installation.md)** — complete setup instructions
- **[Quick Start Guide](documentation/quickstart.md)** — get scanning quickly
- **[User Guide](documentation/user_guide.md)** — fundamental concepts and usage
- **[API Documentation](documentation/api_reference.md)** — REST API reference
- **[Module Guide](documentation/modules.md)** — understanding modules
- **In-app documentation** — accessible from the web UI at `/documentation`

---

## Community

Join the [Discord server](https://discord.gg/vyvztrG) for help, feature requests, or general OSINT discussion.

---

## Active Maintenance

ASM-NG is actively maintained with regular updates. Issues and pull requests are actively managed.

Maintainer: 0x31i <elias@sims.dev>

---

*Built on SpiderFoot. Transformed into an attack surface management platform.*
