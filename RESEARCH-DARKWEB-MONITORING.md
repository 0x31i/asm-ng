# Dark Web / Deep Web External Exposure Monitoring - Research & Plan

## Executive Summary

**Is this feasible? Yes — and ASM-NG is exceptionally well-positioned for it.**

ASM-NG already has foundational dark web capabilities (Ahmia, TORCH, OnionSearchEngine, IntelligenceX, HaveIBeenPwned, LeakIX, PasteBin). The modular plugin architecture (`sfp_*.py` → `watchedEvents` → `handleEvent` → `producedEvents`) makes adding new dark web modules straightforward. The existing event types (`DARKNET_MENTION_URL`, `DARKNET_MENTION_CONTENT`, `LEAKSITE_URL`, `LEAKSITE_CONTENT`, `BREACHED_CREDENTIALS`) and grading/correlation infrastructure already support dark web findings.

The goal: transform ASM-NG from having "some dark web awareness" into being the **most comprehensive open-source dark web external exposure tool** for companies.

---

## Current State Assessment

### What ASM-NG Already Has

| Module | What It Does | Method |
|--------|-------------|--------|
| `sfp_ahmia` | Searches Ahmia.fi for .onion mentions of target | Clearnet portal query |
| `sfp_torch` | Searches TORCH for dark web mentions | Clearnet portal query |
| `sfp_onionsearchengine` | Searches onionsearchengine.com | Clearnet portal query |
| `sfp_onioncity` | Searches Onion City | Clearnet portal query |
| `sfp_intelx` | IntelligenceX — darknet, leaks, pastes | API (free tier) |
| `sfp_haveibeenpwned` | Breach detection for emails | API (paid) |
| `sfp_leakix` | Data leaks, open ports, compromised hosts | API (free tier) |
| `sfp_leakcheck` | Leak checking | API |
| `sfp_apileak` | API key leak detection | API |
| `sfp_pastebin` | PasteBin search via Google CSE | Google API |
| `sfp_torexits` | Tor exit node detection | List-based |

### Existing Event Types for Dark Web

- `DARKNET_MENTION_URL` — URL found on dark web mentioning target
- `DARKNET_MENTION_CONTENT` — Content from dark web page
- `LEAKSITE_URL` — Leak site URL referencing target
- `LEAKSITE_CONTENT` — Content from leak site
- `BREACHED_CREDENTIALS` — Compromised credentials found
- `LEAKSITE_URL_WEBAPP` — Web app leak URL

### Gaps to Fill

1. **No direct Tor connectivity** — All current modules use clearnet proxies to Tor search engines
2. **No credential/password breach depth** — HIBP is paid-only; no free alternatives integrated
3. **No paste site monitoring beyond PasteBin** — Missing GitHub Gists, Ghostbin, Rentry, etc.
4. **No ransomware leak site monitoring** — Critical for corporate exposure
5. **No stealer log / infostealer detection** — Growing threat vector
6. **No dark web marketplace monitoring** — Mentions of company data for sale
7. **No Telegram/Discord channel monitoring** — Major leak distribution channels
8. **No MISP/OpenCTI integration** — Can't consume community threat intel feeds
9. **No onion service scanning** — Can't analyze .onion sites directly
10. **No domain typosquatting on dark web** — Brand impersonation detection

---

## Proposed New Modules & Integration Plan

### Phase 1: Free/No-Auth Dark Web Search Expansion (Low Effort, High Value)

These modules require no API keys and use clearnet portals or free services.

#### 1.1 `sfp_darkweb_aggregate` — Multi-Engine Dark Web Search
- **What**: Aggregate search across multiple Tor search engines simultaneously (Ahmia, TORCH, Phobos, Tor66, Excavator, Haystak)
- **How**: HTTP requests to clearnet portals of these search engines
- **Events**: `DARKNET_MENTION_URL`, `DARKNET_MENTION_CONTENT`
- **Effort**: Low — similar pattern to existing `sfp_ahmia`/`sfp_torch`
- **Value**: High — significantly increases dark web search coverage

#### 1.2 `sfp_xposedornot` — Free Breach Detection (HIBP Alternative)
- **What**: Free, open-source breach detection API (no API key needed for basic checks)
- **Source**: https://github.com/XposedOrNot/XposedOrNot-API
- **Events**: `BREACHED_CREDENTIALS`, `LEAKSITE_URL`
- **Effort**: Low — REST API integration
- **Value**: High — free alternative/complement to HIBP

#### 1.3 `sfp_dehashed` — DeHashed Breach Search
- **What**: Search DeHashed breach database for exposed credentials
- **Source**: https://dehashed.com
- **Events**: `BREACHED_CREDENTIALS`
- **Effort**: Low — API integration (has free tier)
- **Value**: High — one of the largest breach databases

#### 1.4 `sfp_pasterack` — Multi-Paste-Site Monitor
- **What**: Monitor multiple paste sites beyond just PasteBin: GitHub Gists, Rentry, Ghostbin, dpaste, etc.
- **How**: Google CSE queries scoped to each paste platform, or direct search APIs
- **Events**: `LEAKSITE_URL`, `LEAKSITE_CONTENT`, `DARKNET_MENTION_CONTENT`
- **Effort**: Medium — multiple sources to normalize
- **Value**: High — paste sites are a primary leak vector

#### 1.5 `sfp_deepdarkcti` — Community Threat Intelligence Feed
- **What**: Ingest curated dark web threat intelligence from the deepdarkCTI project
- **Source**: https://github.com/fastfire/deepdarkCTI (curated lists of ransomware groups, markets, forums, Telegram channels, Discord servers)
- **Events**: `DARKNET_MENTION_URL`, custom new events (see Phase 4)
- **Effort**: Low — parse YAML/markdown lists
- **Value**: Medium — provides context and watchlists

### Phase 2: Credential & Breach Intelligence (Medium Effort, Critical Value)

#### 2.1 `sfp_h8mail` — Credential Breach Hunting (Tool Integration)
- **What**: Integrate h8mail as an external tool for email/credential breach hunting
- **Source**: https://github.com/khast3x/h8mail (pip installable)
- **How**: Similar pattern to `sfp_tool_nuclei` — invoke h8mail CLI, parse JSON output
- **Events**: `BREACHED_CREDENTIALS`, `EMAIL_ADDRESS`, `LEAKSITE_URL`
- **Effort**: Medium — tool integration pattern already exists
- **Value**: Critical — aggregates multiple breach services in one tool

#### 2.2 `sfp_snusbase` — Snusbase Breach Search
- **What**: Search Snusbase for leaked credentials by email, domain, username, IP
- **Source**: https://snusbase.com (free tier available)
- **Events**: `BREACHED_CREDENTIALS`
- **Effort**: Low — REST API
- **Value**: High

#### 2.3 `sfp_breachdirectory` — BreachDirectory Lookup
- **What**: Check email/domain against BreachDirectory database
- **Source**: https://breachdirectory.org
- **Events**: `BREACHED_CREDENTIALS`
- **Effort**: Low — REST API via RapidAPI
- **Value**: Medium

#### 2.4 `sfp_proxynova` — ProxyNova Breach Search (Combo Lists)
- **What**: Search for exposed credentials in leaked combo lists
- **Events**: `BREACHED_CREDENTIALS`
- **Effort**: Low
- **Value**: Medium

### Phase 3: Dark Web Infrastructure & Active Monitoring (Higher Effort, Differentiating)

These modules set ASM-NG apart from competitors.

#### 3.1 `sfp_tor_proxy` — Native Tor SOCKS5 Proxy Support
- **What**: Add a core utility module that provides Tor SOCKS5 proxy connectivity to other modules
- **How**: Configure local Tor service or Docker container, route requests via `socks5h://127.0.0.1:9050`
- **Dependencies**: `PySocks`, `requests[socks]`, local Tor service or Docker
- **Impact**: Enables ALL dark web modules to directly access .onion sites instead of relying on clearnet proxies
- **Effort**: Medium — infrastructure module + Docker support
- **Value**: Critical — unlocks direct dark web access for all modules

#### 3.2 `sfp_tool_onionscan` — OnionScan Integration
- **What**: Integrate OnionScan for deep .onion site analysis
- **Source**: https://github.com/s-rah/onionscan (Go binary)
- **Capabilities**: Detect server misconfigurations, leaked metadata in images, exposed server status pages, SSH fingerprints, related .onion sites via shared keys
- **Events**: `DARKNET_MENTION_URL`, `VULNERABILITY_GENERAL`, new `ONION_SERVICE_*` events
- **Effort**: Medium — binary tool integration
- **Value**: High — unique capability for investigating dark web presence

#### 3.3 `sfp_tool_torbot` — TorBot Crawler Integration
- **What**: Integrate OWASP TorBot for dark web crawling
- **Source**: https://github.com/DedSecInside/TorBot (Python, pip installable)
- **Capabilities**: Crawl .onion sites, extract links, verify live status, JSON export
- **Events**: `DARKNET_MENTION_URL`, `DARKNET_MENTION_CONTENT`, `INTERNET_NAME`
- **Effort**: Medium — Python tool, good integration story
- **Value**: High

#### 3.4 `sfp_ransomwatch` — Ransomware Leak Site Monitor
- **What**: Monitor known ransomware group leak sites for mentions of target organization
- **Source**: Leverage ransomlook.io API or ransomwatch project (https://github.com/joshhighet/ransomwatch)
- **How**: Query curated list of ransomware leak sites, search for target domain/org name
- **Events**: New `RANSOMWARE_LEAK_MENTION` event type, `DARKNET_MENTION_URL`
- **Effort**: Medium — requires Tor proxy (Phase 3.1) for direct access, or clearnet API
- **Value**: Critical — ransomware is top corporate concern

#### 3.5 `sfp_telegram_osint` — Telegram Channel Monitoring
- **What**: Monitor Telegram channels known for data leaks/breaches for target mentions
- **How**: Telegram Bot API + curated channel list from deepdarkCTI
- **Events**: `LEAKSITE_URL`, `DARKNET_MENTION_CONTENT`
- **Effort**: Medium — Telegram API integration
- **Value**: High — Telegram is the new paste site

#### 3.6 `sfp_darkdump` — DarkDump Integration
- **What**: Integrate DarkDump for deep web scraping and metadata extraction
- **Source**: https://github.com/josh0xA/darkdump
- **Capabilities**: Scrape .onion sites, extract emails, metadata, keywords, images, social media references
- **Events**: `DARKNET_MENTION_URL`, `EMAIL_ADDRESS`, `DARKNET_MENTION_CONTENT`
- **Effort**: Medium
- **Value**: Medium

### Phase 4: Intelligence Platform Integration (Higher Effort, Enterprise Value)

#### 4.1 `sfp_misp` — MISP Threat Intelligence Platform Integration
- **What**: Bi-directional integration with MISP for consuming/sharing dark web threat intelligence
- **Source**: https://github.com/MISP/MISP + PyMISP library
- **Capabilities**:
  - Import: Consume MISP feeds containing dark web IOCs, leaked credentials, ransomware indicators
  - Export: Push ASM-NG scan findings to MISP for sharing
  - Correlation: Match scan targets against MISP event database
- **Events**: All existing dark web event types + MISP-specific metadata
- **Effort**: High — bidirectional sync, MISP taxonomy mapping
- **Value**: Critical for enterprise — connects to global threat intel ecosystem

#### 4.2 `sfp_opencti` — OpenCTI Integration
- **What**: Integrate with OpenCTI platform for structured threat intelligence
- **Source**: https://github.com/OpenCTI-Platform/opencti
- **How**: GraphQL API integration
- **Events**: Dark web IOCs, threat actor mappings
- **Effort**: High
- **Value**: High for enterprises with existing CTI programs

#### 4.3 `sfp_otx_darkweb` — AlienVault OTX Dark Web Pulse Integration
- **What**: Enhance existing OTX module specifically for dark web threat pulses
- **Source**: AlienVault OTX API (already partially integrated)
- **Events**: `DARKNET_MENTION_URL`, `MALICIOUS_*`
- **Effort**: Low — extend existing module
- **Value**: Medium

### Phase 5: Advanced Capabilities (Differentiators)

#### 5.1 `sfp_brand_darkweb` — Dark Web Brand Monitoring
- **What**: Monitor for brand impersonation, typosquatting, and phishing on dark web
- **How**: Combine DNSTwist-style domain generation with dark web search
- **Capabilities**: Detect lookalike .onion domains, brand mentions in dark web forums/markets
- **Events**: New `DARKWEB_BRAND_MENTION`, `DARKWEB_PHISHING_SITE` event types
- **Effort**: Medium
- **Value**: High — unique corporate value proposition

#### 5.2 `sfp_stealerlog_check` — Infostealer Log Detection
- **What**: Check if target domain credentials appear in known infostealer log aggregators
- **Sources**: Hudson Rock (free API), various OSINT stealer log indices
- **Events**: `BREACHED_CREDENTIALS`, new `STEALER_LOG_MATCH` event type
- **Effort**: Medium
- **Value**: Critical — infostealers are the fastest-growing threat vector

#### 5.3 `sfp_darkweb_market` — Dark Web Marketplace Monitor
- **What**: Search dark web marketplaces for mentions of company data, credentials, access for sale
- **How**: Requires Tor proxy (Phase 3.1), searches known marketplace indexes
- **Events**: New `DARKWEB_MARKET_LISTING` event type
- **Effort**: High — dynamic targets, anti-scraping measures
- **Value**: Very High — detects active threats

#### 5.4 Dark Web Scan Use Case Preset
- **What**: Create a new "Dark Web Exposure" scan use case preset
- **How**: Pre-select all dark web modules with recommended configuration
- **Configuration**: Tor proxy settings, API keys, crawl depth, rate limiting
- **Effort**: Low — configuration-only
- **Value**: High — usability

---

## New Event Types Required

| Event Type | Description | Category |
|-----------|-------------|----------|
| `RANSOMWARE_LEAK_MENTION` | Target mentioned on ransomware leak site | VULNERABILITY |
| `STEALER_LOG_MATCH` | Credentials found in infostealer logs | DATA |
| `DARKWEB_BRAND_MENTION` | Brand impersonation on dark web | DESCRIPTOR |
| `DARKWEB_PHISHING_SITE` | Phishing site targeting org on dark web | DESCRIPTOR |
| `DARKWEB_MARKET_LISTING` | Company data listed on dark web marketplace | DATA |
| `DARKWEB_FORUM_MENTION` | Target discussed in dark web forum | DESCRIPTOR |
| `ONION_SERVICE_DETECTED` | .onion service related to target discovered | ENTITY |
| `TELEGRAM_LEAK_MENTION` | Target mentioned in Telegram leak channel | DESCRIPTOR |

---

## New Correlation Rules Needed

```yaml
# correlations/darkweb_multi_source_mention.yaml
# Trigger when target appears across multiple dark web sources

# correlations/ransomware_leak_with_breach.yaml
# Correlate ransomware leak mentions with existing breach data

# correlations/credential_leak_cross_platform.yaml
# Correlate credentials found across breach DBs + paste sites + stealer logs

# correlations/darkweb_brand_abuse_cluster.yaml
# Group brand impersonation findings across dark web and clearnet

# correlations/darkweb_escalation.yaml
# Detect escalation pattern: paste mention → forum discussion → marketplace listing
```

---

## New Grading Integration

Add dark web findings to the grading engine in `spiderfoot/grade_config.py`:

| Event Type | Category | Weight | Rationale |
|-----------|----------|--------|-----------|
| `RANSOMWARE_LEAK_MENTION` | Information Leakage | Critical (10) | Indicates active ransomware compromise |
| `STEALER_LOG_MATCH` | Information Leakage | High (8) | Active credential compromise |
| `DARKWEB_MARKET_LISTING` | Information Leakage | High (8) | Data actively for sale |
| `DARKWEB_BRAND_MENTION` | Information Leakage | Medium (5) | Brand risk |
| `TELEGRAM_LEAK_MENTION` | Information Leakage | Medium-High (6) | Active leak distribution |

---

## Technical Architecture

### Tor Connectivity Strategy

```
Option A: Local Tor Service (Recommended)
├── Install Tor service on host
├── Configure SOCKS5 proxy on port 9050
├── ASM-NG modules use socks5h://127.0.0.1:9050
└── Circuit rotation via Stem library for IP cycling

Option B: Docker Tor Container
├── docker-compose service running Tor
├── Exposed SOCKS5 port to ASM-NG network
├── Separate container = isolation
└── Easy to rebuild/rotate

Option C: Clearnet Only (Current approach, no Tor needed)
├── Use clearnet proxies to Tor search engines
├── Query APIs that index dark web content
├── Limited but zero-infrastructure overhead
└── Suitable for many corporate environments
```

### Module Dependency Graph

```
sfp_tor_proxy (infrastructure)
    ├── sfp_tool_onionscan
    ├── sfp_tool_torbot
    ├── sfp_darkdump
    ├── sfp_ransomwatch (direct mode)
    └── sfp_darkweb_market

Independent (no Tor needed):
    ├── sfp_xposedornot
    ├── sfp_dehashed
    ├── sfp_h8mail
    ├── sfp_snusbase
    ├── sfp_breachdirectory
    ├── sfp_darkweb_aggregate (clearnet portals)
    ├── sfp_pasterack
    ├── sfp_deepdarkcti
    ├── sfp_misp
    ├── sfp_opencti
    ├── sfp_telegram_osint
    ├── sfp_brand_darkweb (partial)
    └── sfp_stealerlog_check (API-based)
```

---

## Implementation Priority Matrix

| Priority | Module | Effort | Value | Dependencies |
|----------|--------|--------|-------|-------------|
| **P0** | `sfp_xposedornot` | Low | High | None |
| **P0** | `sfp_darkweb_aggregate` | Low | High | None |
| **P0** | `sfp_ransomwatch` | Low-Med | Critical | None (API mode) |
| **P0** | `sfp_pasterack` | Medium | High | None |
| **P1** | `sfp_h8mail` | Medium | Critical | pip install h8mail |
| **P1** | `sfp_dehashed` | Low | High | API key (free tier) |
| **P1** | `sfp_stealerlog_check` | Medium | Critical | API access |
| **P1** | `sfp_deepdarkcti` | Low | Medium | None |
| **P1** | `sfp_telegram_osint` | Medium | High | Telegram Bot API |
| **P2** | `sfp_tor_proxy` | Medium | Critical | Tor service |
| **P2** | `sfp_tool_torbot` | Medium | High | Tor proxy, pip |
| **P2** | `sfp_tool_onionscan` | Medium | High | Tor proxy, Go binary |
| **P2** | `sfp_brand_darkweb` | Medium | High | Partial Tor |
| **P2** | `sfp_snusbase` | Low | Medium | API key |
| **P3** | `sfp_misp` | High | Critical | MISP instance |
| **P3** | `sfp_opencti` | High | High | OpenCTI instance |
| **P3** | `sfp_darkweb_market` | High | Very High | Tor proxy |
| **P3** | `sfp_darkdump` | Medium | Medium | Tor proxy |

---

## Legal & Ethical Considerations

### Corporate Dark Web Monitoring — Legal Framework

1. **Passive Monitoring Is Generally Legal**: Searching for your own company's data on the dark web is legally defensible. You're searching for evidence of crimes committed *against* you.

2. **No Purchasing / Engaging**: ASM-NG should never interact with, purchase from, or engage with dark web marketplace sellers. Read-only observation only.

3. **Data Handling Obligations**:
   - If breached personal data is found (employee/customer PII), GDPR/CCPA obligations may be triggered
   - Store findings with appropriate access controls
   - Consider data retention policies for breach data

4. **Tor Network Ethics**:
   - Rate-limit all Tor requests to avoid straining the volunteer network
   - Do not run excessive crawling operations
   - Respect `robots.txt` even on .onion sites where applicable

5. **Terms of Service**:
   - Some APIs (Google, IntelligenceX) have ToS restrictions on automated bulk queries
   - Ensure compliance with each integrated service's terms

6. **Recommendations**:
   - Add a legal disclaimer/acknowledgment in the UI when dark web modules are enabled
   - Include rate limiting as default for all dark web modules
   - Log all dark web queries in the audit trail
   - Corporate users should have legal counsel review before enabling direct Tor modules

---

## Competitive Advantage

### What This Would Give ASM-NG Over Competitors

| Capability | SpiderFoot HX | Commercial Tools | ASM-NG (Proposed) |
|-----------|--------------|-----------------|-------------------|
| Dark web search engines | 3-4 | Proprietary | 6+ (aggregated) |
| Breach database checks | HIBP only | Proprietary feeds | 5+ free sources |
| Paste site monitoring | PasteBin | Multi-platform | Multi-platform |
| Ransomware leak monitoring | No | Yes (expensive) | Yes (free) |
| Infostealer log detection | No | Some | Yes |
| Tor direct access | No | Yes | Yes (optional) |
| MISP/CTI integration | No | Some | Full bidirectional |
| Telegram monitoring | No | Some | Yes |
| Marketplace monitoring | No | Yes | Yes (with Tor) |
| Brand monitoring (dark web) | Basic | Yes | Yes |
| Open source / Free | HX is paid | No | Yes |
| Correlation across sources | Basic | Yes | Advanced (YAML rules) |
| Security grading impact | No | Some | Yes (weighted grades) |

### The Key Differentiator

No other **free, open-source** tool combines:
- Multi-engine dark web search aggregation
- Free breach database correlation (no HIBP dependency)
- Ransomware leak site monitoring
- Infostealer log detection
- MISP/OpenCTI threat intel platform integration
- Telegram leak channel monitoring
- YAML-driven correlation rules
- Security grading that factors in dark web exposure
- All within a single, unified ASM platform

---

## Rough Implementation Roadmap

### Sprint 1 (1-2 weeks): Quick Wins
- [ ] `sfp_xposedornot` — Free breach detection
- [ ] `sfp_darkweb_aggregate` — Multi-engine dark web search
- [ ] `sfp_deepdarkcti` — Threat intel feed ingestion
- [ ] New event types registered in `db.py`
- [ ] Grade config updates for new event types
- [ ] "Dark Web Exposure" scan use case preset

### Sprint 2 (2-3 weeks): Credential Intelligence
- [ ] `sfp_h8mail` — Tool integration for breach hunting
- [ ] `sfp_dehashed` — DeHashed API integration
- [ ] `sfp_pasterack` — Multi-paste-site monitoring
- [ ] `sfp_stealerlog_check` — Infostealer log detection
- [ ] Correlation rules for credential findings

### Sprint 3 (2-3 weeks): Active Dark Web Capabilities
- [ ] `sfp_tor_proxy` — Tor SOCKS5 infrastructure module
- [ ] `sfp_ransomwatch` — Ransomware leak site monitoring
- [ ] `sfp_telegram_osint` — Telegram channel monitoring
- [ ] `sfp_brand_darkweb` — Brand impersonation detection
- [ ] Docker compose updates for Tor service

### Sprint 4 (3-4 weeks): Enterprise & Advanced
- [ ] `sfp_tool_torbot` — TorBot crawler integration
- [ ] `sfp_tool_onionscan` — OnionScan integration
- [ ] `sfp_misp` — MISP bidirectional integration
- [ ] `sfp_darkweb_market` — Marketplace monitoring
- [ ] Comprehensive correlation rules
- [ ] Documentation and setup guides

---

## Conclusion

**This is absolutely feasible.** ASM-NG's module architecture makes it almost trivially easy to add new data sources — each module is a self-contained Python class following a well-defined interface. The existing event type system, grading engine, and correlation framework already support dark web findings and can be extended.

The biggest value comes from the **aggregation effect** — no single free tool covers everything, but combining 15+ free/open-source tools into ASM-NG's unified platform creates something more powerful than any individual commercial tool. The correlation engine then adds intelligence by connecting findings across sources (e.g., "email found in breach DB + mentioned on ransomware leak site + credentials in stealer logs = critical alert").

Phase 1 (quick wins) can be implemented in 1-2 weeks and immediately provides significant value. Phases 2-3 build toward a comprehensive dark web monitoring capability. Phase 4 integrates with the broader threat intelligence ecosystem for enterprise use.

---

---

## Additional High-Value Tools Discovered in Deep Research

### AIL Framework (Analysis of Information Leaks) — **TOP RECOMMENDATION**

**This is the single most important tool to consider integrating.**

- **URL**: https://github.com/ail-project/ail-framework
- **License**: AGPL-3.0
- **Maintained by**: CIRCL (Computer Incident Response Center Luxembourg) — actively maintained, v6.2+ released
- **What it does**: A modular framework to collect, crawl, dig, and analyse unstructured data from paste sites, Tor hidden services, Telegram, Discord, and custom feeds. Detects credit cards, credential leaks, emails, .onion addresses, cryptocurrency addresses. Supports YARA rule matching and retro-hunting. Has an advanced Tor crawler supporting pre-recorded session cookies for accessing forums. Used by EU law enforcement via the HOPLITE project.
- **Why it matters**: Integrates natively with MISP and TheHive. Has ZMQ/Kafka pub-sub for real-time event streaming. Its modular importer/exporter architecture could feed directly into ASM-NG.
- **Integration approach**: Could run as a companion service (Docker) with ASM-NG consuming its events via ZMQ or MISP bridge.

### Darkweb-Scanner (OSINTPH)

- **URL**: https://github.com/osintph/darkweb-scanner
- **License**: AGPL-3.0
- **What it does**: Self-hosted threat intel platform with async Tor crawling, Telegram channel monitoring, ransomware group tracking, threat actor profiling, and daily intelligence digests. Single Docker deployment.
- **Integration**: Docker deployment, keyword monitoring for corporate domains, daily digest fits SOC workflows.

### OnionIngestor

- **URL**: https://github.com/danieleperera/OnionIngestor
- **What it does**: Daemon-based tool modeled after ThreatIngestor. Three components: Sources (PasteBin, Twitter, Gist, crawled links), Operators (fetch HTML, screenshots, run OnionScan), Notifiers (daily reports, change alerts). Elasticsearch indexing.
- **Integration**: Sources/Operators/Notifiers pattern maps well to ASM data pipelines.

### pystemon — Paste Site Monitor

- **URL**: https://github.com/cvandeplas/pystemon
- **What it does**: Monitors multiple PasteBin-alike sites with configurable random wait times, hit-count triggering, exclusion regex, custom email alerts per pattern.
- **Integration**: Best paste monitoring tool for ASM — configure with corporate domain patterns.

### EmploLeaks — Employee Breach Checker

- **URL**: https://github.com/infobyte/emploleaks
- **What it does**: Searches LinkedIn for company employees, then checks those employees against HIBP, Firefox Monitor, LeakCheck, and BreachAlarm.
- **Integration**: Automates "find employees → check for breaches" workflow core to external exposure.

### TruffleHog & Gitleaks — Secret Scanning

- **TruffleHog**: https://github.com/trufflesecurity/trufflehog (AGPL-3.0, 700+ credential detectors with active API verification)
- **Gitleaks**: https://github.com/gitleaks/gitleaks (MIT, 150+ patterns, 24K+ stars)
- **Integration**: Scan discovered public repositories for leaked API keys, secrets, credentials. ASM-NG already has `sfp_tool_trufflehog` — verify coverage depth.

### Fresh Onions (GoSecure Fork) — Tor Spider

- **URL**: https://github.com/gosecure/freshonions-torscraper
- **License**: AGPL-3.0
- **What it does**: Tor spider with 8 Tor instances, Squid/Privoxy load balancing. Extracts Bitcoin addresses, emails, inter-onion links. Docker + Elasticsearch.
- **Integration**: Elasticsearch output enables correlation with ASM-NG data.

### Onion-Lookup (AIL Project)

- **URL**: https://onion.ail-project.org/
- **What it does**: Free API for checking existence of Tor hidden services and retrieving metadata.
- **Integration**: Quick API call to verify if threat actor .onion services are active.

### Thorion

- **URL**: https://thorion.mjolnirlabs.com/
- **What it does**: Tor OSINT tool with named sessions, .onion scanning, IOC extraction, hashed evidence collection. Exports as Markdown/JSON/HTML with evidence manifests and hash chains.
- **Integration**: Evidence chain with hash verification valuable for compliance.

---

## Revised Tool Integration Summary Table

| Tool | Category | License | Maintained | Stars | ASM Fit |
|------|----------|---------|------------|-------|---------|
| **AIL Framework** | Full monitoring platform | AGPL-3.0 | Yes (CIRCL) | ~1.4K | Excellent |
| **MISP** | Threat intel sharing | AGPL-3.0 | Yes | Very High | Excellent |
| **OpenCTI** | Threat intel platform | Apache-2.0 | Yes | ~8.1K | Excellent |
| **TruffleHog** | Secret scanning | AGPL-3.0 | Yes | Very High | Excellent |
| **Gitleaks** | Secret scanning | MIT | Yes | ~24.4K | Excellent |
| **deepdarkCTI** | CTI reference database | GPL-3.0 | Yes | ~6.5K | Reference feed |
| **Ahmia** | Tor search engine | BSD-3 | Yes | Moderate | Excellent |
| **TorBot (OWASP)** | Dark web crawler | Custom OSS | Partial | ~3.7K | Medium |
| **OnionScan** | .onion scanner | MIT | No (2017) | ~3.1K | Low (unmaintained) |
| **DarkDump** | Deep web search | MIT | Moderate | Low | Medium |
| **pystemon** | Paste monitoring | OSS | Moderate | Low | Good |
| **EmploLeaks** | Employee breach check | OSS | Moderate | Low | Good |
| **Fresh Onions** | Tor spider | AGPL-3.0 | GoSecure fork | Low | Good |
| **OnionIngestor** | Ingestion framework | OSS | Early stage | Low | Medium |
| **Darkweb-Scanner** | Threat intel platform | AGPL-3.0 | Yes | Low | Good |
| **h8mail** | Breach hunting | OSS | Yes | Moderate | Good |

---

## Feasibility Tiers

| Tier | What | Feasibility | Open Source Coverage |
|------|------|-------------|---------------------|
| **High** | Breach DB checks, paste monitoring, OSINT feeds | Straightforward | Excellent — many free APIs/tools |
| **Medium** | Crawling public .onion sites, keyword alerts, Telegram monitoring | Achievable with Tor infra | Good — AIL Framework, TorBot, Ahmia |
| **Low** | Private/invite-only forums and marketplaces | Requires manual access, CAPTCHAs, reputation | Poor — this is where commercial tools (DarkOwl, Flashpoint, Recorded Future) excel |

**Recommended approach**: Use open-source tools for high and medium tiers. Consider commercial feed integration (optional connector) for low tier if organizations require that depth.

---

## Sources & References

### Open Source Tools
- [AIL Framework](https://github.com/ail-project/ail-framework) — Comprehensive dark web analysis platform (CIRCL)
- [OnionScan](https://github.com/s-rah/onionscan) — .onion site vulnerability scanner
- [TorBot (OWASP)](https://github.com/DedSecInside/TorBot) — Dark web crawler
- [DarkDump](https://github.com/josh0xA/darkdump) — Deep web scraping interface
- [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) — Curated dark web threat intelligence
- [h8mail](https://github.com/khast3x/h8mail) — Email OSINT & breach hunting
- [XposedOrNot](https://github.com/XposedOrNot/XposedOrNot-API) — Open-source breach detection API
- [ransomwatch](https://github.com/joshhighet/ransomwatch) — Ransomware leak site monitor
- [MISP](https://github.com/MISP/MISP) — Threat intelligence sharing platform
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti) — Cyber threat intelligence platform
- [IntelligenceX SDK](https://github.com/IntelligenceX/SDK) — IntelligenceX API wrapper
- [pwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) — HIBP-based password finder
- [Dark Web OSINT Tools](https://github.com/apurvsinghgautam/dark-web-osint-tools) — Curated tool list
- [Ahmia](https://github.com/ahmia/) — Tor search engine (open source)
- [pystemon](https://github.com/cvandeplas/pystemon) — Multi-paste-site monitor
- [EmploLeaks](https://github.com/infobyte/emploleaks) — Employee breach checker
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — Secret scanner with active verification
- [Gitleaks](https://github.com/gitleaks/gitleaks) — Git secret scanner
- [Fresh Onions (GoSecure)](https://github.com/gosecure/freshonions-torscraper) — Tor spider
- [OnionIngestor](https://github.com/danieleperera/OnionIngestor) — Onion link ingestion daemon
- [Darkweb-Scanner](https://github.com/osintph/darkweb-scanner) — Self-hosted dark web threat intel
- [Onion-Lookup](https://onion.ail-project.org/) — .onion service verification API
- [Thorion](https://thorion.mjolnirlabs.com/) — Tor OSINT with evidence chains

### APIs & Services (Free Tiers)
- [HaveIBeenPwned API v3](https://haveibeenpwned.com/API/v3)
- [DeHashed](https://dehashed.com)
- [LeakIX](https://leakix.net/)
- [IntelligenceX](https://intelx.io/)
- [PhoneBook.cz](https://phonebook.cz/)
- [Ahmia.fi](https://ahmia.fi/)
- [Snusbase](https://snusbase.com)
- [BreachDirectory](https://breachdirectory.org)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Shadowserver Foundation](https://www.shadowserver.org/)
- [CISA AIS](https://www.cisa.gov/automated-indicator-sharing)

### Research & Context
- [SOCRadar: Dark Web Monitoring with Open-Source Tools](https://socradar.io/blog/dark-web-monitoring-with-open-source-tools-services/)
- [DeepStrike: Best Dark Web Monitoring Tools 2025](https://deepstrike.io/blog/best-dark-web-monitoring-tools)
- [Prey: Open-source vs. Paid Dark Web Monitoring](https://preyproject.com/blog/open-source-vs-paid-dark-web-monitoring-which-one-is-best)
- [Brandefense: Top OSINT Tools for Dark Web](https://brandefense.io/blog/dark-web/top-open-source-intelligence-osint-tools-for-dark-web/)
- [OSINT Team: Essential OSINT Tools for Dark Web](https://www.osintteam.com/osint-tools-for-the-dark-web/)
- [DOJ: Legal Considerations for Dark Web Intelligence](https://www.justice.gov/criminal/criminal-ccips/page/file/1252341/dl?inline=)
- [Webz.io: Top 10 Open Source Tools for Dark Web Monitoring](https://webz.io/dwp/top-open-source-tools-for-dark-web-monitoring/)
- [Troy Hunt: Open Sourcing HIBP](https://www.troyhunt.com/im-open-sourcing-the-have-i-been-pwned-code-base/)
