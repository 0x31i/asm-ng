# Zero-key open-source tools for attack surface management

**Every major ASM capability — Google dorking, subsidiary discovery, brand impersonation detection, web searching, and site fingerprinting — can be built entirely from free, open-source tools requiring no API keys.** This report catalogs 55+ confirmed tools across five capability areas, each verified for zero-key operation, active maintenance, and Python/SpiderFoot integration readiness. The toolchain centers on a SearXNG + dnstwist + Amass + httpx + Phishpedia core that covers any industry's brand protection needs. Several widely recommended tools (Whoogle, aquatone, asnmap) are now broken, abandoned, or secretly require keys — these are flagged explicitly below.

---

## Area 1: Google dorking without API keys is solved

Two tiers of tools handle programmatic web searching with zero API keys: direct scrapers and multi-engine aggregators.

**Direct Google scraping** is best served by the **yagooglesearch + pagodo** combination. yagooglesearch (BSD-3, ~264 stars) is a Python library that scrapes Google's HTML results directly, with **randomized User-Agent rotation**, configurable delays (7–17s between pages, 30–60s between queries), HTTP 429 detection with exponential backoff, and SOCKS5/HTTP proxy support. It supports all Google operators natively (site:, inurl:, intitle:, filetype:) and yields ~400 results per query. pagodo (GPL-3.0, ~3,200 stars) sits on top, automating all **4,000+ Google Hacking Database dorks** against target domains with jitter and round-robin proxy rotation. Both received commits through April 2025.

**Multi-engine searching** has a clear winner: **ddgs** (MIT, ~8,000+ stars), the 2025 rewrite of duckduckgo_search. It confirmed delivers **9 text search backends — Bing, Brave, DuckDuckGo, Google, Grokipedia, Mojeek, Yandex, Yahoo, and Wikipedia** — all scraped without API keys. It also offers image, video, news (3 backends), and book search. Auto-mode rotates backends randomly. Active through February 2026 with MCP server support.

**SearXNG** (AGPL-3.0, ~25,500 stars) is the infrastructure play. Deploy via Docker (`docker compose up -d`), enable JSON output in `settings.yml`, and query 70+ engines through a unified REST API: `GET /search?q=site:target.com&format=json&engines=google,bing,duckduckgo`. All major engines (Google, Bing, DuckDuckGo, Brave, Startpage, Qwant, Yahoo, Mojeek) work without API keys configured. Search operators pass through to underlying engines. Updated weekly through February 2026.

**Whoogle is effectively dead.** Google broke JavaScript-free search in January 2025 (Issue #1211). The December 2025 release added a Google Custom Search Engine fallback — which **requires an API key**. The maintainer warned there may be "no further updates." Do not depend on Whoogle for ASM automation.

Additional tools worth noting: **Search-Engines-Scraper** (DatapaloozaCO enhanced fork) covers 11 engines including Tor/Torch for dark web; **scholarly** scrapes Google Scholar without keys but requires proxy rotation due to aggressive blocking; **search-engine-parser** covers 20+ engines with pip-installable simplicity.

| Tool | Stars | Language | Zero-Key | Engines | Operators | Active | Integration |
|------|-------|----------|----------|---------|-----------|--------|-------------|
| **ddgs** | ~8,000 | Python | ✅ Yes | 9 | Backend-dependent | Feb 2026 | Very Low |
| **SearXNG** | ~25,500 | Python | ✅ Yes | 70+ | Full pass-through | Feb 2026 | Medium |
| **yagooglesearch** | ~264 | Python | ✅ Yes | Google | Full | Apr 2025 | Very Low |
| **pagodo** | ~3,200 | Python | ✅ Yes | Google (GHDB) | Full | Apr 2025 | Low |
| **Search-Engines-Scraper** | ~200 | Python | ✅ Yes | 11 (incl. Torch) | Varies | 2024 | Very Low |
| **search-engine-parser** | ~500 | Python | ✅ Yes | 20+ | Varies | 2023 | Very Low |
| **go-dork** | ~1,000 | Go | ⚠️ Partial | 6 (Shodan needs key) | Yes | 2022 ⚠️ | Medium |
| **scholarly** | ~1,500 | Python | ✅ Yes | Google Scholar | N/A | Active | Very Low |
| **Whoogle** | ~11,000 | Python | ❌ Broken | Google only | N/A | ❌ Dead | N/A |

---

## Area 2: Subsidiary discovery chains three free data layers

Discovering affiliated organizations works through three complementary approaches: structured corporate data, infrastructure pivoting, and web content analysis — all achievable without API keys.

### Corporate registries deliver structured ownership data for free

**SEC EDGAR** is the gold standard for US public companies. The API requires zero authentication — only a User-Agent header with company name and email per SEC fair-use policy. The critical endpoint is **Exhibit 21** in 10-K filings, which lists all subsidiaries of ~8,000+ public companies. The **edgartools** Python library (actively maintained, pip-installable) parses these filings directly. Additional endpoints: `data.sec.gov/submissions/CIK##########.json` for filing history, `efts.sec.gov/LATEST/search-index` for full-text search.

**GLEIF** (Legal Entity Identifier) provides global corporate ownership without keys or registration. The REST API at `api.gleif.org/api/v1` offers direct-parent and ultimate-parent relationships, fuzzy name matching, and covers **2.5M+ entities** worldwide. Query `/lei-records?filter[entity.legalName]=Acme` to search, then `/lei-records/{LEI}/direct-parent` for hierarchy traversal.

**Wikidata SPARQL** returns organizational relationships through properties P749 (parent organization), P355 (subsidiary), P127 (owned by), and P361 (part of). The query endpoint at `query.wikidata.org/sparql` requires no keys. Coverage is strong for major public companies but inconsistent for private firms. The **SPARQLWrapper** Python library handles queries directly.

**ProPublica's Nonprofit Explorer API** covers 1.8M+ nonprofits without authentication: search by name/EIN, access Schedule R (related organizations), and download financial data. The IRS also publishes all e-filed 990 XMLs on AWS S3 for free.

### Infrastructure pivoting maps organizations to digital assets

**OWASP Amass** (Go, actively maintained) is the cornerstone. These commands work with **zero API keys configured**:

- `amass intel -org "Company Name"` → finds ASN IDs from BGP/WHOIS data
- `amass intel -asn 12345` → discovers domains on that ASN
- `amass intel -whois -d example.com` → reverse WHOIS for related domains
- `amass enum -passive -d example.com` → passive subdomain enumeration via free sources (crt.sh, Wayback)
- Active DNS brute force, zone transfers, certificate grabbing from IP ranges

**crt.sh** deserves special mention: completely free, no registration, supports wildcard queries (`%.acme.com`), JSON output via `?output=json`, and even **direct PostgreSQL access** (`psql -h crt.sh -p 5432 -U guest certwatch`). Certificate SANs (Subject Alternative Names) frequently reveal cross-brand infrastructure connections.

**theHarvester** (~15,300 stars) works with 15+ sources without keys: Bing, DuckDuckGo, Google, crt.sh, AlienVault OTX, RapidDNS, HackerTarget, Yahoo, and others. Sources like VirusTotal, Shodan, and SecurityTrails require keys and should be treated as optional enrichments.

### Industry-specific registries fill vertical gaps

| Industry | Source | Zero-Key | Data |
|----------|--------|----------|------|
| Healthcare | NPPES NPI Registry API | ✅ Yes | All NPI records, org names, addresses, taxonomies |
| Financial | FDIC BankFind API | ✅ Yes | Banks, branches, holding companies |
| Financial | SEC EDGAR | ✅ Yes | Public company subsidiaries (Exhibit 21) |
| Government | USASpending.gov API | ✅ Yes | Federal award recipients, parent-child orgs |
| Government | SAM.gov API | ❌ Free key required | Contractor registrations, entity hierarchy |
| Education | NCES IPEDS | ✅ Yes | Postsecondary institutions, system hierarchies |
| Energy | EIA API | ❌ Free key required | Energy companies, facilities |
| Transportation | NHTSA API | ✅ Yes | Vehicle manufacturers, plants, brands |
| Technology | Wikidata + SEC + GLEIF | ✅ Yes | Combined coverage for tech hierarchies |
| Nonprofit | ProPublica 990 API | ✅ Yes | 1.8M+ nonprofits, related orgs |

**Tools that falsely appear free:** **OpenCorporates** aggregates 200M+ companies across 145 jurisdictions but its API requires an `api_token` (free only for approved public-benefit projects). **asnmap** by ProjectDiscovery now requires a free PDCP cloud account registration — not truly zero-key. **DomLink** requires a Whoxy.com API key for reverse WHOIS.

---

## Area 3: Brand impersonation detection is strongest zero-key category

### dnstwist anchors domain permutation with 15+ fuzzing algorithms

**dnstwist** (Apache 2.0, ~5,300 stars) is the undisputed leader. All major features work without API keys: **DNS resolution** (A, AAAA, NS, MX), **WHOIS lookups** (pure Python implementation since v20230918), **fuzzy hashing** via `--lsh` (ssdeep or TLSH), **perceptual hashing** via `--phash` (headless Chromium), **screenshots** via `--screenshots`, **MX mail acceptance checking**, and **HTTP/SMTP banner grabbing**. The only quasi-dependency: GeoIP requires downloading MaxMind's GeoLite2 database (free registration, one-time), but the runtime lookup is fully local.

The tool generates permutations via addition, bitsquatting, homoglyph, hyphenation, insertion, omission, plural, repetition, replacement, subdomain, transposition, vowel-swap, dictionary, and TLD-swap algorithms. It's pip-installable and importable as a Python module via the `Fuzzer` class.

**URLInsane** (MIT, ~900 stars, Go) adds multilingual keyboard support (Spanish, Russian, Finnish, Arabic) and is actively developing an AI-based classifier. **URLCrazy** (Ruby, ~800 stars) was updated July 2025 with new prefix/suffix typo types. **catphish** is effectively abandoned since ~2017 — skip it.

### Certificate Transparency monitoring requires self-hosting certstream

**CaliDog's certstream is unreliable.** Multiple issues since early 2024 confirm `wss://certstream.calidog.io/` frequently returns no data. The fix: **certstream-server-go** (Go, actively maintained) is a drop-in replacement. Self-host it for ~40MB RAM and ~14.5 Mbit/s bandwidth to get a real-time CT certificate stream. Zero keys, Docker-ready.

**crt.sh** handles retroactive CT searches. **phishing_catcher** (GPL-3.0, ~1,700 stars) applies keyword/entropy scoring to certstream data — the concept is sound but the codebase is unmaintained since ~2018. Fork and modernize or reimplement the scoring logic.

### Newly registered domain monitoring catches brand abuse early

**openSquat** (GPL-3.0, ~930 stars) is purpose-built for this. Without a VirusTotal key, it still provides: automatic daily NRD feed download (WhoisDS.com), keyword matching with **Levenshtein and Jaro-Winkler** similarity, homograph attack detection, DNS validation via Quad9, CT monitoring, port checking, and phishing database cross-referencing. What's lost without VT: malware/subdomain enrichment (optional).

Free NRD data feeds: **WhoisDS.com** provides free daily feeds consumed by openSquat and nrd-list-downloader. **Shreshta Labs** publishes 10,000 NRDs daily from weekly and monthly datasets on GitHub. **ViewDNS.info** launched a free week-delayed NRD dataset in December 2025 covering 1,000+ TLDs.

### Visual detection closes the impersonation identification loop

**Phishpedia** (Python/PyTorch, ~316 stars, updated July 2025) uses a two-stage deep learning pipeline: Faster R-CNN detects logos in webpage screenshots, then a Siamese network compares them against 181+ known brand logos via cosine similarity. Performance: **99% brand identification accuracy, 98% precision, 0.19s per screenshot**. Adding a new brand requires only inserting logo images and legitimate domains — no retraining. **PhishIntention** extends this with credential-harvesting form detection.

**imagehash** (BSD, ~3,000 stars) provides perceptual hashing (aHash, pHash, dHash, wHash) for screenshot comparison. **gowitness** (GPLv3, ~4,200 stars) captures bulk screenshots with headless Chrome and stores them in SQLite with built-in perceptual hash grouping. **EyeWitness** (GPLv3, ~5,600 stars) is the Python-native alternative with HTML report generation.

**Phishing intelligence feeds** that work without keys: **OpenPhish** (feed.txt, updated every 12 hours), **PhishTank** (online-valid.csv, 6-hour updates without key, 3-hour with free key), **URLhaus** (hourly/daily feeds downloadable without auth, though the REST API needs a free registration key).

**Passive DNS reality check:** True passive DNS databases almost universally require at least free registration. The practical zero-key alternatives are **crt.sh** (CT-based domain discovery) plus direct DNS resolution of permutated domains via dnstwist.

---

## Area 4: SearXNG and archive APIs form the search backbone

**SearXNG is the single most important infrastructure component.** Deploy one Docker instance and every tool in the pipeline gains access to 70+ search engines via `GET /search?q=<query>&format=json`. Enable JSON output in `settings.yml`, disable the limiter for internal use, and configure proxy rotation under `outgoing:` settings. For load distribution, deploy multiple instances with different engine subsets behind a load balancer. Each instance is stateless.

**Wayback Machine CDX API** is confirmed completely free with no authentication. Endpoint: `http://web.archive.org/cdx/search/cdx?url=*.example.com&output=json`. Supports wildcards (`*.example.com`), date filtering (`&from=20240101&to=20251231`), custom field selection, and pagination via `resumeKey`. The **waybackpy** Python library and **cdx_toolkit** (which also queries Common Crawl) provide clean wrappers. This is essential for **evidence collection** — finding historical snapshots of impersonation sites even after takedown.

**Common Crawl** publishes monthly crawl indices at `index.commoncrawl.org`, completely free with no auth. Wildcard queries (`*.brandname.com`) work. Each crawl covers billions of pages. Use **cdx_toolkit** for unified access to both Wayback and Common Crawl from a single Python API.

**Archive.org's Advanced Search API** (`archive.org/advancedsearch.php?q=<query>&output=json`) searches item metadata without keys. The `internetarchive` Python library supports full-text search via `search_items(query, full_text_search=True)`.

Newer self-hosted search engines (Stract, Mwmbl, Alexandria) have indexes too small for OSINT utility. **Stick with SearXNG.**

---

## Area 5: Website fingerprinting confirms impersonation without keys

### httpx is the Swiss Army knife of HTTP probing

**httpx** (MIT, ~9,600 stars, Go) probes suspect URLs and returns: status codes, page titles, server headers, **tech stack detection** (Wappalyzer dataset), **favicon MMH3 hashes**, body hashes (MD5, MMH3, simhash, SHA256), **JARM TLS fingerprints**, CDN/WAF detection, ASN data, TLS certificate info, screenshots (headless Chrome), and response times. All zero-key. Updated January 2025. A single httpx scan against a suspect domain produces most signals needed for impersonation scoring.

**WhatWeb** (GPLv2, ~6,400 stars, Ruby) goes deeper with **1,800+ technology detection plugins** across four aggression levels. SpiderFoot already has a WhatWeb module. The **enthec/webappanalyzer** (GPL-3.0, 428 stars, updated December 2025) is the community-maintained fork of Wappalyzer's detection rules after Wappalyzer went private in August 2023.

### Content hashing quantifies similarity between legitimate and suspect sites

**TLSH** (Apache 2.0, Trend Micro) is the recommended fuzzy hash for impersonation detection — more resistant to adversarial evasion than ssdeep, adopted as a STIX 2.1 standard, and produces a distance metric (0 = exact match) ideal for automated thresholds. Install via `pip install py-tlsh`. **ppdeep** (Apache 2.0, pure Python ssdeep by the dnstwist author) removes the C library dependency for containerized deployments. Both are zero-key, local-only computation.

### katana leads modern web crawling

**katana** (MIT, ~15,600 stars, Go) is the most capable crawler: headless Chrome mode with JS rendering, XHR extraction, form discovery (`-automatic-form-fill`), tech detection (`-td`), scope control via regex, and TLS impersonation. Updated January 2025. Use it to deeply map suspect sites and compare structure against legitimate ones.

**waymore** (Python, ~4,000 stars) is the best URL history tool — queries Wayback, Common Crawl, AlienVault OTX, URLScan, and GhostArchive without keys, and uniquely **downloads archived responses** (not just URLs). This enables comparing historical legitimate content against current suspect content.

---

## Master inventory of all confirmed zero-key tools

| # | Tool | Area | GitHub URL | Stars | Lang | License | Zero-Key | Maintained | Python Integration |
|---|------|------|-----------|-------|------|---------|----------|------------|-------------------|
| 1 | ddgs | Search | github.com/deedy5/ddgs | ~8,000 | Python | MIT | ✅ | ✅ Feb 2026 | Very Low |
| 2 | SearXNG | Search | github.com/searxng/searxng | ~25,500 | Python | AGPL-3.0 | ✅ | ✅ Feb 2026 | Medium |
| 3 | yagooglesearch | Search | github.com/opsdisk/yagooglesearch | ~264 | Python | BSD-3 | ✅ | ✅ Apr 2025 | Very Low |
| 4 | pagodo | Search | github.com/opsdisk/pagodo | ~3,200 | Python | GPL-3.0 | ✅ | ✅ Apr 2025 | Low |
| 5 | Search-Engines-Scraper | Search | github.com/DatapaloozaCO/search-engines-scraper | ~200 | Python | MIT | ✅ | ✅ 2024 | Very Low |
| 6 | scholarly | Search | github.com/scholarly-python-package/scholarly | ~1,500 | Python | Unlicense | ✅ | ✅ Active | Very Low |
| 7 | dnstwist | Impersonation | github.com/elceef/dnstwist | ~5,300 | Python | Apache 2.0 | ✅ | ✅ Sep 2025 | Very High |
| 8 | URLInsane | Impersonation | github.com/rangertaha/urlinsane | ~900 | Go | MIT | ✅ | ✅ 2025 | Low |
| 9 | URLCrazy | Impersonation | github.com/urbanadventurer/urlcrazy | ~800 | Ruby | Custom | ✅ | ✅ Jul 2025 | Low |
| 10 | openSquat | NRD Monitor | github.com/atenreiro/opensquat | ~930 | Python | GPL-3.0 | ⚠️ Partial | ✅ 2025 | Very High |
| 11 | certstream-server-go | CT Stream | github.com/d-Rickyy-b/certstream-server-go | ~200 | Go | Open | ✅ | ✅ Active | Medium |
| 12 | crt.sh | CT Search | crt.sh | N/A | Web/API | Free | ✅ | ✅ Stable | High |
| 13 | Phishpedia | Visual Detection | github.com/lindsey98/Phishpedia | ~345 | Python | Academic | ✅ | ✅ Jul 2025 | High |
| 14 | PhishIntention | Visual Detection | github.com/lindsey98/PhishIntention | ~251 | Python | Academic | ✅ | ✅ Active | High |
| 15 | IOK | Kit Detection | github.com/phish-report/IOK | ~189 | Go/YAML | Open | ✅ | ✅ Active | Medium |
| 16 | gowitness | Screenshots | github.com/sensepost/gowitness | ~4,200 | Go | GPLv3 | ✅ | ✅ Nov 2025 | High |
| 17 | EyeWitness | Screenshots | github.com/RedSiege/EyeWitness | ~5,600 | Python | GPLv3 | ✅ | ✅ Dec 2025 | Very High |
| 18 | imagehash | Perceptual Hash | github.com/JohannesBuchner/imagehash | ~3,000 | Python | BSD | ✅ | ✅ Active | Very High |
| 19 | TLSH | Fuzzy Hash | github.com/trendmicro/tlsh | ~800 | C/Python | Apache 2.0 | ✅ | ✅ Active | Very High |
| 20 | ppdeep | Fuzzy Hash | github.com/elceef/ppdeep | ~50 | Python | Apache 2.0 | ✅ | ✅ Stable | Very High |
| 21 | httpx | Fingerprinting | github.com/projectdiscovery/httpx | ~9,600 | Go | MIT | ✅ | ✅ Jan 2025 | Medium |
| 22 | WhatWeb | Fingerprinting | github.com/urbanadventurer/WhatWeb | ~6,400 | Ruby | GPLv2 | ✅ | ✅ Oct 2025 | Medium |
| 23 | webanalyze | Fingerprinting | github.com/rverton/webanalyze | ~974 | Go | MIT | ✅ | ⚠️ Oct 2023 | Medium |
| 24 | webappanalyzer | Detection Rules | github.com/enthec/webappanalyzer | ~428 | JSON | GPL-3.0 | ✅ | ✅ Dec 2025 | High |
| 25 | katana | Crawling | github.com/projectdiscovery/katana | ~15,600 | Go | MIT | ✅ | ✅ Jan 2025 | Medium |
| 26 | waymore | URL History | github.com/xnl-h4ck3r/waymore | ~4,000 | Python | Open | ⚠️ Partial | ✅ 2025 | Very High |
| 27 | gau | URL History | github.com/lc/gau | ~4,000 | Go | Open | ⚠️ Partial | Low | Low |
| 28 | waybackurls | URL History | github.com/tomnomnom/waybackurls | ~3,500 | Go | Open | ✅ | ⚠️ Stable | Low |
| 29 | FavFreak | Favicon Hash | github.com/devanshbatham/FavFreak | ~1,300 | Python | Open | ✅ | ⚠️ Stable | High |
| 30 | OWASP Amass | Org Discovery | github.com/owasp-amass/amass | ~12,000 | Go | Apache 2.0 | ⚠️ Partial | ✅ Active | Medium |
| 31 | theHarvester | OSINT | github.com/laramies/theHarvester | ~15,300 | Python | GPL-2.0 | ⚠️ Partial | ✅ Active | High |
| 32 | subfinder | Subdomains | github.com/projectdiscovery/subfinder | ~13,000 | Go | MIT | ⚠️ Partial | Medium | Medium |
| 33 | dnsx | DNS | github.com/projectdiscovery/dnsx | ~2,000 | Go | MIT | ✅ | ✅ Active | Medium |
| 34 | massdns | DNS | github.com/blechschmidt/massdns | ~3,500 | C | GPL-3.0 | ✅ | ✅ Stable | Low |
| 35 | spaCy | NER/NLP | github.com/explosion/spaCy | ~30,000 | Python | MIT | ✅ | ✅ Active | Very High |
| 36 | edgartools | SEC EDGAR | github.com/dgunning/edgartools | ~500 | Python | MIT | ✅ | ✅ Active | Very High |
| 37 | waybackpy | Wayback API | github.com/akamhy/waybackpy | ~500 | Python | MIT | ✅ | ✅ Stable | Very High |
| 38 | cdx_toolkit | Archive APIs | github.com/commoncrawl/cdx_toolkit | ~200 | Python | Apache 2.0 | ✅ | ✅ Active | Very High |
| 39 | Photon | Crawling | github.com/s0md3v/Photon | ~11,000 | Python | GPLv3 | ✅ | ❌ Stale | Very High |
| 40 | ail-typo-squatting | Permutations | github.com/ail-project/ail-typo-squatting | ~92 | Python | Open | ✅ | ✅ Apr 2025 | High |

---

## Tools that claim to be free but require API keys

These tools are frequently recommended as "free" but **will not function** or will severely degrade without API keys or account registration:

- **Whoogle** — Was zero-key until Google broke it (Jan 2025). The GCSE fallback requires a Google API key + CSE-ID. The Mullvad Leta backend requires a Mullvad VPN subscription. **Exclude from ASM-NG.**
- **asnmap** (ProjectDiscovery) — Now requires a free ProjectDiscovery Cloud Platform (PDCP) account with API key. Not truly zero-key despite being open-source. **Use Amass `intel -org` instead.**
- **OpenCorporates API** — Requires `api_token` for programmatic queries. Free only for approved public-benefit applicants. **Website is browsable without login but not API-accessible.**
- **DomLink** — Requires Whoxy.com API key for reverse WHOIS. **Use Amass `intel -whois` instead.**
- **SAM.gov API** — Requires a free api.data.gov key (quick registration). Not zero-key.
- **EIA API** — Requires free API key registration.
- **CaliDog certstream** — The hosted service at `wss://certstream.calidog.io/` is unreliable/frequently down since 2024. **Self-host certstream-server-go instead.**
- **DNSDumpster** — Recently started requiring an API key for theHarvester integration.
- **Censys, Shodan, SecurityTrails, VirusTotal** — All require API keys. Treated as optional enrichments only.

---

## Stale and archived projects to avoid

| Tool | Status | Replacement |
|------|--------|-------------|
| **aquatone** | Archived Jan 2023, last release May 2019 | gowitness or httpx `--screenshot` |
| **catphish** | Unmaintained since ~2017 | dnstwist or URLInsane |
| **phishing_catcher** | Unmaintained since ~2018 | Fork the scoring logic; use certstream-server-go as CT source |
| **GoogleScraper** | Author declared "extremely buggy", abandoned | ddgs or yagooglesearch |
| **Photon** | Development stalled | katana |
| **hakrawler** | Superseded, low activity | katana |
| **gospider** | Last release Jun 2021 | katana |
| **go-dork** | Last activity ~2022 | ddgs |
| **fuzzyhashlib** | Python 2.7 only | Use TLSH + ppdeep directly |

---

## Universal brand impersonation detection pipeline

This pipeline works for **any client in any industry** — the brand name, domain, and logo are the only client-specific inputs.

### Phase 1: Asset discovery (run once, refresh weekly)

```
Client inputs: brand name, primary domain(s), logo image(s)
                           │
    ┌──────────────────────┼──────────────────────┐
    ▼                      ▼                      ▼
SEC EDGAR              GLEIF API            Wikidata SPARQL
(Exhibit 21)      (parent-child LEI)     (P749/P355/P127)
    │                      │                      │
    └──────────────────────┼──────────────────────┘
                           ▼
              Consolidated subsidiary list
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        Amass intel    crt.sh CT     theHarvester
     (org→ASN→domains) (%.domain)  (15+ free sources)
              │            │            │
              └────────────┼────────────┘
                           ▼
            Complete domain/infrastructure inventory
```

### Phase 2: Threat generation (run daily)

```
Each known domain
        │
        ├─→ dnstwist (15+ permutation algorithms)
        ├─→ URLInsane (multilingual variants)
        │        │
        │        ▼
        │   Candidate lookalike domains (thousands)
        │        │
        ├─→ openSquat (daily NRD feed + brand keywords)
        ├─→ certstream-server-go → keyword/entropy scoring
        └─→ crt.sh (new certs matching brand patterns)
                 │
                 ▼
         Domains requiring investigation
```

### Phase 3: Analysis and scoring (run on flagged domains)

```
Suspect domain
        │
        ├─→ httpx: status, title, tech stack, favicon hash,
        │         JARM fingerprint, body hash, screenshot
        │
        ├─→ katana: crawl site, extract forms/links/JS
        │
        ├─→ waymore: check URL history, download archives
        │
        ├─→ TLSH/ppdeep: fuzzy-hash HTML vs. legitimate site
        │
        ├─→ imagehash: pHash of screenshot vs. legitimate
        │
        ├─→ Phishpedia: logo detection + brand matching
        │
        ├─→ FavFreak/httpx: favicon hash comparison
        │
        └─→ Cross-reference: OpenPhish, PhishTank, URLhaus
                 │
                 ▼
         Impersonation confidence score (0-100)
         Action: monitor / investigate / takedown
```

### Phase 4: Enrichment via search (on-demand)

```
Brand impersonation indicators
        │
        ├─→ SearXNG: "brand name" + fraud indicators
        ├─→ ddgs: multi-engine brand mention search
        ├─→ Wayback CDX: historical snapshots of suspect sites
        └─→ Common Crawl: bulk brand mention discovery
```

---

## What to keep versus drop from a healthcare-focused version

The generalized ASM-NG platform should **keep all general-purpose tools** and make industry-specific data sources modular plugins:

**KEEP (universal, all-industry):** dnstwist, URLInsane, openSquat, certstream-server-go, crt.sh, Phishpedia, httpx, katana, gowitness, imagehash, TLSH, ppdeep, FavFreak, IOK, SearXNG, ddgs, yagooglesearch, pagodo, Amass, theHarvester, subfinder, dnsx, waymore, waybackpy, cdx_toolkit, spaCy, edgartools, GLEIF API, Wikidata SPARQL, OpenPhish, PhishTank, URLhaus, WhatWeb, EyeWitness, webappanalyzer

**KEEP as optional industry plugins (not core pipeline):**

- NPPES NPI Registry → healthcare clients only
- FDIC BankFind → financial services clients only  
- USASpending.gov → government contractor clients only
- NCES IPEDS → education clients only
- NHTSA API → transportation/automotive clients only
- ProPublica 990 → nonprofit clients only
- SEC EDGAR Exhibit 21 → public company clients (keep in core — applies across industries)

**DROP entirely:**

- Whoogle (broken by Google)
- aquatone (archived, replaced by gowitness)
- catphish (abandoned, redundant with dnstwist)
- GoogleScraper (abandoned)
- Any tool that required healthcare-specific hardcoded logic — replace with configurable brand/keyword parameters
- CaliDog hosted certstream (unreliable) — replace with self-hosted certstream-server-go

## Conclusion

The zero-key ASM toolchain is more capable than many commercial alternatives. The critical insight is that **five tools form an irreplaceable core**: SearXNG (search infrastructure), dnstwist (domain permutation), Amass (organization-to-infrastructure mapping), httpx (site fingerprinting), and Phishpedia (visual brand identification). Every other tool enhances one of these five capabilities. The biggest gaps remaining are passive DNS (no truly free, keyless option exists) and real-time NRD feeds (WhoisDS and Shreshta provide daily granularity at best). The recommended architecture deploys SearXNG and certstream-server-go as persistent Docker services, with all other tools invoked on-demand through SpiderFoot modules. Industry-specific data sources should be implemented as optional plugins selectable per client engagement, keeping the core pipeline entirely industry-agnostic.