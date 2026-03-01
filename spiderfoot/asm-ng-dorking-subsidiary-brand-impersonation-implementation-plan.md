# ASM-NG: Google Dorking, Subsidiary Discovery & Brand Impersonation — Implementation Plan

## Source Research

Based on deep research: `spiderfoot/compass_artifact_wf-fc32c55a-0f5b-4e43-9f0f-b2d8a447cdd8_text_markdown.md`

## Executive Summary

The research identified 55+ zero-key open-source tools across 5 capability areas. After cross-referencing with ASM-NG's existing 296 modules, this plan distills the research into **8 actionable work items**: 4 new modules and 4 enhancements to existing modules. Each leverages tools confirmed as actively maintained, zero-key, and Python-integrable.

The core architecture: **ddgs** for zero-key multi-engine dorking (replaces Google CSE API dependency), **SEC EDGAR + GLEIF + Wikidata** for subsidiary discovery, **dnstwist enhancement** for brand impersonation detection, and **SearXNG** as an optional self-hosted search backend.

---

## What Already Exists vs. What's Missing

### Already Built (leverage, don't rebuild)

| Capability | Existing Module | What it does | Gap |
|-----------|----------------|-------------|-----|
| Google search | `sfp_googlesearch` | Single `site:` query via Google CSE API | No dorking operators, requires API key |
| Bing search | `sfp_bingsearch` | Single query via Bing API | Requires API key |
| DuckDuckGo | `sfp_duckduckgo` | Instant Answer API (summaries only) | Not search results |
| Company extraction | `sfp_company` | Extracts `COMPANY_NAME` from web content | No domain resolution |
| Corporate lookup | `sfp_opencorporates` | Looks up company records | Requires API key, no `AFFILIATE_DOMAIN_NAME` output |
| LEI lookup | `sfp_gleif` | GLEIF API for LEI records | No parent/subsidiary traversal, no domain output |
| DNS permutation | `sfp_tool_dnstwist` | Runs dnstwist, emits `SIMILARDOMAIN` | No visual comparison, no NRD monitoring |
| Cross-referencing | `sfp_crossref` | Finds affiliates by bidirectional linking | Requires backlinks (sister hospitals won't link back) |
| CT certificates | `sfp_crt` + `sfp_certspotter` | Certificate transparency lookups | No brand-monitoring angle |
| Phishing feeds | `sfp_openphish` + `sfp_phishtank` | Cross-reference against phishing databases | Already functional |
| Web crawling | `sfp_spider` | Crawls target site | Already functional |
| Archive.org | `sfp_archiveorg` | Wayback Machine lookups | Already functional |
| Common Crawl | `sfp_commoncrawl` | URL discovery via CC index | Already functional |
| WhatWeb | `sfp_tool_whatweb` | Website fingerprinting | Already functional |

### Missing (build new)

| Capability | What's needed | Priority |
|-----------|--------------|----------|
| Zero-key dorking | Multi-engine search with advanced operators | **P0** — Immediate |
| Subsidiary discovery | `COMPANY_NAME` → domain resolution pipeline | **P0** — Immediate |
| Brand impersonation scoring | Visual + content similarity for `SIMILARDOMAIN` events | **P1** — High |
| NRD monitoring | Daily newly-registered domain brand matching | **P2** — Medium |

---

## Work Items

### NEW-1: `sfp_search_dork` — Zero-Key Multi-Engine Dorking

**Why:** The research confirmed that `ddgs` (MIT, 8k stars, 9 search backends, Feb 2026 active) eliminates the API key requirement entirely. Google CSE's 100/day free tier is a hard ceiling — ddgs has no limit. SearXNG is the infrastructure play for self-hosted deployments.

**Watches:** `DOMAIN_NAME`, `INTERNET_NAME`
**Produces:** `LINKED_URL_INTERNAL`, `LINKED_URL_EXTERNAL`, `SEARCH_ENGINE_WEB_CONTENT`, `RAW_RIR_DATA`

**Search backends (priority order):**
1. **ddgs** (primary) — `pip install ddgs`, Python native, 9 backends (Google, Bing, Brave, DuckDuckGo, Mojeek, Yandex, Yahoo, etc.), auto-rotates backends, no key
2. **SearXNG** (optional) — if user has a self-hosted instance configured, use its JSON API (`/search?q=<query>&format=json`)
3. **Google CSE** (fallback) — existing `googleIterate()` in `sflib.py` if user has an API key configured

**Dork categories:**

```python
# Category 1: Exposed documents
('site:{target} filetype:pdf', 'PDF documents'),
('site:{target} filetype:doc OR filetype:docx', 'Word documents'),
('site:{target} filetype:xls OR filetype:xlsx OR filetype:csv', 'Spreadsheets'),
('site:{target} filetype:sql OR filetype:bak OR filetype:db', 'Database files'),
('site:{target} filetype:log', 'Log files'),

# Category 2: Admin/login exposure
('site:{target} inurl:admin OR inurl:login', 'Admin/login pages'),
('site:{target} intitle:"dashboard"', 'Dashboards'),
('site:{target} intitle:"index of"', 'Directory listings'),

# Category 3: Config/error exposure
('site:{target} filetype:env OR filetype:yml OR filetype:yaml', 'Config files'),
('site:{target} filetype:xml "password" OR "api_key"', 'Secrets in XML'),
('site:{target} intitle:"phpinfo()"', 'PHP info pages'),

# Category 4: Third-party exposure
('"{target}" site:pastebin.com OR site:paste.ee', 'Paste sites'),
('"{target}" site:github.com OR site:gitlab.com', 'Code repos'),
('"{target}" site:trello.com OR site:notion.so', 'Project management'),
('"{target}" "password" OR "credentials" -site:{target}', 'Leaked credentials'),
```

**Options:**
```python
opts = {
    'search_backend': 'ddgs',          # 'ddgs', 'searxng', 'google_cse'
    'searxng_url': '',                  # e.g. http://localhost:8888
    'google_api_key': '',               # Fallback to Google CSE
    'google_cse_id': '',
    'max_dorks': 15,                    # Max dork queries per domain
    'scrape_depth': 1,                  # Fetch discovered URLs 1-2 levels deep
    'delay': 2.0,                       # Seconds between queries
    'enable_filetype_dorks': True,
    'enable_admin_dorks': True,
    'enable_config_dorks': True,
    'enable_thirdparty_dorks': True,
}
```

**Scraping depth (1-2 levels):**
Each discovered URL is fetched and emitted as `SEARCH_ENGINE_WEB_CONTENT`. At depth 1, links on the page are extracted; if `scrape_depth=2`, those are fetched too (same-domain only, capped at 20 links per page). This feeds `sfp_company` for company name extraction and `sfp_ai_webcontent` for AI infrastructure detection.

**Implementation notes:**
- `ddgs` import: `from ddgs import DDGS` → `DDGS().text(query, max_results=20)` returns list of dicts with `href`, `title`, `body`
- Rate limiting: ddgs auto-rotates backends but still needs delays to avoid blocks — 2s default, configurable
- Dedup: track all discovered URLs in `self.results` to avoid re-emitting
- The module replaces the need for a separate `sfp_google_dork` — it's engine-agnostic

**Dependency:** `pip install ddgs` added to `requirements.txt`

---

### NEW-2: `sfp_associated_company` — Subsidiary & Sister Organization Discovery

**Why:** The FHC/sister hospital problem. `sfp_company` extracts company names but nothing resolves them to domains. The research identified three free structured data sources that provide corporate hierarchy data without API keys: SEC EDGAR (Exhibit 21 subsidiaries), GLEIF (parent-child LEI relationships), and Wikidata SPARQL (P749/P355/P127 properties).

**Watches:** `COMPANY_NAME`
**Produces:** `AFFILIATE_DOMAIN_NAME`, `AFFILIATE_INTERNET_NAME`, `COMPANY_NAME`

**Three discovery methods (all zero-key):**

**Method 1 — Search engine domain resolution (primary)**
Uses `ddgs` (or SearXNG/Google CSE) to search `"Company Name"` and identify the most likely domain by frequency scoring. Filters out search engines, social media, directories, and the target's own domain.

```python
def _search_company_domain(self, company_name):
    """Search for a company name, return most likely domain."""
    results = DDGS().text(f'"{company_name}"', max_results=15)
    domain_counts = {}
    for r in results:
        domain = self.sf.urlFQDN(r['href'])
        if domain and not self._is_noise_domain(domain):
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
    if domain_counts:
        return max(domain_counts, key=domain_counts.get)
    return None
```

**Method 2 — SEC EDGAR Exhibit 21 (US public companies)**
The research confirmed SEC EDGAR requires zero authentication — only a User-Agent header. For public company targets, fetch their 10-K filing and parse Exhibit 21 for subsidiary list.

```python
def _check_sec_subsidiaries(self, company_name):
    """Check SEC EDGAR for subsidiaries listed in Exhibit 21."""
    # Search SEC full-text for the company
    url = f"https://efts.sec.gov/LATEST/search-index?q=%22{encoded_name}%22&dateRange=custom&startdt=2024-01-01&forms=10-K"
    # Parse Exhibit 21 attachment for subsidiary names
    # Each subsidiary name becomes a new COMPANY_NAME event
```

**Method 3 — GLEIF parent-child relationships (global)**
The research confirmed GLEIF API is zero-key with parent/child relationship endpoints. The existing `sfp_gleif` module already queries GLEIF but does NOT traverse parent-child relationships or emit `AFFILIATE_DOMAIN_NAME`.

```python
def _check_gleif_relationships(self, company_name):
    """Check GLEIF for parent/subsidiary relationships."""
    # Search: api.gleif.org/api/v1/lei-records?filter[entity.legalName]=<name>
    # For each LEI found, check:
    #   /lei-records/{LEI}/direct-parent
    #   /lei-records/{LEI}/ultimate-parent
    # Discovered parent/subsidiary names → new COMPANY_NAME events
```

**Method 4 — Wikidata SPARQL (supplementary)**
```sparql
SELECT ?subsidiary ?subsidiaryLabel ?website WHERE {
  ?org rdfs:label "Foundation Health Care"@en .
  ?subsidiary wdt:P749 ?org .         # P749 = parent organization
  OPTIONAL { ?subsidiary wdt:P856 ?website }  # P856 = official website
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en" }
}
```

**Company name filtering (noise suppression):**
```python
BLOCKLIST = [
    # Tech/infra (finding google.com as an affiliate is useless)
    'google', 'microsoft', 'amazon', 'apple', 'meta', 'cloudflare',
    # SSL CAs
    "let's encrypt", 'digicert', 'comodo', 'sectigo', 'godaddy',
    # CMS/frameworks
    'wordpress', 'drupal', 'jquery', 'bootstrap',
    # Hosting
    'aws', 'azure', 'heroku', 'netlify',
]
```

**Options:**
```python
opts = {
    'search_backend': 'ddgs',
    'searxng_url': '',
    'google_api_key': '',
    'google_cse_id': '',
    'use_sec_edgar': True,              # Check SEC EDGAR for subsidiaries
    'use_gleif': True,                  # Check GLEIF for parent/child
    'use_wikidata': True,               # Check Wikidata for relationships
    'verify_domain': True,              # DNS-verify discovered domains
    'max_lookups': 30,                  # Max company name lookups per scan
    'min_name_length': 5,               # Skip short names (noise)
    'exclude_common_companies': True,
    'delay': 1.5,
}
```

**SEC User-Agent requirement:** The SEC fair-use policy requires `User-Agent: CompanyName AdminEmail` — use `ASM-NG security-scan@asm-ng.local` or make configurable.

---

### NEW-3: `sfp_brand_impersonation` — Visual + Content Similarity Scoring

**Why:** `sfp_tool_dnstwist` already generates `SIMILARDOMAIN` events, but nobody *scores* them. The research identified `imagehash`, `TLSH`/`ppdeep`, and `Phishpedia` as zero-key tools for visual and content comparison. This module watches `SIMILARDOMAIN`, fetches the lookalike, compares it to the target, and emits a scored impersonation event.

**Watches:** `SIMILARDOMAIN`
**Produces:** `BRAND_IMPERSONATION_DETECTED` (new event type), `MALICIOUS_AFFILIATE_INTERNET_NAME`

**Scoring pipeline:**

```
SIMILARDOMAIN: typo-fhc.com
    │
    ├─ 1. Fetch both pages (target + suspect)
    │     └─ httpx-style probe: status, title, headers, body
    │
    ├─ 2. Content similarity (TLSH fuzzy hash)
    │     └─ TLSH distance 0-400: <50 = very similar, <100 = suspicious
    │
    ├─ 3. Title/keyword overlap
    │     └─ Jaccard similarity of page titles and meta keywords
    │
    ├─ 4. Favicon hash comparison
    │     └─ Fetch /favicon.ico, compute MMH3 hash, compare
    │
    ├─ 5. Phishing feed cross-reference
    │     └─ Check against OpenPhish/PhishTank feeds (already in ASM-NG)
    │
    └─ 6. Final score (0-100)
          ├─ ≥80: BRAND_IMPERSONATION_DETECTED (high confidence)
          ├─ 50-79: BRAND_IMPERSONATION_DETECTED (medium confidence)
          └─ <50: Log only, no event
```

**Implementation notes:**
- `TLSH`: `pip install py-tlsh` → `tlsh.hash(body_bytes)` → `tlsh.diff(hash1, hash2)` returns distance (lower = more similar)
- `ppdeep` (pure Python ssdeep): `pip install ppdeep` → `ppdeep.hash(content)` → `ppdeep.compare(hash1, hash2)` returns 0-100 similarity
- `imagehash`: `pip install imagehash Pillow` → fetch favicon/screenshot as PIL Image → `imagehash.phash(img)` → compare with `-` operator
- Favicon MMH3: `pip install mmh3` → fetch `/favicon.ico` → `mmh3.hash(favicon_bytes)` — standard Shodan favicon fingerprint
- No external tools required (no headless Chrome, no gowitness) — pure HTTP fetches + Python hashing

**New event type required:** `BRAND_IMPERSONATION_DETECTED`
- Add to `spiderfoot/event_type_mapping.py`
- Add to grading config if applicable
- Event data format: `"typo-fhc.com — Score: 87/100 (TLSH: 23, title match: 95%, favicon: match) — Possible brand impersonation of fhc.com"`

**Options:**
```python
opts = {
    'min_score_to_emit': 50,           # Minimum impersonation score to emit event
    'check_favicon': True,
    'check_content_hash': True,
    'check_title_similarity': True,
    'check_phishing_feeds': True,
    'fetch_timeout': 10,
}
```

**Dependencies:** `pip install py-tlsh ppdeep imagehash Pillow mmh3`

---

### NEW-4: `sfp_nrd_monitor` — Newly Registered Domain Brand Monitoring

**Why:** The research confirmed WhoisDS.com provides free daily NRD feeds and `openSquat` (GPL-3, 930 stars) has the brand-matching logic built in. This catches domain registrations targeting the client's brand *before* they're weaponized.

**Watches:** `DOMAIN_NAME`
**Produces:** `SIMILARDOMAIN`, `BRAND_IMPERSONATION_DETECTED`

**Data sources (zero-key):**
1. **WhoisDS.com daily feed** — free CSV of newly registered domains
2. **Shreshta Labs GitHub** — 10k NRDs daily published as text files

**Matching algorithms (from openSquat + dnstwist):**
- Levenshtein distance (edit distance ≤ 3)
- Jaro-Winkler similarity (≥ 0.85)
- Keyword substring match (brand name appears in NRD)
- Homograph detection (unicode confusables)

```python
def _check_nrd_feed(self, brand_domain, brand_keywords):
    """Download today's NRD feed, match against brand."""
    # Fetch WhoisDS daily feed
    today = datetime.date.today().strftime('%Y-%m-%d')
    url = f"https://whoisds.com/whois-database/newly-registered-domains/{today}.zip"
    # Parse, apply Levenshtein/Jaro-Winkler against brand_domain
    # Keyword match against brand_keywords
    # Emit SIMILARDOMAIN for matches
```

**Options:**
```python
opts = {
    'nrd_source': 'whoisds',           # 'whoisds' or 'shreshta'
    'max_edit_distance': 3,
    'min_jaro_winkler': 0.85,
    'brand_keywords': '',               # Additional keywords (comma-sep)
    'check_dns': True,                  # Verify NRD resolves before emitting
}
```

**Note:** This is a **P2** item — lower priority than dorking and subsidiary discovery. Can be deferred to a future sprint. Included here because the research validated the data sources and approach.

---

### ENHANCE-1: Upgrade `sfp_gleif` — Add Parent/Subsidiary Traversal

**Current state:** `sfp_gleif` (`modules/sfp_gleif.py`) watches `COMPANY_NAME` and `LEI`, looks up entity records, but only emits `COMPANY_NAME`, `LEI`, `PHYSICAL_ADDRESS`. It does NOT query the relationship endpoints or emit `AFFILIATE_DOMAIN_NAME`.

**Enhancement:**
1. After finding a LEI record, query `/lei-records/{LEI}/direct-parent` and `/lei-records/{LEI}/ultimate-parent`
2. For each parent/subsidiary found, emit `COMPANY_NAME` (feeds `sfp_associated_company`)
3. If the GLEIF record contains a website URL in the entity data, emit `AFFILIATE_DOMAIN_NAME` directly

**Changes to `sfp_gleif.py`:**
- Add `AFFILIATE_DOMAIN_NAME` to `producedEvents()`
- Add `_check_relationships(lei, event)` method
- Call it after successful LEI lookup

---

### ENHANCE-2: Upgrade `sfp_tool_dnstwist` — Enable `--lsh` and `--phash` Flags

**Current state:** `sfp_tool_dnstwist` runs dnstwist with minimal flags and only emits `SIMILARDOMAIN`. The research confirmed dnstwist supports `--lsh` (fuzzy hash comparison), `--phash` (perceptual screenshot hash), and `--whois` natively — all zero-key.

**Enhancement:**
1. Add options for `--lsh`, `--phash`, `--whois`, `--mxcheck` flags
2. Parse the enriched JSON output (dnstwist returns `ssdeep`, `phash`, `whois_created` fields when enabled)
3. Pass enrichment data in the `SIMILARDOMAIN` event data so `sfp_brand_impersonation` can use it without re-fetching

**Changes to `sfp_tool_dnstwist.py`:**
```python
opts = {
    # ... existing opts ...
    'enable_lsh': True,        # Fuzzy hash comparison (ssdeep/TLSH)
    'enable_phash': False,     # Perceptual hash (requires Chrome, slower)
    'enable_whois': True,      # WHOIS lookup for creation date
    'enable_mxcheck': True,    # Check if MX accepts mail (phishing indicator)
}
```

---

### ENHANCE-3: Add `ddgs` as Search Backend to `sflib.py`

**Why:** Multiple modules need search capability (dorking, associated company, etc.). Rather than importing ddgs in each module, add a `ddgsIterate()` helper to `sflib.py` alongside the existing `googleIterate()` and `bingIterate()`.

**Changes to `sflib.py`:**
```python
def ddgsIterate(self, searchString: str, opts: dict = None) -> dict:
    """Request search results from ddgs (zero-key multi-engine).

    Returns:
        dict: {"urls": [...], "webSearchUrl": "https://duckduckgo.com/?q=..."}
    """
    from ddgs import DDGS
    results = DDGS().text(searchString, max_results=opts.get('max_results', 20))
    urls = [r['href'] for r in results if r.get('href')]
    return {
        "urls": urls,
        "webSearchUrl": f"https://duckduckgo.com/?q={searchString}"
    }
```

This gives all modules a unified interface: `self.sf.ddgsIterate(query)` returns the same format as `googleIterate()` and `bingIterate()`.

---

### ENHANCE-4: Register New Event Types

**New events needed:**

| Event Type | Parent Type | Description |
|-----------|------------|-------------|
| `BRAND_IMPERSONATION_DETECTED` | `SIMILARDOMAIN` | Scored brand impersonation alert with confidence level |
| `SEARCH_ENGINE_WEB_CONTENT` | `TARGET_WEB_CONTENT` | Web content discovered via search engine dorking |

**Files to update:**
- `spiderfoot/event_type_mapping.py` — add new types to the mapping dict and ordered list
- `spiderfoot/grade_config.py` — add grading rules for `BRAND_IMPERSONATION_DETECTED`
- `spiderfoot/db.py` — no changes needed (event types are dynamic)

---

## Implementation Order

| Phase | Work Item | Files | Dependency | Effort |
|-------|-----------|-------|-----------|--------|
| **1** | ENHANCE-3: `ddgsIterate()` in sflib.py | `sflib.py`, `requirements.txt` | None | Small |
| **1** | ENHANCE-4: Register new event types | `spiderfoot/event_type_mapping.py`, `spiderfoot/grade_config.py` | None | Small |
| **2** | NEW-1: `sfp_search_dork` | `modules/sfp_search_dork.py` | ENHANCE-3 | Medium |
| **2** | NEW-2: `sfp_associated_company` | `modules/sfp_associated_company.py` | ENHANCE-3 | Medium |
| **3** | ENHANCE-1: Upgrade `sfp_gleif` | `modules/sfp_gleif.py` | None | Small |
| **3** | ENHANCE-2: Upgrade `sfp_tool_dnstwist` | `modules/sfp_tool_dnstwist.py` | None | Small |
| **4** | NEW-3: `sfp_brand_impersonation` | `modules/sfp_brand_impersonation.py` | ENHANCE-2, ENHANCE-4 | Medium |
| **5** | NEW-4: `sfp_nrd_monitor` | `modules/sfp_nrd_monitor.py` | ENHANCE-4 | Medium |

**Phase 1** unblocks everything — can be done in a single commit.
**Phase 2** solves the two original asks (dorking + subsidiary discovery).
**Phase 3** enriches existing data pipelines.
**Phase 4-5** add brand protection capabilities.

---

## Dependencies to Add

```
# requirements.txt additions
ddgs>=7.0                    # Zero-key multi-engine search (9 backends)
py-tlsh>=4.7.2               # TLSH fuzzy hashing (brand impersonation)
ppdeep>=20200505             # Pure Python ssdeep (content similarity)
imagehash>=4.3.1             # Perceptual hashing (favicon/screenshot comparison)
mmh3>=4.0                    # MurmurHash3 (favicon fingerprinting)
```

Only `ddgs` is needed for Phase 1-2. The others are Phase 4 (brand impersonation).

---

## Tools From Research — Disposition

| Tool | Disposition | Rationale |
|------|------------|-----------|
| **ddgs** | **USE — primary search backend** | 9 engines, zero-key, actively maintained, Python native |
| **SearXNG** | **USE — optional self-hosted backend** | Best for high-volume deployments, configurable |
| **yagooglesearch / pagodo** | **SKIP** | ddgs covers the same ground with more backends and less blocking risk |
| **SEC EDGAR** | **USE — in sfp_associated_company** | Zero-key, Exhibit 21 subsidiaries, edgartools library |
| **GLEIF** | **ENHANCE — existing sfp_gleif** | Already integrated, just needs relationship traversal |
| **Wikidata SPARQL** | **USE — in sfp_associated_company** | Zero-key, global coverage, P749/P355 properties |
| **dnstwist** | **ENHANCE — existing sfp_tool_dnstwist** | Already integrated, enable --lsh/--phash/--whois flags |
| **URLInsane** | **SKIP for now** | dnstwist covers 15+ algorithms already, URLInsane adds multilingual (future) |
| **openSquat** | **REFERENCE — for sfp_nrd_monitor** | Borrow NRD feed + matching logic, don't wrap the whole tool |
| **certstream-server-go** | **DEFER** | Requires Docker infrastructure, better as a deployment guide |
| **Phishpedia** | **DEFER** | Requires PyTorch + model files — too heavy for Phase 1. Add later as optional tool module |
| **httpx** | **DEFER** | Go binary, already partially covered by sfp_tool_whatweb |
| **katana** | **DEFER** | Go binary, sfp_spider already crawls. Add later if deeper JS rendering needed |
| **TLSH / ppdeep / imagehash** | **USE — in sfp_brand_impersonation** | Lightweight Python packages, zero-key |
| **Amass** | **SKIP** | Heavy Go binary, most of its zero-key sources (crt.sh, DNS brute) already in ASM-NG |
| **theHarvester** | **SKIP** | Overlaps with existing modules (email, DNS, CT lookups) |
| **Whoogle** | **DROP** | Broken by Google Jan 2025, confirmed dead |
| **OpenCorporates API** | **SKIP** | Requires API key despite claims — existing module already handles this |
| **waymore / waybackpy** | **DEFER** | sfp_archiveorg + sfp_commoncrawl already cover Wayback/CC |
| **gowitness / EyeWitness** | **DEFER** | Screenshot capability — add as optional tool in Phase 4 |

---

## Verification Checklist

### Phase 2 Completion (Dorking + Subsidiary)

- [ ] `sfp_search_dork` with ddgs backend discovers URLs that `sfp_googlesearch` misses for the same target
- [ ] `sfp_search_dork` with `scrape_depth=1` fetches discovered pages and emits `SEARCH_ENGINE_WEB_CONTENT`
- [ ] `sfp_associated_company` resolves "San Diego Regional Hospital" → correct domain → emits `AFFILIATE_DOMAIN_NAME`
- [ ] `sfp_associated_company` does NOT emit the target's own domain as an affiliate
- [ ] `sfp_associated_company` filters noise companies (Google, Microsoft, etc.)
- [ ] SEC EDGAR lookup finds subsidiaries for a known public company (e.g. Alphabet → Google, YouTube, etc.)
- [ ] GLEIF relationship traversal finds parent/subsidiary for a known LEI entity
- [ ] End-to-end: scan target with associated company on website → subsidiary domain appears in scan results → affiliate modules fire on it

### Phase 4 Completion (Brand Impersonation)

- [ ] `sfp_brand_impersonation` receives `SIMILARDOMAIN`, fetches both pages, produces a score
- [ ] TLSH fuzzy hash correctly identifies similar vs. dissimilar page content
- [ ] Favicon hash comparison detects matching favicons
- [ ] Score ≥80 emits `BRAND_IMPERSONATION_DETECTED` with high confidence
- [ ] Score <50 does NOT emit event (log only)
- [ ] Enhanced dnstwist with `--lsh --whois --mxcheck` enriches `SIMILARDOMAIN` event data

---

## Healthcare Client Notes (FHC Scenario)

For the specific FHC case, the pipeline after implementation:

```
Target: fhc.example.com
  │
  ├─ sfp_spider crawls site → finds "San Diego Regional Hospital" on /about
  ├─ sfp_company extracts COMPANY_NAME: "San Diego Regional Hospital"
  │
  ├─ sfp_associated_company receives COMPANY_NAME
  │   ├─ ddgs search: "San Diego Regional Hospital" → sdregionalhospital.org (3 results)
  │   ├─ SEC EDGAR: FHC 10-K Exhibit 21 lists "SD Regional Hospital LLC"
  │   ├─ Verify: sdregionalhospital.org resolves ✓
  │   └─ Emit: AFFILIATE_DOMAIN_NAME: sdregionalhospital.org
  │
  ├─ 49+ affiliate modules fire on sdregionalhospital.org:
  │   ├─ sfp_dnsresolve → IP addresses
  │   ├─ sfp_sslcert → certificate details
  │   ├─ sfp_whois → registration info
  │   ├─ sfp_spider → crawl affiliate site
  │   ├─ sfp_ai_* → AI infrastructure scanning
  │   └─ ... etc
  │
  ├─ sfp_search_dork runs against fhc.example.com
  │   ├─ "site:fhc.example.com filetype:pdf" → exposed patient forms?
  │   ├─ "site:fhc.example.com inurl:admin" → admin panels?
  │   ├─ "fhc.example.com" site:pastebin.com → paste exposure?
  │   └─ Scrape depth 1: fetch each URL, extract content for analysis
  │
  └─ sfp_tool_dnstwist runs against fhc.example.com
      ├─ Generates: fhc-example.com, fhcexample.com, etc.
      ├─ sfp_brand_impersonation scores each SIMILARDOMAIN
      └─ High-score matches → BRAND_IMPERSONATION_DETECTED
```

The NPPES NPI Registry (zero-key) is a future healthcare-specific plugin that could further enrich the FHC scenario by finding all NPI-registered entities under the same organization. This is out of scope for this plan but noted for the backlog.
