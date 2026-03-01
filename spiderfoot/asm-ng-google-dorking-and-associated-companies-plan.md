# ASM-NG: Google Dorking & Associated Company Discovery — Implementation Plan

## Context

Two critical OSINT capabilities are missing from the ASM-NG scanning pipeline:

1. **Google Dorking** — The platform only uses a single `site:target.com` query via the Google Custom Search API (`sfp_googlesearch`). No advanced search operators are used (`filetype:`, `inurl:`, `intitle:`, `intext:`, etc.). This means exposed documents, admin panels, config files, directory listings, and third-party mentions are never discovered.

2. **Associated Company / Subsidiary Discovery** — When scanning a target like FHC (Foundation Health Care), the spider finds links to sister organizations (e.g. a sister hospital in San Diego mentioned on FHC's website), but no module pivots on discovered company names to find their domains and add them as affiliates. The `COMPANY_NAME` → `AFFILIATE_DOMAIN_NAME` pipeline is broken — `sfp_company` extracts names, but nothing resolves them to scannable domains.

### Real-World Impact (FHC Example)

```
Target: fhc.example.com
  → sfp_spider finds "San Diego Regional Hospital" on /about page
  → sfp_company extracts COMPANY_NAME: "San Diego Regional Hospital"
  → ??? nothing happens — no module resolves this to sdregionalhospital.org
  → sdregionalhospital.org never becomes an AFFILIATE_DOMAIN_NAME
  → 49+ modules that handle affiliates never fire for it
```

---

## Existing Infrastructure to Build On

### Google Search

| Component | Location | What it does |
|-----------|----------|-------------|
| `sfp_googlesearch` | `modules/sfp_googlesearch.py` | Single `site:` query via Google Custom Search API |
| `googleIterate()` | `sflib.py:1611` | Core helper — takes any query string, calls Google CSE API, returns `{"urls": [...], "webSearchUrl": "..."}` |
| `sfp_bingsearch` | `modules/sfp_bingsearch.py` | Same pattern via Bing API (`bingIterate()` in `sflib.py:1676`) |
| `sfp_duckduckgo` | `modules/sfp_duckduckgo.py` | Instant Answer API only — topic summaries, no search results |

### Company / Affiliate Pipeline

| Component | Location | What it does |
|-----------|----------|-------------|
| `sfp_company` | `modules/sfp_company.py` | Extracts `COMPANY_NAME` from web content, SSL certs, WHOIS data |
| `sfp_crossref` | `modules/sfp_crossref.py` | Finds affiliates by checking if external links reference back to target |
| `sfp_opencorporates` | `modules/sfp_opencorporates.py` | Watches `COMPANY_NAME`, looks up corporate records — but only emits `COMPANY_NAME` / `PHYSICAL_ADDRESS`, **not** `AFFILIATE_DOMAIN_NAME` |
| `sfp_gleif` | `modules/sfp_gleif.py` | Watches `COMPANY_NAME`, looks up LEI records — same gap, no domain output |
| `sfp_reversewhois` | `modules/sfp_reversewhois.py` | Emits `AFFILIATE_DOMAIN_NAME` from WHOIS registrant pivots |
| `sfp_whoxy` / `sfp_whoisfreaks` | `modules/sfp_who*.py` | Similar WHOIS-based affiliate discovery |
| `sfp_google_tag_manager` | `modules/sfp_google_tag_manager.py` | Finds affiliates sharing GTM containers — emits `AFFILIATE_DOMAIN_NAME` |
| 49+ modules | various | Watch `AFFILIATE_DOMAIN_NAME` / `AFFILIATE_INTERNET_NAME` for downstream processing |

### Event Types Available

```
COMPANY_NAME              — extracted company name (produced by sfp_company)
AFFILIATE_COMPANY_NAME    — company name from affiliate content
AFFILIATE_DOMAIN_NAME     — domain belonging to an affiliate (triggers 49+ modules)
AFFILIATE_INTERNET_NAME   — hostname belonging to an affiliate
AFFILIATE_WEB_CONTENT     — web content from affiliate sites
AFFILIATE_DOMAIN_WHOIS    — WHOIS data for affiliate domains
```

---

## Module 1: `sfp_google_dork` — Google Dorking Engine

### Purpose

Run a battery of targeted Google search operator queries (dorks) against the scan target to discover exposed documents, admin panels, config files, error pages, third-party data exposure, and associated domains.

### Design

```
Watches:  DOMAIN_NAME, INTERNET_NAME
Produces: LINKED_URL_INTERNAL, LINKED_URL_EXTERNAL, RAW_RIR_DATA,
          SEARCH_ENGINE_WEB_CONTENT
```

### Options

```python
opts = {
    'api_key': '',                     # Google API key (required)
    'cse_id': '013611106330597893267:tfgl3wxdtbp',  # Custom Search Engine ID
    'max_dorks': 15,                   # Max dork categories to run per domain
    'max_pages_per_dork': 2,           # Max result pages per dork (10 results/page)
    'delay': 1.0,                      # Delay between API calls (rate limiting)
    'enable_filetype_dorks': True,     # Exposed document dorks
    'enable_admin_dorks': True,        # Admin panel / login page dorks
    'enable_config_dorks': True,       # Config file / error page dorks
    'enable_thirdparty_dorks': True,   # Third-party exposure dorks
    'scrape_depth': 1,                 # Levels deep to fetch discovered URLs (1-2)
}
```

### Dork Categories

Each category is a list of query templates. `{target}` is replaced with the domain.

**Category 1 — Exposed Documents** (`enable_filetype_dorks`)
```python
FILETYPE_DORKS = [
    ('site:{target} filetype:pdf', 'PDF documents'),
    ('site:{target} filetype:doc OR filetype:docx', 'Word documents'),
    ('site:{target} filetype:xls OR filetype:xlsx OR filetype:csv', 'Spreadsheets'),
    ('site:{target} filetype:ppt OR filetype:pptx', 'Presentations'),
    ('site:{target} filetype:sql OR filetype:db OR filetype:bak', 'Database files'),
    ('site:{target} filetype:log', 'Log files'),
    ('site:{target} filetype:conf OR filetype:cfg OR filetype:ini', 'Config files'),
]
```

**Category 2 — Admin Panels & Login Pages** (`enable_admin_dorks`)
```python
ADMIN_DORKS = [
    ('site:{target} inurl:admin', 'Admin panels'),
    ('site:{target} inurl:login OR inurl:signin', 'Login pages'),
    ('site:{target} intitle:"dashboard"', 'Dashboards'),
    ('site:{target} inurl:portal', 'Portals'),
    ('site:{target} intitle:"index of" OR intitle:"directory listing"', 'Directory listings'),
]
```

**Category 3 — Configuration & Error Exposure** (`enable_config_dorks`)
```python
CONFIG_DORKS = [
    ('site:{target} filetype:env OR filetype:yml OR filetype:yaml', 'Environment/config files'),
    ('site:{target} inurl:".git" OR inurl:".svn"', 'Version control exposure'),
    ('site:{target} intitle:"phpinfo()"', 'PHP info pages'),
    ('site:{target} "error" OR "exception" OR "stack trace" filetype:log', 'Error logs'),
    ('site:{target} filetype:xml "password" OR "secret" OR "api_key"', 'XML with secrets'),
]
```

**Category 4 — Third-Party Exposure** (`enable_thirdparty_dorks`)
```python
THIRDPARTY_DORKS = [
    ('"{target}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com', 'Paste sites'),
    ('"{target}" site:github.com OR site:gitlab.com', 'Code repositories'),
    ('"{target}" site:trello.com OR site:notion.so', 'Project management'),
    ('"{target}" filetype:pdf -site:{target}', 'External PDF mentions'),
    ('"{target}" "password" OR "credentials" OR "api key" -site:{target}', 'Leaked credentials'),
]
```

### Implementation Flow

```python
def handleEvent(self, event):
    domain = event.data

    # Build dork list based on enabled categories
    dorks = []
    if self.opts['enable_filetype_dorks']:
        dorks.extend(self.FILETYPE_DORKS)
    if self.opts['enable_admin_dorks']:
        dorks.extend(self.ADMIN_DORKS)
    # ... etc

    # Respect max_dorks limit
    dorks = dorks[:self.opts['max_dorks']]

    for query_template, category in dorks:
        if self.checkForStop():
            return

        query = query_template.format(target=domain)
        res = self.sf.googleIterate(
            searchString=query,
            opts={
                'timeout': self.opts['_fetchtimeout'],
                'useragent': self.opts['_useragent'],
                'api_key': self.opts['api_key'],
                'cse_id': self.opts['cse_id'],
            }
        )

        if not res:
            continue

        for url in res['urls']:
            if url in self.results:
                continue
            self.results[url] = True

            # Classify as internal or external
            if self.sf.urlFQDN(url).endswith(domain):
                evt = SpiderFootEvent("LINKED_URL_INTERNAL", url, ...)
            else:
                evt = SpiderFootEvent("LINKED_URL_EXTERNAL", url, ...)
            self.notifyListeners(evt)

            # Optional: scrape discovered URL (depth 1-2)
            if self.opts['scrape_depth'] >= 1:
                self._scrape_url(url, domain, event, depth=1)

        time.sleep(self.opts['delay'])
```

### Scraping Depth (1-2 Levels)

When `scrape_depth` is set, the module fetches each discovered URL and:
1. Emits `SEARCH_ENGINE_WEB_CONTENT` with the page content (downstream modules like `sfp_company` can extract company names from it)
2. At depth 1, extracts links from the page and optionally follows them one more level (depth 2)
3. **Only follows links to the same domain** — no recursive spider explosion

```python
def _scrape_url(self, url, target_domain, event, depth):
    """Fetch a discovered URL and optionally follow links 1 level deeper."""
    if depth > self.opts['scrape_depth']:
        return

    res = self.sf.fetchUrl(url, timeout=15,
                           useragent=self.opts['_useragent'])
    if not res or not res.get('content'):
        return

    # Emit web content for downstream analysis
    evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT",
                          res['content'], self.__class__.__name__, event)
    self.notifyListeners(evt)

    # Follow links one level deeper if depth allows
    if depth < self.opts['scrape_depth']:
        links = self.sf.parseLinks(url, res['content'], target_domain)
        for link in links[:20]:  # Cap at 20 links per page
            if link not in self.results:
                self.results[link] = True
                self._scrape_url(link, target_domain, event, depth + 1)
```

### Rate Limiting & Budget

Google Custom Search API free tier: **100 queries/day**, **10 results per query**.

With default settings (`max_dorks=15`, `max_pages_per_dork=2`):
- Worst case: 15 × 2 = **30 API calls per domain**
- Practical: Most dorks return <10 results → 1 page → **~15 API calls per domain**
- Multiple domains in a scan share the budget → the module should track total calls and stop at a configurable limit

```python
opts = {
    'daily_api_budget': 80,  # Reserve some headroom
}
```

### Bing Fallback (Optional Enhancement)

If no Google API key is configured but a Bing API key is available (from `sfp_bingsearch`), the module can fall back to `bingIterate()` with the same dork syntax (Bing supports most of the same operators). This is a nice-to-have, not required for v1.

---

## Module 2: `sfp_associated_company` — Associated Company & Subsidiary Discovery

### Purpose

Bridge the gap between discovered company names and scannable domains. When `sfp_company` extracts a company name from the target's website (e.g. "San Diego Regional Hospital" found on FHC's /about page), this module resolves it to a domain and emits `AFFILIATE_DOMAIN_NAME` so the entire 49+ module affiliate pipeline kicks in.

### Design

```
Watches:  COMPANY_NAME
Produces: AFFILIATE_DOMAIN_NAME, AFFILIATE_INTERNET_NAME
```

### The Pipeline This Enables

```
sfp_spider crawls fhc.example.com
  → sfp_company extracts COMPANY_NAME: "San Diego Regional Hospital"
  → sfp_associated_company receives COMPANY_NAME
    → Google CSE: "San Diego Regional Hospital" → finds sdregionalhospital.org
    → Validates: confirms it's a real domain, not the target itself
    → Emits AFFILIATE_DOMAIN_NAME: sdregionalhospital.org
      → sfp_dnsresolve resolves it
      → sfp_whois runs WHOIS on it
      → sfp_ssl checks its certificates
      → sfp_spider crawls it (as AFFILIATE_WEB_CONTENT)
      → sfp_ai_* modules scan for AI infrastructure
      → ... 49+ more modules fire
```

### Options

```python
opts = {
    'api_key': '',                     # Google API key (shared with sfp_google_dork)
    'cse_id': '013611106330597893267:tfgl3wxdtbp',
    'verify_domain': True,             # Verify discovered domains resolve
    'max_lookups': 30,                 # Max company name lookups per scan
    'min_company_name_length': 5,      # Skip very short names (noise)
    'exclude_common_companies': True,  # Skip "Google LLC", "Microsoft Corp" etc.
    'delay': 1.0,
}
```

### Company Name Filtering

Not every `COMPANY_NAME` event should trigger a lookup. Many are noise (the company that made the web framework, the SSL CA, etc.). The module needs a blocklist:

```python
COMMON_COMPANY_BLOCKLIST = [
    # Tech giants — finding their domains isn't useful for affiliate discovery
    'google', 'microsoft', 'amazon', 'apple', 'meta', 'facebook',
    'cloudflare', 'akamai', 'fastly',
    # SSL Certificate Authorities
    "let's encrypt", 'digicert', 'comodo', 'globalsign', 'sectigo',
    'godaddy', 'entrust',
    # Web frameworks / CMS vendors
    'wordpress', 'drupal', 'joomla', 'squarespace', 'wix',
    'automattic', 'acquia',
    # Hosting / CDN
    'aws', 'azure', 'heroku', 'netlify', 'vercel',
]
```

### Implementation Flow

```python
def handleEvent(self, event):
    company_name = event.data.strip()

    # Filter: too short
    if len(company_name) < self.opts['min_company_name_length']:
        return

    # Filter: common/noise companies
    if self.opts['exclude_common_companies']:
        name_lower = company_name.lower()
        for blocked in self.COMMON_COMPANY_BLOCKLIST:
            if blocked in name_lower:
                self.debug(f"Skipping common company: {company_name}")
                return

    # Filter: already looked up
    dedup_key = f"company:{company_name.lower()}"
    if dedup_key in self.results:
        return
    self.results[dedup_key] = True

    # Approach 1: Google search for the company name
    domain = self._google_company_domain(company_name, event)

    # Approach 2: Try direct domain guess (companyname.com)
    if not domain:
        domain = self._guess_company_domain(company_name)

    if domain:
        # Don't emit the target's own domain as an affiliate
        if self.getTarget().matches(domain):
            self.debug(f"Skipping {domain} — it's the target itself")
            return

        evt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", domain,
                              self.__class__.__name__, event)
        self.notifyListeners(evt)
```

### Domain Discovery Methods

**Method 1 — Google Search** (primary, requires API key)

```python
def _google_company_domain(self, company_name, event):
    """Search Google for a company name and extract the most likely domain."""
    if not self.opts.get('api_key'):
        return None

    # Search for the company name in quotes
    res = self.sf.googleIterate(
        searchString=f'"{company_name}"',
        opts={
            'timeout': self.opts['_fetchtimeout'],
            'useragent': self.opts['_useragent'],
            'api_key': self.opts['api_key'],
            'cse_id': self.opts['cse_id'],
        }
    )

    if not res or not res.get('urls'):
        return None

    # Score domains by frequency in results
    domain_counts = {}
    for url in res['urls']:
        domain = self.sf.urlFQDN(url)
        if not domain:
            continue
        # Skip search engines, social media, directories
        skip_domains = ['google.com', 'bing.com', 'yahoo.com',
                       'facebook.com', 'twitter.com', 'linkedin.com',
                       'wikipedia.org', 'yelp.com', 'bbb.org',
                       'yellowpages.com', 'bloomberg.com']
        if any(domain.endswith(s) for s in skip_domains):
            continue
        # Skip the target's own domain
        if self.getTarget().matches(domain):
            continue
        domain_counts[domain] = domain_counts.get(domain, 0) + 1

    if not domain_counts:
        return None

    # Return the most frequently appearing domain
    best = max(domain_counts, key=domain_counts.get)

    # Verify it resolves
    if self.opts['verify_domain'] and not self.sf.resolveHost(best):
        return None

    return best
```

**Method 2 — Domain Guessing** (fallback, no API key needed)

```python
def _guess_company_domain(self, company_name):
    """Try to guess a company's domain from its name."""
    # Normalize: "San Diego Regional Hospital Inc." → "sandiegoregionalhospital"
    name = company_name.lower()
    # Strip common suffixes
    for suffix in ['inc', 'llc', 'corp', 'corporation', 'ltd', 'limited',
                   'co', 'company', 'group', 'holdings', 'partners',
                   'foundation', 'institute', 'hospital', 'health']:
        name = re.sub(rf'\b{suffix}\.?\b', '', name)
    name = re.sub(r'[^a-z0-9]', '', name)

    if len(name) < 3:
        return None

    # Try common TLDs
    for tld in ['.com', '.org', '.net', '.health', '.care']:
        candidate = name + tld
        if self.sf.resolveHost(candidate):
            return candidate

    return None
```

### Handling the FHC Scenario Specifically

The FHC case involves a **sister hospital mentioned on the target's own website**. The pipeline:

1. `sfp_spider` crawls `fhc.example.com`, finds the "About" page mentioning "San Diego Regional Hospital" and possibly linking to their website
2. If there's a **direct link** → `sfp_crossref` already handles this (checks if the external site links back). But `sfp_crossref` requires the external site to link *back* to the target — a sister hospital's website may not.
3. If there's **only a text mention** → `sfp_company` extracts the name → `sfp_associated_company` (this new module) resolves it to a domain → `AFFILIATE_DOMAIN_NAME` fires the full pipeline.

The key insight: `sfp_crossref` finds affiliates by **bidirectional linking**. This new module finds affiliates by **name resolution** — the company name appears on the target's site, so it's associated by definition. No backlink required.

---

## Implementation Order

| # | Module | File | Priority | Dependencies |
|---|--------|------|----------|-------------|
| 1 | Google Dorking | `modules/sfp_google_dork.py` | High | `sflib.py:googleIterate()` (exists) |
| 2 | Associated Company Discovery | `modules/sfp_associated_company.py` | High | `sfp_company.py` (exists), `sflib.py:googleIterate()` (exists) |

Module 1 should be built first because:
- It's self-contained — no new event types needed
- It feeds Module 2 (dorking can discover pages that mention associated companies, which `sfp_company` then extracts)
- It provides immediate value for any scan type

Module 2 should be built second because:
- It depends on `COMPANY_NAME` events which are already flowing
- It completes the affiliate discovery gap
- It specifically solves the FHC/sister hospital problem

---

## Testing Plan

### Module 1: `sfp_google_dork`

1. **Unit tests:** Options, setup, watchedEvents, producedEvents, meta validation (standard pattern)
2. **Dork construction test:** Verify all query templates produce valid Google search syntax
3. **Rate limiting test:** Verify `daily_api_budget` stops queries after limit
4. **URL classification test:** Internal vs external URL routing
5. **Integration test:** Run against a known domain, verify URLs are discovered that `sfp_googlesearch` misses

### Module 2: `sfp_associated_company`

1. **Unit tests:** Standard module tests
2. **Blocklist test:** Common companies (Google, Microsoft) are filtered out
3. **Target exclusion test:** Target's own domain is never emitted as affiliate
4. **Domain guessing test:** "San Diego Regional Hospital Inc." → try `sandiegoregionalhospital.com`
5. **Google lookup test:** Mock Google API response, verify best domain selection
6. **FHC scenario test:** Mock `COMPANY_NAME` event with "San Diego Regional Hospital", verify `AFFILIATE_DOMAIN_NAME` is emitted
7. **Integration test:** Run scan against FHC-like target, verify sister hospital domain appears in results

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Google API rate limiting (100/day free) | Scan stops dorking mid-run | `daily_api_budget` option, Bing fallback, prioritize highest-value dorks first |
| False affiliate discovery | Wrong domain associated with target | `verify_domain` option, Google result frequency scoring, manual review in UI |
| Company name noise | Too many irrelevant lookups | Blocklist, `min_company_name_length`, `max_lookups` cap |
| Dorking finds sensitive data | Ethical/legal concerns | Module only discovers URLs — doesn't download/store content beyond what the spider already does. Same exposure as clicking a Google result. |

---

## Future Enhancements (Out of Scope for v1)

- **Bing API fallback** for dorking when no Google key is configured
- **DuckDuckGo HTML scraping** as a free, no-API-key alternative (fragile, but useful)
- **OpenCorporates integration** in `sfp_associated_company` — use their API to find subsidiaries/parent companies by corporate registration
- **GLEIF relationship data** — the GLEIF API has parent/subsidiary relationship records that could directly answer "who owns who"
- **Reverse WHOIS pivot** — if the target domain's WHOIS registrant is "FHC Holdings LLC", find all other domains registered by the same entity (partially covered by `sfp_reversewhois` already)
- **Healthcare-specific enrichment** — NPI registry, CMS hospital data, joint commission accreditation records (relevant for healthcare clients like FHC)
