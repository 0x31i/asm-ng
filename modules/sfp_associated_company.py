# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_associated_company
# Purpose:     Discover subsidiary and sister organizations by resolving
#              company names found on the target's website to domains.
#              Bridges the COMPANY_NAME → AFFILIATE_DOMAIN_NAME gap.
#
# Author:      ASM-NG
#
# Created:     2026-02-28
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_associated_company(SpiderFootPlugin):

    meta = {
        'name': "Associated Company Discovery",
        'summary': "Discover subsidiary and sister organizations by resolving "
                   "company names to domains. Uses multi-engine search, "
                   "SEC EDGAR (Exhibit 21 subsidiaries), GLEIF parent-child "
                   "relationships, and Wikidata corporate hierarchy data — "
                   "all without API keys.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://efts.sec.gov",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Resolves company names to domains using search "
                           "engines (ddgs), SEC EDGAR subsidiary filings, "
                           "GLEIF corporate relationships, and Wikidata "
                           "SPARQL queries. No API keys required.",
        }
    }

    # Companies that are noise — finding google.com as an affiliate is useless
    COMPANY_BLOCKLIST = [
        'google', 'microsoft', 'amazon', 'apple', 'meta', 'facebook',
        'cloudflare', 'akamai', 'fastly', 'aws', 'azure', 'heroku',
        'netlify', 'vercel', 'digitalocean',
        "let's encrypt", 'digicert', 'comodo', 'sectigo', 'godaddy',
        'globalsign', 'entrust', 'geotrust', 'thawte',
        'wordpress', 'drupal', 'joomla', 'squarespace', 'wix',
        'automattic', 'acquia', 'jquery', 'bootstrap', 'react',
        'adobe', 'oracle', 'ibm', 'salesforce', 'cisco',
        'github', 'gitlab', 'bitbucket', 'atlassian',
    ]

    # Domains to skip when scoring search results
    NOISE_DOMAINS = [
        'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
        'wikipedia.org', 'yelp.com', 'bbb.org', 'yellowpages.com',
        'bloomberg.com', 'crunchbase.com', 'glassdoor.com',
        'indeed.com', 'reddit.com', 'youtube.com', 'tiktok.com',
        'pinterest.com', 'amazon.com', 'apple.com',
    ]

    opts = {
        'use_search': True,
        'use_sec_edgar': True,
        'use_gleif': True,
        'use_wikidata': True,
        'verify_domain': True,
        'max_lookups': 30,
        'min_name_length': 5,
        'exclude_common_companies': True,
        'delay': 1.5,
    }

    optdescs = {
        'use_search': "Use multi-engine search (ddgs) to find company "
                      "domains from names.",
        'use_sec_edgar': "Check SEC EDGAR for subsidiary listings "
                         "(US public companies, Exhibit 21).",
        'use_gleif': "Check GLEIF for parent/subsidiary relationships "
                     "(global, LEI-based).",
        'use_wikidata': "Check Wikidata for organizational relationships "
                        "(P749/P355 properties).",
        'verify_domain': "DNS-verify discovered domains before emitting.",
        'max_lookups': "Maximum company name lookups per scan.",
        'min_name_length': "Minimum company name length to process.",
        'exclude_common_companies': "Skip common tech/infra companies "
                                    "(Google, Microsoft, etc.).",
        'delay': "Delay between API calls in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._lookup_count = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["COMPANY_NAME"]

    def producedEvents(self):
        return [
            "AFFILIATE_DOMAIN_NAME",
            "AFFILIATE_INTERNET_NAME",
            "COMPANY_NAME",
        ]

    def _is_blocked_company(self, name):
        """Check if a company name is in the blocklist."""
        name_lower = name.lower()
        for blocked in self.COMPANY_BLOCKLIST:
            if blocked in name_lower:
                return True
        return False

    def _is_noise_domain(self, domain):
        """Check if a domain is a noise domain (search engines, social, etc.)."""
        for noise in self.NOISE_DOMAINS:
            if domain.endswith(noise):
                return True
        return False

    def _search_company_domain(self, company_name):
        """Search for a company name and return the most likely domain.

        Uses ddgs multi-engine search, scores domains by frequency
        in results, and returns the best candidate.
        """
        res = self.sf.ddgsIterate(
            f'"{company_name}"',
            opts={'max_results': 15})

        if not res or not res.get('urls'):
            return None

        domain_counts = {}
        for url in res['urls']:
            domain = self.sf.urlFQDN(url)
            if not domain:
                continue
            if self._is_noise_domain(domain):
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
        if self.opts['verify_domain']:
            if not self.sf.resolveHost(best) and \
               not self.sf.resolveHost6(best):
                self.debug(f"Domain {best} does not resolve, skipping.")
                return None

        return best

    def _guess_company_domain(self, company_name):
        """Try to guess a company's domain from its name."""
        name = company_name.lower()
        # Strip common suffixes
        for suffix in ['incorporated', 'corporation', 'company',
                       'limited', 'holdings', 'partners', 'foundation',
                       'institute', 'group', 'associates', 'solutions',
                       'services', 'technologies', 'systems',
                       'inc', 'llc', 'corp', 'ltd', 'co', 'plc',
                       'sa', 'ag', 'gmbh', 'bv', 'nv', 'pty']:
            name = re.sub(rf'\b{suffix}\.?\b', '', name)
        name = re.sub(r'[^a-z0-9]', '', name)

        if len(name) < 3:
            return None

        for tld in ['.com', '.org', '.net']:
            candidate = name + tld
            if self.sf.resolveHost(candidate):
                # Don't return target's own domain
                if not self.getTarget().matches(candidate):
                    return candidate

        return None

    def _check_sec_subsidiaries(self, company_name, event):
        """Check SEC EDGAR for subsidiaries in Exhibit 21 filings.

        SEC EDGAR API requires no authentication — only a User-Agent
        header with company name and email per fair-use policy.
        """
        encoded = urllib.parse.quote(f'"{company_name}"')
        url = (f"https://efts.sec.gov/LATEST/search-index"
               f"?q={encoded}&forms=10-K&dateRange=custom"
               f"&startdt=2023-01-01")

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent='ASM-NG scan@asm-ng.local',
        )

        if not res or not res.get('content'):
            return

        try:
            data = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            return

        hits = data.get('hits', {}).get('hits', [])
        if not hits:
            return

        # Get the most recent 10-K filing
        for hit in hits[:3]:
            if self.checkForStop():
                return

            source = hit.get('_source', {})
            file_num = source.get('file_num', '')
            entity_name = source.get('entity_name', '')

            if entity_name and entity_name != company_name:
                dedup = f"sec:{entity_name.lower()}"
                if dedup not in self.results:
                    self.results[dedup] = True
                    self.info(f"SEC EDGAR: found entity {entity_name}")
                    evt = SpiderFootEvent(
                        "COMPANY_NAME", entity_name,
                        self.__class__.__name__, event)
                    self.notifyListeners(evt)

    def _check_gleif_relationships(self, company_name, event):
        """Check GLEIF for parent/subsidiary relationships.

        GLEIF API is zero-key with parent-child relationship endpoints.
        """
        encoded = urllib.parse.quote(company_name)
        url = (f"https://api.gleif.org/api/v1/fuzzycompletions"
               f"?q={encoded}&field=entity.legalName")

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG'),
            headers={'Accept': 'application/vnd.api+json'},
        )

        if not res or not res.get('content'):
            return

        try:
            data = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            return

        records = data.get('data', [])
        if not records:
            return

        # Extract LEI from first match and check relationships
        for record in records[:2]:
            if self.checkForStop():
                return

            relationships = record.get('relationships', {})
            lei_data = relationships.get('lei-records', {}).get('data', {})
            lei = lei_data.get('id', '')
            if not lei:
                continue

            # Check direct parent
            parent_url = (f"https://api.gleif.org/api/v1"
                          f"/lei-records/{lei}"
                          f"/direct-parent")
            parent_res = self.sf.fetchUrl(
                parent_url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'ASM-NG'),
                headers={'Accept': 'application/vnd.api+json'},
            )

            if parent_res and parent_res.get('content'):
                try:
                    parent_data = json.loads(parent_res['content'])
                    p_entity = (parent_data.get('data', {})
                                .get('attributes', {})
                                .get('entity', {}))
                    p_name = (p_entity.get('legalName', {})
                              .get('value', ''))
                    if p_name and p_name.lower() != company_name.lower():
                        dedup = f"gleif:{p_name.lower()}"
                        if dedup not in self.results:
                            self.results[dedup] = True
                            self.info(f"GLEIF parent: {p_name}")
                            evt = SpiderFootEvent(
                                "COMPANY_NAME", p_name,
                                self.__class__.__name__, event)
                            self.notifyListeners(evt)
                except (json.JSONDecodeError, ValueError, AttributeError):
                    pass

    def _check_wikidata(self, company_name, event):
        """Check Wikidata for organizational relationships via SPARQL."""
        query = f"""
        SELECT ?subsidiary ?subsidiaryLabel ?website WHERE {{
          ?org rdfs:label "{company_name}"@en .
          ?subsidiary wdt:P749 ?org .
          OPTIONAL {{ ?subsidiary wdt:P856 ?website }}
          SERVICE wikibase:label {{
            bd:serviceParam wikibase:language "en"
          }}
        }}
        LIMIT 20
        """

        params = urllib.parse.urlencode({
            'query': query,
            'format': 'json',
        })

        res = self.sf.fetchUrl(
            f"https://query.wikidata.org/sparql?{params}",
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG'),
        )

        if not res or not res.get('content'):
            return

        try:
            data = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            return

        bindings = data.get('results', {}).get('bindings', [])
        for binding in bindings:
            if self.checkForStop():
                return

            sub_name = binding.get('subsidiaryLabel', {}).get('value', '')
            website = binding.get('website', {}).get('value', '')

            if sub_name:
                dedup = f"wikidata:{sub_name.lower()}"
                if dedup not in self.results:
                    self.results[dedup] = True
                    self.info(f"Wikidata subsidiary: {sub_name}")
                    evt = SpiderFootEvent(
                        "COMPANY_NAME", sub_name,
                        self.__class__.__name__, event)
                    self.notifyListeners(evt)

            if website:
                domain = self.sf.urlFQDN(website)
                if domain and not self.getTarget().matches(domain):
                    dedup = f"wdomain:{domain}"
                    if dedup not in self.results:
                        self.results[dedup] = True
                        evt = SpiderFootEvent(
                            "AFFILIATE_DOMAIN_NAME", domain,
                            self.__class__.__name__, event)
                        self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        company_name = eventData.strip()

        # Filter: too short
        if len(company_name) < self.opts['min_name_length']:
            self.debug(f"Company name too short: {company_name}")
            return

        # Filter: common/noise companies
        if self.opts['exclude_common_companies']:
            if self._is_blocked_company(company_name):
                self.debug(f"Skipping common company: {company_name}")
                return

        # Filter: already looked up
        dedup_key = f"company:{company_name.lower()}"
        if dedup_key in self.results:
            return
        self.results[dedup_key] = True

        # Filter: max lookups
        if self._lookup_count >= self.opts['max_lookups']:
            self.debug(f"Reached max_lookups limit "
                       f"({self.opts['max_lookups']}), skipping.")
            return
        self._lookup_count += 1

        self.info(f"Resolving company: {company_name}")

        # Method 1: Search engine domain resolution
        domain = None
        if self.opts['use_search']:
            domain = self._search_company_domain(company_name)
            if domain:
                self.info(f"Search found domain for "
                          f"'{company_name}': {domain}")

        # Method 2: Domain guessing fallback
        if not domain:
            domain = self._guess_company_domain(company_name)
            if domain:
                self.info(f"Guessed domain for "
                          f"'{company_name}': {domain}")

        # Emit affiliate domain if found
        if domain:
            if not self.getTarget().matches(domain):
                evt = SpiderFootEvent(
                    "AFFILIATE_DOMAIN_NAME", domain,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

        # Method 3: SEC EDGAR subsidiaries (emits COMPANY_NAME events)
        if self.opts['use_sec_edgar']:
            if self.checkForStop():
                return
            self._check_sec_subsidiaries(company_name, event)

        # Method 4: GLEIF parent/subsidiary (emits COMPANY_NAME events)
        if self.opts['use_gleif']:
            if self.checkForStop():
                return
            self._check_gleif_relationships(company_name, event)

        # Method 5: Wikidata subsidiaries
        if self.opts['use_wikidata']:
            if self.checkForStop():
                return
            self._check_wikidata(company_name, event)


# End of sfp_associated_company class
