# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_search_dork
# Purpose:     Multi-engine search dorking using advanced search operators
#              (filetype:, inurl:, intitle:, site:) to discover exposed
#              documents, admin panels, config files, and third-party mentions.
#
# Author:      ASM-NG
#
# Created:     2026-02-28
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import re
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_search_dork(SpiderFootPlugin):

    meta = {
        'name': "Search Engine Dorking",
        'summary': "Use advanced search operators (filetype:, inurl:, intitle:) "
                   "across multiple search engines to discover exposed documents, "
                   "admin panels, config files, directory listings, and "
                   "third-party data exposure. Works without API keys via ddgs.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://github.com/deedy5/ddgs",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Multi-engine search using ddgs (9 backends: Google, "
                           "Bing, Brave, DuckDuckGo, Mojeek, Yandex, Yahoo, "
                           "etc.) with advanced search operators for attack "
                           "surface discovery. No API keys required.",
        }
    }

    # Dork categories: (query_template, description)
    # {target} is replaced with the domain name
    FILETYPE_DORKS = [
        ('site:{target} filetype:pdf', 'PDF documents'),
        ('site:{target} filetype:doc OR filetype:docx', 'Word documents'),
        ('site:{target} filetype:xls OR filetype:xlsx OR filetype:csv',
         'Spreadsheets'),
        ('site:{target} filetype:ppt OR filetype:pptx', 'Presentations'),
        ('site:{target} filetype:sql OR filetype:bak OR filetype:db',
         'Database files'),
        ('site:{target} filetype:log', 'Log files'),
        ('site:{target} filetype:conf OR filetype:cfg OR filetype:ini',
         'Config files'),
    ]

    ADMIN_DORKS = [
        ('site:{target} inurl:admin', 'Admin panels'),
        ('site:{target} inurl:login OR inurl:signin', 'Login pages'),
        ('site:{target} intitle:"dashboard"', 'Dashboards'),
        ('site:{target} inurl:portal', 'Portals'),
        ('site:{target} intitle:"index of"', 'Directory listings'),
    ]

    CONFIG_DORKS = [
        ('site:{target} filetype:env OR filetype:yml OR filetype:yaml',
         'Environment/config files'),
        ('site:{target} intitle:"phpinfo()"', 'PHP info pages'),
        ('site:{target} filetype:xml "password" OR "api_key"',
         'Secrets in XML'),
    ]

    THIRDPARTY_DORKS = [
        ('"{target}" site:pastebin.com OR site:paste.ee', 'Paste sites'),
        ('"{target}" site:github.com OR site:gitlab.com', 'Code repos'),
        ('"{target}" site:trello.com OR site:notion.so',
         'Project management'),
        ('"{target}" "password" OR "credentials" -site:{target}',
         'Leaked credentials'),
    ]

    opts = {
        'search_backend': 'ddgs',
        'searxng_url': '',
        'google_api_key': '',
        'google_cse_id': '013611106330597893267:tfgl3wxdtbp',
        'max_dorks': 15,
        'scrape_depth': 1,
        'delay': 2.0,
        'enable_filetype_dorks': True,
        'enable_admin_dorks': True,
        'enable_config_dorks': True,
        'enable_thirdparty_dorks': True,
    }

    optdescs = {
        'search_backend': "Search backend: 'ddgs' (free, no key), "
                          "'searxng' (self-hosted), or 'google_cse' "
                          "(requires API key).",
        'searxng_url': "URL of self-hosted SearXNG instance "
                       "(e.g. http://localhost:8888). Only used when "
                       "search_backend is 'searxng'.",
        'google_api_key': "Google API key. Only used when search_backend "
                          "is 'google_cse'.",
        'google_cse_id': "Google Custom Search Engine ID.",
        'max_dorks': "Maximum number of dork queries per domain.",
        'scrape_depth': "Levels deep to fetch discovered URLs (0-2). "
                        "Higher values find more but are slower.",
        'delay': "Delay in seconds between search queries.",
        'enable_filetype_dorks': "Search for exposed documents "
                                 "(PDF, DOC, XLS, SQL, etc.).",
        'enable_admin_dorks': "Search for admin panels and login pages.",
        'enable_config_dorks': "Search for config files and error pages.",
        'enable_thirdparty_dorks': "Search for third-party mentions "
                                   "(paste sites, code repos, etc.).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._query_count = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return [
            "LINKED_URL_INTERNAL",
            "LINKED_URL_EXTERNAL",
            "SEARCH_ENGINE_WEB_CONTENT",
            "RAW_RIR_DATA",
        ]

    def _search(self, query):
        """Execute a search using the configured backend.

        Returns:
            dict: {"urls": [...], "webSearchUrl": "..."} or None
        """
        backend = self.opts['search_backend']

        if backend == 'ddgs':
            return self.sf.ddgsIterate(
                query, opts={'max_results': 20})

        elif backend == 'searxng':
            return self._search_searxng(query)

        elif backend == 'google_cse':
            if not self.opts.get('google_api_key'):
                self.debug("No Google API key configured.")
                return None
            return self.sf.googleIterate(
                searchString=query,
                opts={
                    'timeout': self.opts.get('_fetchtimeout', 15),
                    'useragent': self.opts.get('_useragent', 'ASM-NG'),
                    'api_key': self.opts['google_api_key'],
                    'cse_id': self.opts['google_cse_id'],
                })

        return None

    def _search_searxng(self, query):
        """Search via a self-hosted SearXNG instance."""
        base_url = self.opts.get('searxng_url', '').rstrip('/')
        if not base_url:
            return None

        import urllib.parse
        params = urllib.parse.urlencode({
            'q': query,
            'format': 'json',
            'engines': 'google,bing,duckduckgo',
        })

        res = self.sf.fetchUrl(
            f"{base_url}/search?{params}",
            timeout=self.opts.get('_fetchtimeout', 15),
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return None

        try:
            import json
            data = json.loads(res['content'])
        except (ValueError, Exception):
            return None

        urls = [r.get('url') for r in data.get('results', [])
                if r.get('url')]
        if not urls:
            return None

        return {
            "urls": urls,
            "webSearchUrl": f"{base_url}/search?q={query}"
        }

    def _scrape_url(self, url, target_domain, event, depth):
        """Fetch a discovered URL and emit content for downstream analysis."""
        if depth > self.opts['scrape_depth']:
            return
        if depth < 0:
            return

        scrape_key = f"scrape:{url}"
        if scrape_key in self.results:
            return
        self.results[scrape_key] = True

        if self.checkForStop():
            return

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts.get('_fetchtimeout', 15),
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return

        content = res['content']

        # Emit web content for downstream analysis (sfp_company, etc.)
        evt = SpiderFootEvent(
            "SEARCH_ENGINE_WEB_CONTENT",
            content,
            self.__class__.__name__, event)
        self.notifyListeners(evt)

        # Follow links one level deeper if depth allows
        if depth < self.opts['scrape_depth']:
            links = re.findall(
                r'href=["\']?(https?://[^"\'>\s]+)', content)
            followed = 0
            for link in links:
                if followed >= 20:
                    break
                if self.checkForStop():
                    return
                link_domain = self.sf.urlFQDN(link)
                if not link_domain:
                    continue
                # Only follow links to the same domain
                if not link_domain.endswith(target_domain):
                    continue
                if link in self.results:
                    continue
                self.results[link] = True
                followed += 1
                self._scrape_url(link, target_domain, event, depth + 1)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Already dorked {eventData}, skipping.")
            return
        self.results[eventData] = True

        # Build dork list based on enabled categories
        dorks = []
        if self.opts['enable_filetype_dorks']:
            dorks.extend(self.FILETYPE_DORKS)
        if self.opts['enable_admin_dorks']:
            dorks.extend(self.ADMIN_DORKS)
        if self.opts['enable_config_dorks']:
            dorks.extend(self.CONFIG_DORKS)
        if self.opts['enable_thirdparty_dorks']:
            dorks.extend(self.THIRDPARTY_DORKS)

        # Respect max_dorks limit
        dorks = dorks[:self.opts['max_dorks']]

        for query_template, category in dorks:
            if self.checkForStop():
                return

            query = query_template.format(target=eventData)
            self.info(f"Dorking [{category}]: {query}")

            res = self._search(query)
            self._query_count += 1

            if not res or not res.get('urls'):
                time.sleep(self.opts['delay'])
                continue

            # Emit raw search results
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(res), self.__class__.__name__, event)
            self.notifyListeners(evt)

            for url in res['urls']:
                if url in self.results:
                    continue
                self.results[url] = True

                # Classify as internal or external
                url_domain = self.sf.urlFQDN(url)
                if not url_domain:
                    continue

                if url_domain.endswith(eventData):
                    evt = SpiderFootEvent(
                        "LINKED_URL_INTERNAL", url,
                        self.__class__.__name__, event)
                else:
                    evt = SpiderFootEvent(
                        "LINKED_URL_EXTERNAL", url,
                        self.__class__.__name__, event)
                self.notifyListeners(evt)

                # Optionally scrape discovered URL
                if self.opts['scrape_depth'] >= 1:
                    self._scrape_url(url, eventData, event, 1)

            time.sleep(self.opts['delay'])


# End of sfp_search_dork class
