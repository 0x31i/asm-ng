# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_darkweb_aggregate
# Purpose:     Aggregate search across multiple Tor search engines not already
#              covered by dedicated modules (Haystak, Tor66).
#              Requires Tor SOCKS proxy to be configured.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_darkweb_aggregate(SpiderFootPlugin):

    meta = {
        'name': "Dark Web Aggregate Search",
        'summary': "Search multiple Tor search engines (Haystak, Tor66) for mentions "
        "of the target. Requires Tor SOCKS proxy (127.0.0.1:9050).",
        'flags': ["tor"],
        'useCases': ["Footprint", "Investigate", "Dark Web Exposure"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'favIcon': "",
            'logo': "",
            'description': "Aggregated search across Tor-only search engines "
            "(Haystak, Tor66) that have no clearnet portals. "
            "Requires a Tor SOCKS proxy to be running. "
            "Configure SOCKS Type=TOR, Address=127.0.0.1, Port=9050 in scan settings.",
        }
    }

    opts = {
        'fetchlinks': True,
        'fullnames': True,
        'max_results_per_engine': 50,
    }

    optdescs = {
        'fetchlinks': "Fetch the darknet pages (via Tor) to verify they mention your target.",
        'fullnames': "Search for human names?",
        'max_results_per_engine': "Maximum number of results to process per search engine.",
    }

    results = None
    _torAvailable = False

    # These Tor search engines have NO clearnet portals — Tor is mandatory
    SEARCH_ENGINES = [
        {
            'name': 'Haystak',
            'url': 'http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/',
            'search_path': '?q={query}',
            'link_pattern': r'href=["\'](?:https?://)?([a-z2-7]{56}\.onion[^"\']*)["\']',
        },
        {
            'name': 'Tor66',
            'url': 'http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiber7qd.onion/',
            'search_path': 'search?q={query}',
            'link_pattern': r'href=["\'](?:https?://)?([a-z2-7]{56}\.onion[^"\']*)["\']',
        },
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._torAvailable = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def _checkTorProxy(self):
        """Check if Tor SOCKS proxy is configured in scan settings."""
        socks_type = self.opts.get('_socks1type', '')
        socks_addr = self.opts.get('_socks2addr', '')
        socks_port = self.opts.get('_socks3port', '')

        if not socks_type or str(socks_type).upper() not in ('TOR', 'SOCKS5', 'HTTP'):
            return False

        if not socks_addr:
            return False

        return True

    def watchedEvents(self):
        return ["DOMAIN_NAME", "HUMAN_NAME", "EMAILADDR"]

    def producedEvents(self):
        return [
            "DARKNET_MENTION_URL",
            "DARKNET_MENTION_CONTENT",
            "ONION_SERVICE_DETECTED",
        ]

    def searchEngine(self, engine, query):
        """Search a single Tor search engine for the query."""
        results = []

        base_url = engine['url']
        search_path = engine['search_path'].format(query=urllib.parse.quote(query))
        url = base_url + search_path

        data = self.sf.fetchUrl(
            url,
            useragent=self.opts['_useragent'],
            timeout=30,
        )

        if not data or not data.get('content'):
            self.debug(f"No results from {engine['name']} for: {query}")
            return results

        content = data['content']

        # Extract .onion links
        links = re.findall(
            engine.get('link_pattern', r'([a-z2-7]{56}\.onion[^\s"\'<>]*)'),
            content,
            re.IGNORECASE,
        )

        seen = set()
        for link in links:
            if len(results) >= self.opts.get('max_results_per_engine', 50):
                break

            # Normalize the link
            if not link.startswith('http'):
                link = f"http://{link}"

            if link in seen:
                continue
            seen.add(link)
            results.append(link)

        return results

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            self.debug(f"Skipping HUMAN_NAME: {eventData}")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Check Tor availability on first event
        if not self._torAvailable:
            if self._checkTorProxy():
                self._torAvailable = True
                self.info("Tor SOCKS proxy detected — dark web aggregate search enabled.")
            else:
                self.info(
                    "Dark Web Aggregate Search requires a Tor SOCKS proxy. "
                    "Configure: SOCKS Type=TOR, Address=127.0.0.1, Port=9050 in scan settings. "
                    "Install Tor: apt install tor (Linux) or brew install tor (macOS). "
                    "Skipping dark web search engine queries."
                )
                return

        allLinks = []

        for engine in self.SEARCH_ENGINES:
            if self.checkForStop():
                return

            self.debug(f"Searching {engine['name']} for: {eventData}")
            links = self.searchEngine(engine, eventData)
            if links:
                self.info(f"{engine['name']}: found {len(links)} .onion links for {eventData}")
            allLinks.extend(links)

        if not allLinks:
            self.info(f"No darknet mentions found across {len(self.SEARCH_ENGINES)} Tor search engines for: {eventData}")
            return

        for link in allLinks:
            if self.checkForStop():
                return

            if link in self.results:
                continue

            self.results[link] = True

            # Detect .onion services
            onion_match = re.search(r'([a-z2-7]{56}\.onion)', link, re.IGNORECASE)
            if onion_match:
                onion_addr = onion_match.group(1)
                if onion_addr not in self.results:
                    self.results[onion_addr] = True
                    evt = SpiderFootEvent(
                        "ONION_SERVICE_DETECTED",
                        onion_addr,
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

            if not self.opts['fetchlinks']:
                evt = SpiderFootEvent(
                    "DARKNET_MENTION_URL",
                    link,
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)
                continue

            # Attempt to fetch and verify the link mentions the target
            res = self.sf.fetchUrl(
                link,
                timeout=self.opts['_fetchtimeout'],
                useragent=self.opts['_useragent'],
                verify=False,
            )

            if not res or res.get('content') is None:
                self.debug(f"Ignoring {link} as no data returned")
                # Still emit the URL even if we can't verify
                evt = SpiderFootEvent(
                    "DARKNET_MENTION_URL",
                    link,
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)
                continue

            if eventData.lower() not in res['content'].lower():
                self.debug(f"Ignoring {link} as no mention of {eventData}")
                continue

            evt = SpiderFootEvent(
                "DARKNET_MENTION_URL",
                link,
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

            try:
                startIndex = res['content'].lower().index(eventData.lower()) - 120
                if startIndex < 0:
                    startIndex = 0
                endIndex = startIndex + len(eventData) + 240
            except ValueError:
                continue

            wdata = res['content'][startIndex:endIndex]
            evt2 = SpiderFootEvent(
                "DARKNET_MENTION_CONTENT",
                f"...{wdata}...",
                self.__class__.__name__,
                evt,
            )
            self.notifyListeners(evt2)

# End of sfp_darkweb_aggregate class
