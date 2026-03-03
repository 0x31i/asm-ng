# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_deepdarkcti
# Purpose:     Cross-reference discovered darknet URLs and domains against the
#              deepdarkCTI curated threat intelligence watchlists.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_deepdarkcti(SpiderFootPlugin):

    meta = {
        'name': "DeepDarkCTI",
        'summary': "Cross-reference discovered .onion URLs and domains against the "
        "deepdarkCTI curated watchlists of ransomware groups, forums, and markets.",
        'flags': [],
        'useCases': ["Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://github.com/fastfire/deepdarkCTI",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://github.com/fastfire/deepdarkCTI",
            ],
            'favIcon': "",
            'logo': "",
            'description': "deepdarkCTI is a collection of cyber threat intelligence "
            "sources from the deep and dark web. It curates lists of ransomware "
            "groups, forums, markets, and Telegram channels used for cybercrime.",
        }
    }

    opts = {
        'ransomware_list_url': 'https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md',
        'forum_list_url': 'https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/forum.md',
        'market_list_url': 'https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/market.md',
    }

    optdescs = {
        'ransomware_list_url': "URL to the deepdarkCTI ransomware gang list (raw markdown).",
        'forum_list_url': "URL to the deepdarkCTI forum list (raw markdown).",
        'market_list_url': "URL to the deepdarkCTI market list (raw markdown).",
    }

    results = None
    watchlists = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.watchlists = None

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DARKNET_MENTION_URL", "ONION_SERVICE_DETECTED", "DOMAIN_NAME"]

    def producedEvents(self):
        return [
            "THREAT_INTEL_FEED_MATCH",
            "DARKWEB_FORUM_MENTION",
            "RAW_RIR_DATA",
        ]

    def loadWatchlists(self):
        """Load and parse all deepdarkCTI watchlists."""
        if self.watchlists is not None:
            return

        self.watchlists = {
            'ransomware': set(),
            'forums': set(),
            'markets': set(),
        }

        lists = [
            ('ransomware', self.opts.get('ransomware_list_url', '')),
            ('forums', self.opts.get('forum_list_url', '')),
            ('markets', self.opts.get('market_list_url', '')),
        ]

        for list_type, url in lists:
            if not url:
                continue

            res = self.sf.fetchUrl(
                url,
                timeout=30,
                useragent=self.opts['_useragent'],
            )

            if not res or not res.get('content'):
                self.debug(f"Could not fetch {list_type} list from deepdarkCTI")
                continue

            # Extract .onion addresses from the markdown
            onions = re.findall(
                r'([a-z2-7]{56}\.onion)',
                res['content'],
                re.IGNORECASE,
            )

            # Also extract regular domains mentioned as indicators
            domains = re.findall(
                r'(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,})',
                res['content'],
            )

            for onion in onions:
                self.watchlists[list_type].add(onion.lower())

            for domain in domains:
                # Filter out github.com and other common non-threat domains
                if domain.lower() not in ('github.com', 'raw.githubusercontent.com',
                                           'gitlab.com', 'twitter.com', 'x.com'):
                    self.watchlists[list_type].add(domain.lower())

        total = sum(len(v) for v in self.watchlists.values())
        self.info(f"Loaded {total} indicators from deepdarkCTI watchlists")

    def checkAgainstWatchlists(self, indicator):
        """Check an indicator against all watchlists.

        Returns list of (list_type, indicator) matches.
        """
        matches = []
        indicator_lower = indicator.lower()

        for list_type, indicators in self.watchlists.items():
            for watchlist_entry in indicators:
                if watchlist_entry in indicator_lower or indicator_lower in watchlist_entry:
                    matches.append((list_type, watchlist_entry))

        return matches

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Load watchlists on first use
        self.loadWatchlists()

        if not self.watchlists:
            return

        matches = self.checkAgainstWatchlists(eventData)

        if not matches:
            return

        for list_type, matched_indicator in matches:
            if self.checkForStop():
                return

            if list_type == 'ransomware':
                evt = SpiderFootEvent(
                    "THREAT_INTEL_FEED_MATCH",
                    f"Ransomware group indicator match: {eventData} matched "
                    f"deepdarkCTI ransomware list entry: {matched_indicator}",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

            elif list_type == 'forums':
                evt = SpiderFootEvent(
                    "DARKWEB_FORUM_MENTION",
                    f"Dark web forum match: {eventData} matched "
                    f"deepdarkCTI forum list entry: {matched_indicator}",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

                evt2 = SpiderFootEvent(
                    "THREAT_INTEL_FEED_MATCH",
                    f"Forum indicator match: {eventData} matched "
                    f"deepdarkCTI forum list entry: {matched_indicator}",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)

            elif list_type == 'markets':
                evt = SpiderFootEvent(
                    "THREAT_INTEL_FEED_MATCH",
                    f"Dark web market match: {eventData} matched "
                    f"deepdarkCTI market list entry: {matched_indicator}",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

        # Raw data for all matches
        evt = SpiderFootEvent(
            "RAW_RIR_DATA",
            str({'indicator': eventData, 'matches': matches}),
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt)

# End of sfp_deepdarkcti class
