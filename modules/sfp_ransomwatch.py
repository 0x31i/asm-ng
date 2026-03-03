# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ransomwatch
# Purpose:     Search ransomware.live API for ransomware leak site mentions of
#              the target.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ransomwatch(SpiderFootPlugin):

    meta = {
        'name': "RansomWatch",
        'summary': "Search ransomware.live API for ransomware group leak site mentions of the target. "
        "Tracks 300+ ransomware groups and 26,000+ victims.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://www.ransomware.live/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://www.ransomware.live/apidocs",
            ],
            'favIcon': "",
            'logo': "",
            'description': "ransomware.live is a monitoring tool tracking 300+ ransomware groups "
            "and their leak sites. It provides searchable victim data, group profiles, "
            "and .onion claim URLs. Free API with daily rate limits.",
        }
    }

    opts = {
        'max_results': 100,
    }

    optdescs = {
        'max_results': "Maximum number of results to process per query.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "COMPANY_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return [
            "RANSOMWARE_LEAK_MENTION",
            "DARKNET_MENTION_URL",
            "DARKNET_MENTION_CONTENT",
            "RAW_RIR_DATA",
        ]

    def _searchVictims(self, keyword):
        """Search ransomware.live v2 API for victims matching a keyword.

        The API does substring matching across victim name and domain fields.
        """
        encoded = urllib.parse.quote(keyword)
        url = f"https://api.ransomware.live/v2/searchvictims/{encoded}"

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts['_useragent'],
        )

        if not res or not res.get('content'):
            self.debug(f"No response from ransomware.live for: {keyword}")
            return None

        if res.get('code') == '429':
            self.error("Rate limited by ransomware.live API. Daily limit reached.")
            return None

        if res.get('code') == '404':
            self.debug(f"No victims found on ransomware.live for: {keyword}")
            return None

        if res.get('code') not in ('200', '301', '302'):
            self.debug(f"Unexpected response code from ransomware.live: {res.get('code')}")
            return None

        try:
            data = json.loads(res['content'])
            if isinstance(data, list):
                return data
            return None
        except Exception as e:
            self.debug(f"Error parsing ransomware.live JSON: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Search by the event data directly
        victims = self._searchVictims(eventData)

        # For DOMAIN_NAME, also try the bare name without TLD
        if not victims and eventName == "DOMAIN_NAME" and '.' in eventData:
            bare = eventData.split('.')[0]
            if len(bare) > 2:
                victims = self._searchVictims(bare)

        if not victims:
            self.debug(f"ransomware.live: no victims found for {eventData}")
            return

        count = 0
        maxResults = self.opts.get('max_results', 100)

        for victim in victims:
            if self.checkForStop():
                return

            if count >= maxResults:
                break

            if not isinstance(victim, dict):
                continue

            group = victim.get('group', 'Unknown')
            victim_name = victim.get('victim', '')
            domain = victim.get('domain', '')
            country = victim.get('country', '')
            activity = victim.get('activity', '')
            discovered = victim.get('discovered', '')
            claim_url = victim.get('claim_url', '')
            description = victim.get('description', '')
            screenshot = victim.get('screenshot', '')
            url = victim.get('url', '')

            # Build detailed mention text
            mention_parts = [f"Ransomware group '{group}' listed '{victim_name}'"]
            if domain:
                mention_parts.append(f"Domain: {domain}")
            if country:
                mention_parts.append(f"Country: {country}")
            if activity:
                mention_parts.append(f"Sector: {activity}")
            if discovered:
                mention_parts.append(f"Discovered: {discovered}")
            mention_parts.append("Source: ransomware.live")

            mention_text = " | ".join(mention_parts)

            evt = SpiderFootEvent(
                "RANSOMWARE_LEAK_MENTION",
                mention_text,
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)
            count += 1

            # Emit .onion claim URL
            if claim_url and '.onion' in claim_url:
                evt2 = SpiderFootEvent(
                    "DARKNET_MENTION_URL",
                    claim_url,
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)

            # Emit description snippet as content
            if description:
                snippet = description[:500]
                evt3 = SpiderFootEvent(
                    "DARKNET_MENTION_CONTENT",
                    f"Ransomware leak site listing for '{victim_name}' by {group}:\n{snippet}",
                    self.__class__.__name__,
                    evt,
                )
                self.notifyListeners(evt3)

            # Emit full structured data for the first few results
            if count <= 10:
                raw = {
                    'victim': victim_name,
                    'group': group,
                    'domain': domain,
                    'country': country,
                    'sector': activity,
                    'discovered': discovered,
                    'claim_url': claim_url,
                    'screenshot': screenshot,
                    'url': url,
                    'source': 'ransomware.live',
                }
                evt4 = SpiderFootEvent(
                    "RAW_RIR_DATA",
                    f"ransomware.live victim record:\n{json.dumps(raw, indent=2)}",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt4)

# End of sfp_ransomwatch class
