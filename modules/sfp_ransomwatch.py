# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ransomwatch
# Purpose:     Search RansomLook API for ransomware leak site mentions of
#              the target.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ransomwatch(SpiderFootPlugin):

    meta = {
        'name': "RansomWatch",
        'summary': "Search RansomLook API for ransomware leak site mentions of the target.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://www.ransomlook.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.ransomlook.io/api",
            ],
            'favIcon': "",
            'logo': "",
            'description': "RansomLook is a monitoring tool for ransomware leak sites. "
            "It tracks ransomware groups and their victims to provide threat intelligence "
            "on active ransomware campaigns.",
        }
    }

    opts = {
        'max_results': 100,
    }

    optdescs = {
        'max_results': "Maximum number of results to process per query.",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "COMPANY_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return [
            "RANSOMWARE_LEAK_MENTION",
            "DARKNET_MENTION_URL",
            "DARKNET_MENTION_CONTENT",
        ]

    def query(self, target):
        """Query the RansomLook API for a target."""
        encoded = urllib.parse.quote(target)
        url = f"https://api.ransomlook.io/v2/search/{encoded}"

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts['_useragent'],
        )

        if not res or not res.get('content'):
            self.debug(f"No response from RansomLook for: {target}")
            return None

        if res.get('code') != '200':
            self.debug(f"Unexpected response code from RansomLook: {res.get('code')}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing JSON response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)
        if not data:
            return

        count = 0
        maxResults = self.opts.get('max_results', 100)

        # RansomLook returns results grouped by ransomware group
        entries = data if isinstance(data, list) else data.get('data', data.get('results', []))
        if isinstance(entries, dict):
            # Flatten dict-of-lists structure
            flat = []
            for group_name, victims in entries.items():
                if isinstance(victims, list):
                    for v in victims:
                        if isinstance(v, dict):
                            v['_group'] = group_name
                        flat.append(v)
                elif isinstance(victims, dict):
                    victims['_group'] = group_name
                    flat.append(victims)
            entries = flat

        if not isinstance(entries, list):
            return

        for entry in entries:
            if self.checkForStop():
                return

            if count >= maxResults:
                break

            if isinstance(entry, dict):
                group = entry.get('group_name', entry.get('_group', 'Unknown'))
                victim = entry.get('post_title', entry.get('victim', entry.get('name', '')))
                post_url = entry.get('post_url', entry.get('url', ''))
                description = entry.get('description', entry.get('post_content', ''))
                discovered = entry.get('discovered', entry.get('date', ''))

                mention_text = f"Ransomware group '{group}' listed '{victim}'"
                if discovered:
                    mention_text += f" (discovered: {discovered})"

                evt = SpiderFootEvent(
                    "RANSOMWARE_LEAK_MENTION",
                    mention_text,
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)
                count += 1

                if post_url:
                    evt2 = SpiderFootEvent(
                        "DARKNET_MENTION_URL",
                        post_url,
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt2)

                if description:
                    try:
                        startIndex = max(0, description.lower().index(eventData.lower()) - 120)
                        endIndex = startIndex + len(eventData) + 240
                        snippet = description[startIndex:endIndex]
                    except ValueError:
                        snippet = description[:360]

                    evt3 = SpiderFootEvent(
                        "DARKNET_MENTION_CONTENT",
                        f"...{snippet}...",
                        self.__class__.__name__,
                        evt,
                    )
                    self.notifyListeners(evt3)

            elif isinstance(entry, str):
                evt = SpiderFootEvent(
                    "RANSOMWARE_LEAK_MENTION",
                    f"Target '{eventData}' found in ransomware leak data: {entry}",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)
                count += 1

# End of sfp_ransomwatch class
