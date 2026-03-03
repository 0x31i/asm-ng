# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_xposedornot
# Purpose:     Check XposedOrNot for email and domain breaches.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_xposedornot(SpiderFootPlugin):

    meta = {
        'name': "XposedOrNot",
        'summary': "Check XposedOrNot API for email and domain data breaches.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://xposedornot.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://xposedornot.com/api_doc",
            ],
            'favIcon': "https://xposedornot.com/favicon.ico",
            'logo': "https://xposedornot.com/favicon.ico",
            'description': "XposedOrNot is a free service that lets you check "
            "if your email address or domain has been compromised in a data breach. "
            "It aggregates data from multiple breach sources.",
        }
    }

    opts = {
        'api_key': '',
        'pause': 1,
    }

    optdescs = {
        'api_key': "XposedOrNot API key. Required for domain breach lookups. "
        "Free at https://xposedornot.com/ — email lookups work without a key.",
        'pause': "Seconds to wait between API requests to avoid rate limiting.",
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
        return ["EMAILADDR", "DOMAIN_NAME"]

    def producedEvents(self):
        return [
            "EMAILADDR_COMPROMISED",
            "RAW_RIR_DATA",
        ]

    def _flatten_breaches(self, breaches):
        """Flatten nested breach lists from XposedOrNot API.

        The API returns breaches in various formats:
        - Nested list: [["breach1","breach2",...]]
        - Flat list: ["breach1","breach2",...]
        - List of dicts: [{"breach":"name",...},...]
        """
        if not isinstance(breaches, list):
            return []

        flat = []
        for item in breaches:
            if isinstance(item, list):
                flat.extend(item)
            elif isinstance(item, (str, dict)):
                flat.append(item)
        return flat

    def queryEmail(self, email):
        """Query XposedOrNot for a specific email address."""
        url = f"https://api.xposedornot.com/v1/check-email/{email}"

        headers = {}
        api_key = self.opts.get('api_key', '')
        if api_key:
            headers['x-api-key'] = api_key

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts['_useragent'],
            headers=headers,
        )

        if not res or not res.get('content'):
            self.debug(f"No response from XposedOrNot for email: {email}")
            return None

        if res.get('code') == '404':
            self.debug(f"Email not found in breaches: {email}")
            return None

        if res.get('code') == '429':
            self.error("Rate limited by XposedOrNot API.")
            return None

        if res.get('code') != '200':
            self.debug(f"Unexpected response code: {res.get('code')}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing JSON response: {e}")
            return None

    def queryDomain(self, domain):
        """Query XposedOrNot for a specific domain.

        Requires an API key (x-api-key header). Without one the endpoint
        returns 405 Method Not Allowed.
        """
        api_key = self.opts.get('api_key', '')
        if not api_key:
            self.debug(f"Skipping domain lookup for {domain} — no XposedOrNot API key configured. "
                       "Get a free key at https://xposedornot.com/")
            return None

        url = f"https://api.xposedornot.com/v1/domain-breaches/?domain={domain}"

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts['_useragent'],
            headers={'x-api-key': api_key},
        )

        if not res or not res.get('content'):
            self.debug(f"No response from XposedOrNot for domain: {domain}")
            return None

        if res.get('code') == '404':
            self.debug(f"Domain not found in breaches: {domain}")
            return None

        if res.get('code') in ('401', '403', '405'):
            self.error("XposedOrNot API key invalid or domain endpoint requires auth. "
                       "Check your API key at https://xposedornot.com/")
            return None

        if res.get('code') == '429':
            self.error("Rate limited by XposedOrNot API.")
            return None

        if res.get('code') != '200':
            self.debug(f"Unexpected response code: {res.get('code')}")
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

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            data = self.queryEmail(eventData)
            if not data:
                return

            # XposedOrNot returns breach info in various formats:
            #   {"breaches":[["breach1","breach2",...]],"email":"...","status":"success"}
            #   {"ExposedBreaches":{"breaches_details":[...]}}
            breaches_raw = data.get('breaches') or data.get('ExposedBreaches', {}).get('breaches_details', [])
            breaches = self._flatten_breaches(breaches_raw)

            if not breaches:
                self.debug(f"XposedOrNot: no breaches found for {eventData}")
                return

            breach_names = []
            for breach in breaches:
                if self.checkForStop():
                    return

                if isinstance(breach, str):
                    breachName = breach
                elif isinstance(breach, dict):
                    breachName = breach.get('breach', breach.get('domain', breach.get('name', 'Unknown')))
                else:
                    continue

                breach_names.append(breachName)

                evt = SpiderFootEvent(
                    "EMAILADDR_COMPROMISED",
                    f"{eventData} [Breach: {breachName} | Source: XposedOrNot]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

            # Emit summary RAW_RIR_DATA
            summary = {
                'email': eventData,
                'breach_count': len(breach_names),
                'breaches': breach_names,
                'source': 'XposedOrNot',
                'raw': data,
            }
            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                f"XposedOrNot breach results for {eventData}:\n{json.dumps(summary, indent=2)}",
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

        elif eventName == "DOMAIN_NAME":
            data = self.queryDomain(eventData)
            if not data:
                return

            breaches_raw = data.get('breaches') or data.get('ExposedBreaches', {}).get('breaches_details', [])
            breaches = self._flatten_breaches(breaches_raw)

            if not breaches:
                self.debug(f"XposedOrNot: no breaches found for domain {eventData}")
                return

            breach_names = []
            for breach in breaches:
                if self.checkForStop():
                    return

                if isinstance(breach, str):
                    breachName = breach
                elif isinstance(breach, dict):
                    breachName = breach.get('breach', breach.get('domain', breach.get('name', 'Unknown')))
                else:
                    continue

                breach_names.append(breachName)

                evt = SpiderFootEvent(
                    "EMAILADDR_COMPROMISED",
                    f"@{eventData} [Breach: {breachName} | Source: XposedOrNot]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                f"XposedOrNot domain breach results for {eventData}:\n{json.dumps({'domain': eventData, 'breach_count': len(breach_names), 'breaches': breach_names}, indent=2)}",
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

        import time
        time.sleep(self.opts.get('pause', 1))

# End of sfp_xposedornot class
