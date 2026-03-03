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
        'pause': 1,
    }

    optdescs = {
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

    def queryEmail(self, email):
        """Query XposedOrNot for a specific email address."""
        url = f"https://api.xposedornot.com/v1/check-email/{email}"

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts['_useragent'],
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
        """Query XposedOrNot for a specific domain."""
        url = f"https://api.xposedornot.com/v1/domain-breaches/?domain={domain}"

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts['_useragent'],
        )

        if not res or not res.get('content'):
            self.debug(f"No response from XposedOrNot for domain: {domain}")
            return None

        if res.get('code') == '404':
            self.debug(f"Domain not found in breaches: {domain}")
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

            # XposedOrNot returns breach info in 'breaches' field
            breaches = data.get('breaches') or data.get('ExposedBreaches', {}).get('breaches_details', [])
            if not breaches:
                return

            if isinstance(breaches, list):
                for breach in breaches:
                    if self.checkForStop():
                        return

                    breachName = breach if isinstance(breach, str) else breach.get('breach', breach.get('domain', 'Unknown'))

                    evt = SpiderFootEvent(
                        "EMAILADDR_COMPROMISED",
                        f"{eventData} [{breachName}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                str(data),
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

        elif eventName == "DOMAIN_NAME":
            data = self.queryDomain(eventData)
            if not data:
                return

            breaches = data.get('breaches') or data.get('ExposedBreaches', {}).get('breaches_details', [])
            if not breaches:
                return

            if isinstance(breaches, list):
                for breach in breaches:
                    if self.checkForStop():
                        return

                    breachName = breach if isinstance(breach, str) else breach.get('breach', breach.get('domain', 'Unknown'))

                    evt = SpiderFootEvent(
                        "EMAILADDR_COMPROMISED",
                        f"@{eventData} [{breachName}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                str(data),
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

        import time
        time.sleep(self.opts.get('pause', 1))

# End of sfp_xposedornot class
