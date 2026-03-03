# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_stealerlog_check
# Purpose:     Check Hudson Rock Cavalier API for infostealer log matches
#              against the target domain or email.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_stealerlog_check(SpiderFootPlugin):

    meta = {
        'name': "Stealer Log Check (Hudson Rock)",
        'summary': "Check Hudson Rock Cavalier OSINT API for infostealer log credential matches.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://cavalier.hudsonrock.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://cavalier.hudsonrock.com/docs",
            ],
            'favIcon': "",
            'logo': "",
            'description': "Hudson Rock's Cavalier provides free OSINT access to "
            "infostealer log data, identifying credentials stolen by malware like "
            "Raccoon, RedLine, Vidar, and other infostealers.",
        }
    }

    opts = {
        'pause': 2,
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
        return ["DOMAIN_NAME", "EMAILADDR"]

    def producedEvents(self):
        return [
            "STEALER_LOG_MATCH",
            "EMAILADDR_COMPROMISED",
            "PASSWORD_COMPROMISED",
            "RAW_RIR_DATA",
        ]

    def queryDomain(self, domain):
        """Query Hudson Rock for a domain."""
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts['_useragent'],
        )

        if not res or not res.get('content'):
            self.debug(f"No response from Hudson Rock for domain: {domain}")
            return None

        if res.get('code') == '429':
            self.error("Rate limited by Hudson Rock API.")
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
            # For email, extract the domain and search
            domain = eventData.split('@')[-1] if '@' in eventData else eventData
            data = self.queryDomain(domain)
        else:
            data = self.queryDomain(eventData)

        if not data:
            return

        stealers = data.get('stealers', [])
        if not stealers:
            return

        for entry in stealers:
            if self.checkForStop():
                return

            email = entry.get('email', entry.get('username', ''))
            password = entry.get('password', '')
            stealer_type = entry.get('stealer_type', entry.get('malware_family', 'Unknown'))
            computer_name = entry.get('computer_name', '')
            date_compromised = entry.get('date_compromised', entry.get('date', ''))
            url = entry.get('url', '')

            # If searching by email, only report matches for that email
            if eventName == "EMAILADDR" and email and email.lower() != eventData.lower():
                continue

            mention = f"Stealer log match: {email or eventData}"
            if stealer_type:
                mention += f" (malware: {stealer_type})"
            if date_compromised:
                mention += f" (date: {date_compromised})"
            if computer_name:
                mention += f" (host: {computer_name})"
            if url:
                mention += f" (source: {url})"

            evt = SpiderFootEvent(
                "STEALER_LOG_MATCH",
                mention,
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

            if email:
                evt2 = SpiderFootEvent(
                    "EMAILADDR_COMPROMISED",
                    f"{email} [Infostealer - {stealer_type}]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)

            if password:
                evt3 = SpiderFootEvent(
                    "PASSWORD_COMPROMISED",
                    f"{email}:{password} [Infostealer - {stealer_type}]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt3)

        # Emit raw data
        evt = SpiderFootEvent(
            "RAW_RIR_DATA",
            str(data),
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt)

        import time
        time.sleep(self.opts.get('pause', 2))

# End of sfp_stealerlog_check class
