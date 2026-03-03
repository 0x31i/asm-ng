# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_snusbase
# Purpose:     Search Snusbase API for breached credentials associated with
#              the target.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_snusbase(SpiderFootPlugin):

    meta = {
        'name': "Snusbase",
        'summary': "Search Snusbase breach database for compromised credentials.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://snusbase.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://docs.snusbase.com/",
            ],
            'apiKeyInstructions': [
                "Visit https://snusbase.com/",
                "Register an account",
                "Purchase an API subscription",
                "Your API key will be available in your account settings",
            ],
            'favIcon': "https://snusbase.com/favicon.ico",
            'logo': "https://snusbase.com/favicon.ico",
            'description': "Snusbase is a breach database search engine that lets you "
            "search through billions of compromised records to find leaked "
            "credentials, passwords, hashes, and other data.",
        }
    }

    opts = {
        'api_key': '',
        'pause': 1,
    }

    optdescs = {
        'api_key': "Snusbase API key.",
        'pause': "Seconds to wait between API requests.",
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
        return ["EMAILADDR", "DOMAIN_NAME", "USERNAME"]

    def producedEvents(self):
        return [
            "EMAILADDR_COMPROMISED",
            "PASSWORD_COMPROMISED",
            "HASH_COMPROMISED",
        ]

    def query(self, search_type, search_term):
        """Query Snusbase API.

        Args:
            search_type: One of 'email', 'domain', 'username'
            search_term: The value to search for
        """
        url = "https://api-experimental.snusbase.com/data/search"

        headers = {
            'Auth': self.opts['api_key'],
            'Content-Type': 'application/json',
        }

        payload = json.dumps({
            'terms': [search_term],
            'types': [search_type],
            'wildcard': False,
        })

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts['_useragent'],
            headers=headers,
            postData=payload,
        )

        if not res or not res.get('content'):
            self.debug(f"No response from Snusbase for: {search_term}")
            return None

        if res.get('code') == '401':
            self.error("Invalid Snusbase API key.")
            self.errorState = True
            return None

        if res.get('code') == '429':
            self.error("Rate limited by Snusbase API.")
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

        if self.opts['api_key'] == '':
            self.error("You enabled sfp_snusbase but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Determine search type
        if eventName == "EMAILADDR":
            search_type = "email"
        elif eventName == "DOMAIN_NAME":
            search_type = "domain"
        elif eventName == "USERNAME":
            search_type = "username"
        else:
            return

        data = self.query(search_type, eventData)
        if not data:
            return

        # Snusbase returns results grouped by database
        results_data = data.get('results', {})
        if not results_data:
            return

        seen = set()

        for db_name, entries in results_data.items():
            if not isinstance(entries, list):
                continue

            for entry in entries:
                if self.checkForStop():
                    return

                if not isinstance(entry, dict):
                    continue

                email = entry.get('email', '')
                password = entry.get('password', '')
                password_hash = entry.get('hash', '')
                username = entry.get('username', '')

                identifier = email or username or eventData
                key = f"{identifier}:{db_name}"

                if key in seen:
                    continue
                seen.add(key)

                if email:
                    evt = SpiderFootEvent(
                        "EMAILADDR_COMPROMISED",
                        f"{email} [{db_name}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

                if password:
                    evt = SpiderFootEvent(
                        "PASSWORD_COMPROMISED",
                        f"{identifier}:{password} [{db_name}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

                if password_hash:
                    evt = SpiderFootEvent(
                        "HASH_COMPROMISED",
                        f"{identifier}:{password_hash} [{db_name}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

        import time
        time.sleep(self.opts.get('pause', 1))

# End of sfp_snusbase class
