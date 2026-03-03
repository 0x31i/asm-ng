# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_breachparse_ng
# Purpose:     Query the bp-ng breach credential API for compromised credentials
#              associated with the target domain or email.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-03
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_breachparse_ng(SpiderFootPlugin):

    meta = {
        'name': "BreachParse-NG",
        'summary': "Search your private bp-ng breach credential database for compromised "
        "credentials. Requires a running bp-ng API instance.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://github.com/0x31i/bp-ng",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'favIcon': "",
            'logo': "",
            'description': "bp-ng is a self-hosted breach credential search engine built on "
            "PostgreSQL. It indexes breach compilations (Collection 1-5, COMB, etc.) "
            "and serves fast lookups via a REST API. Free, private, and unlimited.",
        }
    }

    opts = {
        'api_url': 'http://localhost:8800',
        'api_key': '',
        'max_results': 500,
        'emit_passwords': False,
        'pause': 0,
    }

    optdescs = {
        'api_url': "URL of your bp-ng API instance (e.g., http://10.0.0.5:8800 or Tailscale address).",
        'api_key': "bp-ng API key (optional if auth is disabled on your instance).",
        'max_results': "Maximum credential results to process per query.",
        'emit_passwords': "Emit plaintext passwords as PASSWORD_COMPROMISED events. "
        "WARNING: Passwords will be stored in the ASM-NG database. "
        "Disable this for compliance-sensitive environments.",
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
        return ["EMAILADDR", "DOMAIN_NAME"]

    def producedEvents(self):
        return [
            "EMAILADDR_COMPROMISED",
            "PASSWORD_COMPROMISED",
            "HASH_COMPROMISED",
            "RAW_RIR_DATA",
        ]

    def _query(self, endpoint: str, payload: dict) -> dict | None:
        """Query the bp-ng API."""
        url = self.opts['api_url'].rstrip('/') + endpoint

        headers = {'Content-Type': 'application/json'}
        api_key = self.opts.get('api_key', '')
        if api_key:
            headers['X-API-Key'] = api_key

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts['_useragent'],
            headers=headers,
            postData=json.dumps(payload),
        )

        if not res or not res.get('content'):
            self.debug(f"No response from bp-ng API at {url}")
            return None

        if res.get('code') == '401' or res.get('code') == '403':
            self.error("bp-ng API authentication failed. Check your API key.")
            self.errorState = True
            return None

        if res.get('code') == '429':
            self.error("bp-ng API rate limit exceeded.")
            return None

        if res.get('code') != '200':
            self.debug(f"bp-ng API returned code {res.get('code')}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing bp-ng response: {e}")
            return None

    def _handleDomain(self, domain: str, event):
        """Search bp-ng for all breached credentials under a domain."""
        # First get summary
        summary = self._query("/api/v1/summary/domain", {"domain": domain})
        if summary and summary.get("total_records", 0) > 0:
            sources = summary.get("sources", [])
            source_str = ", ".join(sources[:10]) if sources else "unknown"

            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                f"bp-ng breach summary for {domain}:\n"
                f"  Total records: {summary.get('total_records', 0):,}\n"
                f"  Unique emails: {summary.get('unique_emails', 0):,}\n"
                f"  Passwords: {summary.get('passwords', 0):,}\n"
                f"  Hashes: {summary.get('hashes', 0):,}\n"
                f"  Sources: {source_str}",
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

        # Get actual results
        data = self._query("/api/v1/search/domain", {
            "domain": domain,
            "limit": self.opts.get('max_results', 500),
        })

        if not data or not data.get("results"):
            self.debug(f"bp-ng: no breach data for domain {domain}")
            return

        self._processResults(data["results"], event)

    def _handleEmail(self, email: str, event):
        """Search bp-ng for breached credentials for a specific email."""
        data = self._query("/api/v1/search/email", {
            "email": email,
            "limit": self.opts.get('max_results', 500),
        })

        if not data or not data.get("results"):
            self.debug(f"bp-ng: no breach data for email {email}")
            return

        self._processResults(data["results"], event)

    def _processResults(self, results: list, event):
        """Process breach results and emit SpiderFoot events."""
        seen_emails = set()

        for entry in results:
            if self.checkForStop():
                return

            email = entry.get("email", "")
            credential = entry.get("credential", "")
            cred_type = entry.get("type", "unknown")
            source = entry.get("source", "unknown")

            if not email:
                continue

            # Emit EMAILADDR_COMPROMISED (once per email per source)
            dedup_key = f"{email}:{source}"
            if dedup_key not in seen_emails:
                seen_emails.add(dedup_key)
                evt = SpiderFootEvent(
                    "EMAILADDR_COMPROMISED",
                    f"{email} [Breach: {source} | Source: bp-ng]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

            # Emit credential events
            if credential:
                if cred_type == "hash":
                    hash_len = len(credential)
                    hash_type = {32: 'MD5', 40: 'SHA1', 64: 'SHA256', 128: 'SHA512'}.get(hash_len, 'hash')
                    evt = SpiderFootEvent(
                        "HASH_COMPROMISED",
                        f"{email}:{credential} [Breach: {source} | Type: {hash_type} | Source: bp-ng]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

                elif cred_type == "password" and self.opts.get('emit_passwords', False):
                    evt = SpiderFootEvent(
                        "PASSWORD_COMPROMISED",
                        f"{email}:{credential} [Breach: {source} | Source: bp-ng]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

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

        # Check if API is reachable on first call
        if not self.results.get("_api_checked"):
            self.results["_api_checked"] = True
            health = self._query("/api/v1/health", None)
            if health is None:
                # Try GET instead of POST for health endpoint
                url = self.opts['api_url'].rstrip('/') + '/api/v1/health'
                res = self.sf.fetchUrl(url, timeout=10, useragent=self.opts['_useragent'])
                if not res or res.get('code') != '200':
                    self.error(
                        f"Cannot reach bp-ng API at {self.opts['api_url']}. "
                        "Is the bp-ng server running? Check api_url in module settings."
                    )
                    self.errorState = True
                    return

        if eventName == "DOMAIN_NAME":
            self._handleDomain(eventData, event)
        elif eventName == "EMAILADDR":
            self._handleEmail(eventData, event)

        if self.opts.get('pause', 0) > 0:
            import time
            time.sleep(self.opts['pause'])

# End of sfp_breachparse_ng class
