# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_brand_darkweb
# Purpose:     Generate domain permutations and search the dark web for brand
#              impersonation targeting the scan target.
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


class sfp_brand_darkweb(SpiderFootPlugin):

    meta = {
        'name': "Dark Web Brand Monitor",
        'summary': "Search dark web for brand impersonation and domain spoofing "
        "targeting the scan target.",
        'flags': ["tor"],
        'useCases': ["Investigate", "Dark Web Exposure"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://ahmia.fi/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'favIcon': "",
            'logo': "",
            'description': "Generates domain permutations (typosquats, homoglyphs, "
            "common variations) and searches dark web search engines for mentions. "
            "Helps identify brand impersonation on .onion sites.",
        }
    }

    opts = {
        'max_permutations': 20,
        'search_ahmia': True,
    }

    optdescs = {
        'max_permutations': "Maximum number of domain permutations to search for.",
        'search_ahmia': "Use Ahmia.fi clearnet portal for dark web searches.",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "COMPANY_NAME"]

    def producedEvents(self):
        return [
            "DARKWEB_BRAND_MENTION",
            "DARKNET_MENTION_URL",
            "ONION_SERVICE_DETECTED",
        ]

    def generatePermutations(self, domain):
        """Generate common domain permutations for brand monitoring."""
        perms = set()
        base = domain.split('.')[0] if '.' in domain else domain

        # Common typosquats
        for i in range(len(base)):
            # Character omission
            perms.add(base[:i] + base[i + 1:])
            # Character duplication
            perms.add(base[:i] + base[i] + base[i:])

        # Common substitutions
        subs = {
            'o': '0', '0': 'o',
            'l': '1', '1': 'l',
            'i': '1',
            'e': '3', '3': 'e',
            'a': '4', '4': 'a',
            's': '5', '5': 's',
            'g': '9', '9': 'g',
        }
        for i, c in enumerate(base):
            if c.lower() in subs:
                perms.add(base[:i] + subs[c.lower()] + base[i + 1:])

        # Hyphenation
        for i in range(1, len(base)):
            perms.add(base[:i] + '-' + base[i:])

        # Common prefixes/suffixes for phishing
        for prefix in ['login-', 'secure-', 'my', 'auth-', 'verify-']:
            perms.add(prefix + base)
        for suffix in ['-login', '-secure', '-verify', '-auth', '-support']:
            perms.add(base + suffix)

        # Remove the original
        perms.discard(base)

        return list(perms)[:self.opts.get('max_permutations', 20)]

    def searchAhmia(self, query):
        """Search Ahmia.fi clearnet portal for darknet mentions."""
        params = urllib.parse.urlencode({'q': query})
        url = f"https://ahmia.fi/search/?{params}"

        data = self.sf.fetchUrl(
            url,
            useragent=self.opts['_useragent'],
            timeout=15,
        )

        if not data or not data.get('content'):
            return []

        # Extract .onion links from results
        links = re.findall(
            r'redirect_url=(.[^"]+)"',
            data['content'],
            re.IGNORECASE | re.DOTALL,
        )

        return links

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Generate search terms
        search_terms = [eventData]

        if eventName == "DOMAIN_NAME":
            perms = self.generatePermutations(eventData)
            search_terms.extend(perms)

        for term in search_terms:
            if self.checkForStop():
                return

            if term in self.results and term != eventData:
                continue
            self.results[term] = True

            if not self.opts.get('search_ahmia', True):
                continue

            links = self.searchAhmia(term)

            if not links:
                continue

            for link in links:
                if self.checkForStop():
                    return

                if link in self.results:
                    continue
                self.results[link] = True

                if not self.sf.urlFQDN(link).endswith(".onion"):
                    continue

                # This is a brand mention on the dark web
                is_permutation = (term != eventData)
                mention_type = "brand impersonation" if is_permutation else "brand mention"

                evt = SpiderFootEvent(
                    "DARKWEB_BRAND_MENTION",
                    f"Dark web {mention_type}: '{term}' found at {link}",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

                evt2 = SpiderFootEvent(
                    "DARKNET_MENTION_URL",
                    link,
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)

                # Detect .onion service
                onion_match = re.search(r'([a-z2-7]{56}\.onion)', link, re.IGNORECASE)
                if onion_match:
                    onion_addr = onion_match.group(1)
                    if onion_addr not in self.results:
                        self.results[onion_addr] = True
                        evt3 = SpiderFootEvent(
                            "ONION_SERVICE_DETECTED",
                            onion_addr,
                            self.__class__.__name__,
                            event,
                        )
                        self.notifyListeners(evt3)

# End of sfp_brand_darkweb class
