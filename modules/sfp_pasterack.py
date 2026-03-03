# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_pasterack
# Purpose:     Monitor multiple paste sites beyond PasteBin — GitHub Gists,
#              Rentry, dpaste, Paste.ee, JustPaste — using Google CSE.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_pasterack(SpiderFootPlugin):

    meta = {
        'name': "PasteRack",
        'summary': "Search multiple paste sites (GitHub Gists, Rentry, dpaste, Paste.ee, JustPaste) "
        "via Google CSE for target mentions.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://gist.github.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developers.google.com/custom-search/v1/introduction",
            ],
            'apiKeyInstructions': [
                "Visit https://developers.google.com/custom-search/v1/introduction",
                "Register a free Google account",
                "Click on 'Get A Key'",
                "Connect a Project",
                "The API Key will be listed under 'YOUR API KEY'",
            ],
            'favIcon': "",
            'logo': "",
            'description': "Searches multiple paste sites for mentions of target "
            "domains, hostnames, and email addresses. Uses Google Custom Search "
            "Engine to find content across GitHub Gists, Rentry, dpaste, Paste.ee, "
            "and JustPaste.",
        }
    }

    opts = {
        "api_key": "",
        "cse_id": "013611106330597893267:tfgl3wxdtbp",
    }

    optdescs = {
        "api_key": "Google API Key for paste site search.",
        "cse_id": "Google Custom Search Engine ID.",
    }

    domains = {
        'gist': "gist.github.com",
        'rentry': "rentry.co",
        'dpaste': "dpaste.org",
        'pasteee': "paste.ee",
        'justpaste': "justpaste.it",
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
        return ["DOMAIN_NAME", "INTERNET_NAME", "EMAILADDR"]

    def producedEvents(self):
        return ["LEAKSITE_URL", "LEAKSITE_CONTENT"]

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set a Google API key!")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        for dom in list(self.domains.keys()):
            if self.checkForStop():
                return

            target = self.domains[dom]
            res = self.sf.googleIterate(
                searchString=f'+site:{target} "{eventData}"',
                opts={
                    "timeout": self.opts["_fetchtimeout"],
                    "useragent": self.opts["_useragent"],
                    "api_key": self.opts["api_key"],
                    "cse_id": self.opts["cse_id"],
                },
            )

            if res is None:
                continue

            urls = res["urls"]
            new_links = list(set(urls) - set(self.results.keys()))

            for link in new_links:
                self.results[link] = True

            relevant_links = [
                link for link in new_links if SpiderFootHelpers.urlBaseUrl(link).endswith(target)
            ]

            for link in relevant_links:
                self.debug("Found a link: " + link)

                if self.checkForStop():
                    return

                res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.debug(f"Ignoring {link} as no data returned")
                    continue

                if re.search(
                    r"[^a-zA-Z\-\_0-9]" +
                        re.escape(eventData) + r"[^a-zA-Z\-\_0-9]",
                    res['content'],
                    re.IGNORECASE
                ) is None:
                    continue

                evt1 = SpiderFootEvent(
                    "LEAKSITE_URL", link, self.__class__.__name__, event)
                self.notifyListeners(evt1)

                evt2 = SpiderFootEvent(
                    "LEAKSITE_CONTENT", res['content'], self.__class__.__name__, evt1)
                self.notifyListeners(evt2)

# End of sfp_pasterack class
