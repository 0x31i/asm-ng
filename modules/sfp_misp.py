# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_misp
# Purpose:     Search a MISP instance for threat intelligence matching the
#              scan target. Optionally push findings back to MISP.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

try:
    from pymisp import PyMISP
except ImportError:
    PyMISP = None


class sfp_misp(SpiderFootPlugin):

    meta = {
        'name': "MISP",
        'summary': "Search MISP threat intelligence platform for IOCs matching "
        "the target. Optionally push ASM-NG findings back to MISP.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.misp-project.org/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://www.misp-project.org/documentation/",
                "https://pymisp.readthedocs.io/",
            ],
            'apiKeyInstructions': [
                "Access your MISP instance",
                "Navigate to Administration -> Users -> Your user",
                "Your API key (Auth key) is listed on the user page",
            ],
            'favIcon': "",
            'logo': "",
            'description': "MISP is an open source threat intelligence platform "
            "for sharing, storing, and correlating Indicators of Compromise. "
            "This module searches MISP events for IOCs matching the scan target.",
        }
    }

    opts = {
        'api_key': '',
        'misp_url': '',
        'verify_ssl': True,
        'push_findings': False,
        'max_results': 50,
        'pause': 1,
    }

    optdescs = {
        'api_key': "MISP API key (Auth key).",
        'misp_url': "MISP instance URL (e.g. https://misp.example.com).",
        'verify_ssl': "Verify SSL certificate of the MISP instance.",
        'push_findings': "Push ASM-NG dark web findings back to MISP (creates events).",
        'max_results': "Maximum number of MISP events to process.",
        'pause': "Seconds to wait between API requests.",
    }

    results = None
    errorState = False
    misp = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.misp = None

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "IP_ADDRESS",
            "EMAILADDR",
            "DARKNET_MENTION_URL",
            "RANSOMWARE_LEAK_MENTION",
        ]

    def producedEvents(self):
        return [
            "THREAT_INTEL_FEED_MATCH",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
        ]

    def initMISP(self):
        """Initialize PyMISP connection."""
        if self.misp:
            return True

        if not PyMISP:
            self.error("pymisp library is not installed. Install with: pip install pymisp")
            self.errorState = True
            return False

        if not self.opts.get('api_key') or not self.opts.get('misp_url'):
            self.error("MISP API key and URL must be configured.")
            self.errorState = True
            return False

        try:
            self.misp = PyMISP(
                self.opts['misp_url'],
                self.opts['api_key'],
                ssl=self.opts.get('verify_ssl', True),
            )
            return True
        except Exception as e:
            self.error(f"Failed to connect to MISP: {e}")
            self.errorState = True
            return False

    def searchMISP(self, search_type, value):
        """Search MISP for a specific indicator.

        Args:
            search_type: 'domain', 'ip-src', 'ip-dst', 'email-src', 'url'
            value: The indicator value to search for

        Returns:
            List of matching MISP events or None
        """
        try:
            result = self.misp.search(
                controller='attributes',
                type_attribute=search_type,
                value=value,
                limit=self.opts.get('max_results', 50),
                pythonify=True,
            )
            return result
        except Exception as e:
            self.debug(f"MISP search error for {search_type}={value}: {e}")
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

        if not self.initMISP():
            return

        # Determine MISP search type based on event type
        search_types = []
        if eventName == "DOMAIN_NAME":
            search_types = ['domain', 'hostname']
        elif eventName == "IP_ADDRESS":
            search_types = ['ip-src', 'ip-dst']
        elif eventName == "EMAILADDR":
            search_types = ['email-src', 'email-dst']
        elif eventName == "DARKNET_MENTION_URL":
            search_types = ['url']
        elif eventName == "RANSOMWARE_LEAK_MENTION":
            # For ransomware mentions, push to MISP if enabled
            if self.opts.get('push_findings', False):
                self.pushToMISP(eventData, 'ransomware-leak', event)
            return

        for search_type in search_types:
            if self.checkForStop():
                return

            results = self.searchMISP(search_type, eventData)
            if not results:
                continue

            for attr in results:
                if self.checkForStop():
                    return

                if not hasattr(attr, 'event_id'):
                    continue

                event_info = getattr(attr, 'comment', '') or ''
                event_id = getattr(attr, 'event_id', '')
                category = getattr(attr, 'category', '')

                match_text = (
                    f"MISP match: {eventData} found in MISP event #{event_id}"
                )
                if category:
                    match_text += f" (category: {category})"
                if event_info:
                    match_text += f" — {event_info}"

                evt = SpiderFootEvent(
                    "THREAT_INTEL_FEED_MATCH",
                    match_text,
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

                # Emit specific malicious indicators
                if eventName == "IP_ADDRESS":
                    evt2 = SpiderFootEvent(
                        "MALICIOUS_IPADDR",
                        f"{eventData} [MISP Event #{event_id}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt2)
                elif eventName == "DOMAIN_NAME":
                    evt2 = SpiderFootEvent(
                        "MALICIOUS_INTERNET_NAME",
                        f"{eventData} [MISP Event #{event_id}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt2)

        import time
        time.sleep(self.opts.get('pause', 1))

    def pushToMISP(self, data, tag, source_event):
        """Push a finding back to MISP as a new event."""
        try:
            from pymisp import MISPEvent

            misp_event = MISPEvent()
            misp_event.info = f"ASM-NG finding: {tag}"
            misp_event.distribution = 0  # Your organization only
            misp_event.threat_level_id = 2  # Medium
            misp_event.analysis = 1  # Ongoing

            misp_event.add_attribute('comment', data)
            misp_event.add_tag(f'asm-ng:{tag}')

            self.misp.add_event(misp_event)
            self.debug(f"Pushed finding to MISP: {tag}")
        except Exception as e:
            self.debug(f"Failed to push to MISP: {e}")

# End of sfp_misp class
