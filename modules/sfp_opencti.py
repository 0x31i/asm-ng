# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_opencti
# Purpose:     Search OpenCTI threat intelligence platform for IOCs matching
#              the scan target via its GraphQL API.
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_opencti(SpiderFootPlugin):

    meta = {
        'name': "OpenCTI",
        'summary': "Search OpenCTI threat intelligence platform for IOCs "
        "matching the target via GraphQL API.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive", "Dark Web Exposure"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.opencti.io/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://docs.opencti.io/latest/",
                "https://docs.opencti.io/latest/deployment/connectors/",
            ],
            'apiKeyInstructions': [
                "Access your OpenCTI instance",
                "Navigate to Settings -> Users -> Your user -> API access",
                "Generate or copy your API token",
            ],
            'favIcon': "",
            'logo': "",
            'description': "OpenCTI is an open source platform allowing organizations "
            "to manage their cyber threat intelligence knowledge and observables. "
            "This module searches OpenCTI for indicators matching the scan target.",
        }
    }

    opts = {
        'api_key': '',
        'opencti_url': '',
        'verify_ssl': True,
        'max_results': 50,
        'pause': 1,
    }

    optdescs = {
        'api_key': "OpenCTI API token (Bearer token).",
        'opencti_url': "OpenCTI instance URL (e.g. https://opencti.example.com).",
        'verify_ssl': "Verify SSL certificate of the OpenCTI instance.",
        'max_results': "Maximum number of results to process.",
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
        return ["DOMAIN_NAME", "IP_ADDRESS", "EMAILADDR"]

    def producedEvents(self):
        return [
            "THREAT_INTEL_FEED_MATCH",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
        ]

    def queryGraphQL(self, query, variables=None):
        """Execute a GraphQL query against OpenCTI."""
        url = f"{self.opts['opencti_url'].rstrip('/')}/graphql"

        headers = {
            'Authorization': f"Bearer {self.opts['api_key']}",
            'Content-Type': 'application/json',
        }

        payload = json.dumps({
            'query': query,
            'variables': variables or {},
        })

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts['_useragent'],
            headers=headers,
            postData=payload,
        )

        if not res or not res.get('content'):
            self.debug("No response from OpenCTI")
            return None

        if res.get('code') == '401' or res.get('code') == '403':
            self.error("Invalid OpenCTI API credentials.")
            self.errorState = True
            return None

        if res.get('code') != '200':
            self.debug(f"Unexpected response code from OpenCTI: {res.get('code')}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing JSON response: {e}")
            return None

    def searchIndicators(self, value, indicator_type=None):
        """Search OpenCTI for indicators matching a value."""
        query = """
        query SearchStixCyberObservables($search: String, $first: Int) {
            stixCyberObservables(search: $search, first: $first) {
                edges {
                    node {
                        id
                        entity_type
                        observable_value
                        created_at
                        objectLabel {
                            edges {
                                node {
                                    value
                                    color
                                }
                            }
                        }
                        indicators {
                            edges {
                                node {
                                    id
                                    name
                                    description
                                    pattern
                                    valid_from
                                }
                            }
                        }
                    }
                }
            }
        }
        """

        variables = {
            'search': value,
            'first': self.opts.get('max_results', 50),
        }

        return self.queryGraphQL(query, variables)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if not self.opts.get('api_key') or not self.opts.get('opencti_url'):
            self.error("OpenCTI API key and URL must be configured.")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.searchIndicators(eventData)
        if not data:
            return

        observables = data.get('data', {}).get('stixCyberObservables', {}).get('edges', [])
        if not observables:
            return

        for edge in observables:
            if self.checkForStop():
                return

            node = edge.get('node', {})
            if not node:
                continue

            obs_value = node.get('observable_value', '')
            entity_type = node.get('entity_type', '')
            obs_id = node.get('id', '')

            # Get labels/tags
            labels = []
            for label_edge in node.get('objectLabel', {}).get('edges', []):
                label_val = label_edge.get('node', {}).get('value', '')
                if label_val:
                    labels.append(label_val)

            # Get associated indicators
            indicators = node.get('indicators', {}).get('edges', [])

            label_str = ', '.join(labels) if labels else 'No labels'

            match_text = (
                f"OpenCTI match: {eventData} found as {entity_type} "
                f"observable (labels: {label_str})"
            )

            if indicators:
                ind_names = [
                    ind.get('node', {}).get('name', 'Unknown')
                    for ind in indicators[:5]
                ]
                match_text += f" — linked to indicators: {', '.join(ind_names)}"

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
                    f"{eventData} [OpenCTI: {label_str}]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)
            elif eventName == "DOMAIN_NAME":
                evt2 = SpiderFootEvent(
                    "MALICIOUS_INTERNET_NAME",
                    f"{eventData} [OpenCTI: {label_str}]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)

        import time
        time.sleep(self.opts.get('pause', 1))

# End of sfp_opencti class
