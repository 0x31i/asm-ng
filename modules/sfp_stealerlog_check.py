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

    def _fetchApi(self, url):
        """Fetch a Hudson Rock API endpoint and return parsed JSON."""
        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts['_useragent'],
        )

        if not res or not res.get('content'):
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

    def _handleEmail(self, email, event):
        """Handle EMAILADDR events using the search-by-email endpoint.

        Response: {"stealers":[{...},...], "total_corporate_services":N, ...}
        """
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
        data = self._fetchApi(url)

        if not data:
            return

        stealers = data.get('stealers', [])
        if not stealers:
            self.debug(f"Hudson Rock: no stealer logs found for email {email}")
            return

        for entry in stealers:
            if self.checkForStop():
                return

            if not isinstance(entry, dict):
                continue

            stealer_type = entry.get('stealer_type', entry.get('malware_family', 'Unknown'))
            computer_name = entry.get('computer_name', '')
            date_compromised = entry.get('date_compromised', entry.get('date', ''))
            operating_system = entry.get('operating_system', '')
            ip = entry.get('ip', '')
            antiviruses = entry.get('antiviruses', '')
            log_file_name = entry.get('log_file_name', '')

            # Build detailed mention
            parts = [f"Email: {email}"]
            parts.append(f"Malware: {stealer_type}")
            if date_compromised:
                parts.append(f"Date: {date_compromised}")
            if computer_name:
                parts.append(f"Host: {computer_name}")
            if operating_system:
                parts.append(f"OS: {operating_system}")
            if ip:
                parts.append(f"IP: {ip}")
            if antiviruses:
                parts.append(f"AV: {antiviruses}")
            parts.append("Source: Hudson Rock Cavalier")

            mention = " | ".join(parts)

            evt = SpiderFootEvent(
                "STEALER_LOG_MATCH",
                mention,
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

            evt2 = SpiderFootEvent(
                "EMAILADDR_COMPROMISED",
                f"{email} [Infostealer: {stealer_type} | Source: Hudson Rock]",
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt2)

        # Emit raw data
        evt = SpiderFootEvent(
            "RAW_RIR_DATA",
            f"Hudson Rock stealer log results for {email}:\n{json.dumps(data, indent=2, default=str)[:5000]}",
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt)

    def _handleDomain(self, domain, event):
        """Handle DOMAIN_NAME events using the search-by-domain endpoint.

        Response: {"total":N, "employees":N, "users":N, "third_parties":N,
                   "stealerFamilies":{...}, "data":{"employees_urls":[...],...}, ...}
        """
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"
        data = self._fetchApi(url)

        if not data:
            return

        total = data.get('total', 0)
        employees = data.get('employees', 0)
        users = data.get('users', 0)
        third_parties = data.get('third_parties', 0)

        if total == 0 and employees == 0 and users == 0:
            self.debug(f"Hudson Rock: no stealer logs found for domain {domain}")
            return

        # Build stealer family summary
        stealer_families = data.get('stealerFamilies', {})
        family_str = ', '.join(f"{k}: {v}" for k, v in stealer_families.items()) if stealer_families else 'Unknown'

        last_employee = data.get('last_employee_compromised', '')
        last_user = data.get('last_user_compromised', '')

        # Emit domain-level stealer log match
        parts = [f"Domain: {domain}"]
        parts.append(f"Total compromised: {total}")
        if employees:
            parts.append(f"Employees: {employees}")
        if users:
            parts.append(f"Users: {users}")
        if third_parties:
            parts.append(f"Third-parties: {third_parties}")
        parts.append(f"Stealer families: {family_str}")
        if last_employee:
            parts.append(f"Last employee compromise: {last_employee}")
        if last_user:
            parts.append(f"Last user compromise: {last_user}")
        parts.append("Source: Hudson Rock Cavalier")

        mention = " | ".join(parts)

        evt = SpiderFootEvent(
            "STEALER_LOG_MATCH",
            mention,
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt)

        # Emit raw data with summary
        summary = {
            'domain': domain,
            'total': total,
            'employees': employees,
            'users': users,
            'third_parties': third_parties,
            'stealer_families': stealer_families,
            'last_employee_compromised': last_employee,
            'last_user_compromised': last_user,
            'source': 'Hudson Rock Cavalier',
        }
        evt2 = SpiderFootEvent(
            "RAW_RIR_DATA",
            f"Hudson Rock domain summary for {domain}:\n{json.dumps(summary, indent=2, default=str)}",
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt2)

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
            self._handleEmail(eventData, event)
        elif eventName == "DOMAIN_NAME":
            self._handleDomain(eventData, event)

        import time
        time.sleep(self.opts.get('pause', 2))

# End of sfp_stealerlog_check class
