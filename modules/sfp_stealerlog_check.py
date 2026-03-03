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
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_stealerlog_check(SpiderFootPlugin):

    meta = {
        'name': "Stealer Log Check (Hudson Rock)",
        'summary': "Check Hudson Rock Cavalier OSINT API for infostealer log "
        "credential matches. For domains: reports compromised employee/user "
        "counts, exposed internal systems (SSO, VPN, ADFS), malware family "
        "breakdown, password strength posture, antivirus gaps, third-party "
        "supply chain exposure, and compromise timeline. For emails: reports "
        "per-infection detail (malware, date, host, IP).",
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
        'max_urls': 10,
        'max_third_parties': 10,
    }

    optdescs = {
        'pause': "Seconds to wait between API requests to avoid rate limiting.",
        'max_urls': "Maximum number of compromised URLs to include in the report.",
        'max_third_parties': "Maximum number of third-party domains to include.",
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

    # ------------------------------------------------------------------
    # Email handler — per-infection detail (unchanged, already good)
    # ------------------------------------------------------------------

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
            f"Hudson Rock stealer log results for {email}:\n"
            f"{json.dumps(data, indent=2, default=str)[:5000]}",
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt)

    # ------------------------------------------------------------------
    # Domain handler — full intelligence extraction
    # ------------------------------------------------------------------

    def _handleDomain(self, domain, event):
        """Handle DOMAIN_NAME events using the search-by-domain endpoint.

        The free OSINT API returns rich aggregate intelligence:
        - Employee/user/third-party compromise counts
        - Top compromised URLs (SSO, VPN, ADFS portals)
        - Stealer malware family breakdown
        - Password strength distribution
        - Antivirus coverage gaps
        - Third-party supply chain exposure
        - Compromise timeline
        """
        url = (
            "https://cavalier.hudsonrock.com/api/json/v2/"
            f"osint-tools/search-by-domain?domain={domain}"
        )
        data = self._fetchApi(url)

        if not data:
            return

        total = data.get('total', 0)
        employees = data.get('employees', 0)
        users = data.get('users', 0)

        if total == 0 and employees == 0 and users == 0:
            self.debug(f"Hudson Rock: no stealer logs found for domain {domain}")
            return

        third_parties = data.get('third_parties', 0)

        # --- Build actionable report ---
        report_lines = []

        # Headline
        parts = []
        if employees:
            parts.append(f"{employees} employee")
        if users:
            parts.append(f"{users} user")
        headline = " and ".join(parts) + " credentials found in infostealer logs"
        report_lines.append(f"{domain}: {headline}")

        # Exposed systems (top compromised URLs)
        exposed = self._extract_exposed_urls(data)
        if exposed:
            report_lines.append(
                "EXPOSED SYSTEMS: " + ", ".join(exposed)
            )

        # Malware families
        families = self._extract_families(data)
        if families:
            report_lines.append("MALWARE: " + ", ".join(families))

        # Password strength
        pw_summary = self._extract_password_strength(data)
        if pw_summary:
            report_lines.append("PASSWORD STRENGTH: " + pw_summary)

        # Antivirus gaps
        av_summary = self._extract_av_gaps(data)
        if av_summary:
            report_lines.append("ANTIVIRUS GAPS: " + av_summary)

        # Third-party supply chain exposure
        tp_summary = self._extract_third_parties(data)
        if tp_summary:
            report_lines.append("THIRD-PARTY EXPOSURE: " + ", ".join(tp_summary))

        # Compromise timeline
        timeline = self._extract_timeline(data)
        if timeline:
            report_lines.append("LAST COMPROMISE: " + timeline)

        # Application keywords
        apps = data.get('applications', [])
        if apps:
            app_names = [a.get('keyword', '') for a in apps if a.get('keyword')]
            if app_names:
                report_lines.append(
                    "SERVICES DETECTED: " + ", ".join(app_names[:15])
                )

        report_lines.append("Source: Hudson Rock Cavalier")

        report = "\n".join(report_lines)

        # Emit as STEALER_LOG_MATCH — this is now actionable intelligence
        evt = SpiderFootEvent(
            "STEALER_LOG_MATCH",
            report,
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt)

        # Emit full raw data for deep analysis
        evt2 = SpiderFootEvent(
            "RAW_RIR_DATA",
            f"Hudson Rock full domain intelligence for {domain}:\n"
            f"{json.dumps(data, indent=2, default=str)[:10000]}",
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt2)

    def _extract_exposed_urls(self, data):
        """Extract top compromised URLs showing exposed internal systems."""
        max_urls = self.opts.get('max_urls', 10)
        exposed = []

        # Try the structured data first (employees + clients)
        all_urls = []
        data_block = data.get('data', {})
        if isinstance(data_block, dict):
            for entry in data_block.get('employees_urls', []):
                if isinstance(entry, dict) and entry.get('url'):
                    url = entry['url']
                    # Skip heavily redacted URLs (asterisks)
                    if '****' not in url:
                        all_urls.append((entry.get('occurrence', 0), 'emp', url))

            for entry in data_block.get('clients_urls', []):
                if isinstance(entry, dict) and entry.get('url'):
                    url = entry['url']
                    if '****' not in url:
                        all_urls.append((entry.get('occurrence', 0), 'user', url))

        # Sort by occurrence count (highest first)
        all_urls.sort(key=lambda x: x[0], reverse=True)

        for count, src_type, url in all_urls[:max_urls]:
            # Shorten URL for readability
            short = url.replace('https://', '').replace('http://', '')
            if len(short) > 60:
                short = short[:57] + '...'
            exposed.append(f"{short} ({count}x)")

        return exposed

    def _extract_families(self, data):
        """Extract stealer malware family breakdown."""
        families_raw = data.get('stealerFamilies', {})
        if not families_raw or not isinstance(families_raw, dict):
            return []

        # Filter out the 'total' key and sort by count
        families = [
            (name, count)
            for name, count in families_raw.items()
            if name != 'total' and isinstance(count, (int, float)) and count > 0
        ]
        families.sort(key=lambda x: x[1], reverse=True)

        return [f"{name} ({count})" for name, count in families[:8]]

    def _extract_password_strength(self, data):
        """Extract password strength distribution."""
        parts = []

        for label, key in [("Employees", "employeePasswords"),
                           ("Users", "userPasswords")]:
            pw_data = data.get(key, {})
            if not isinstance(pw_data, dict) or not pw_data.get('has_stats'):
                continue

            total_pass = pw_data.get('totalPass', 0)
            if total_pass == 0:
                continue

            too_weak = pw_data.get('too_weak', {})
            weak = pw_data.get('weak', {})
            strong = pw_data.get('strong', {})

            weak_pct = (too_weak.get('perc', 0) or 0) + (weak.get('perc', 0) or 0)
            strong_pct = strong.get('perc', 0) or 0

            parts.append(
                f"{label}: {weak_pct:.0f}% weak/very-weak, "
                f"{strong_pct:.0f}% strong ({total_pass} analyzed)"
            )

        return " | ".join(parts) if parts else ""

    def _extract_av_gaps(self, data):
        """Extract antivirus coverage gaps."""
        av_data = data.get('antiviruses', {})
        if not isinstance(av_data, dict):
            return ""

        total = av_data.get('total', 0)
        if total == 0:
            return ""

        not_found = av_data.get('not_found', 0)
        free_av = av_data.get('free', 0)

        parts = []
        if not_found:
            parts.append(f"{not_found:.0f}% had no AV detected")
        if free_av:
            parts.append(f"{free_av:.0f}% had free AV only")

        # Top AV products for context
        av_list = av_data.get('list', [])
        if av_list and isinstance(av_list, list):
            top_av = [
                a['name'] for a in av_list
                if isinstance(a, dict) and a.get('name')
                and a['name'] != 'Not Found'
            ][:3]
            if top_av:
                parts.append(f"Top AV: {', '.join(top_av)}")

        return " | ".join(parts) if parts else ""

    def _extract_third_parties(self, data):
        """Extract third-party domain exposure (supply chain risk)."""
        max_tp = self.opts.get('max_third_parties', 10)
        tp_domains = data.get('thirdPartyDomains', [])
        if not tp_domains or not isinstance(tp_domains, list):
            return []

        results = []
        for entry in tp_domains[:max_tp]:
            if not isinstance(entry, dict):
                continue
            domain = entry.get('domain', '')
            count = entry.get('occurrence', 0)
            # Skip redacted entries
            if domain and '****' not in domain:
                results.append(f"{domain} ({count}x)")

        return results

    def _extract_timeline(self, data):
        """Extract last compromise dates."""
        parts = []

        last_emp = data.get('last_employee_compromised', '')
        last_user = data.get('last_user_compromised', '')

        if last_emp:
            # Trim to date only
            date_str = str(last_emp)[:10]
            parts.append(f"Employees {date_str}")

        if last_user:
            date_str = str(last_user)[:10]
            parts.append(f"Users {date_str}")

        return ", ".join(parts) if parts else ""

    # ------------------------------------------------------------------
    # Event handler
    # ------------------------------------------------------------------

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

        time.sleep(self.opts.get('pause', 2))

# End of sfp_stealerlog_check class
