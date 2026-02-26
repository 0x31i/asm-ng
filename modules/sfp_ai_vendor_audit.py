# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_vendor_audit
# Purpose:     Detect third-party AI vendor widget embeds in web content,
#              including chatbots, AI-powered support, sales tools, and
#              AI crawler directives in robots.txt.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_vendor_audit(SpiderFootPlugin):

    meta = {
        'name': "AI Vendor Widget Detector",
        'summary': "Detects third-party AI vendor widget integrations in web "
                   "content. Scans for AI-powered chatbots (Zendesk AI, "
                   "Intercom Fin, Ada, Drift, Botpress), sales/marketing AI "
                   "(Salesforce Einstein, HubSpot AI, Qualified), analytics "
                   "AI (Algolia, Dynamic Yield, Coveo), and checks robots.txt "
                   "for AI crawler bot directives (GPTBot, Claude-Web, etc.).",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Analyzes fetched web content for third-party AI "
                           "vendor widget script tags, iframes, and "
                           "configuration objects. Also checks robots.txt for "
                           "AI bot directives. No external API required.",
        }
    }

    # (compiled_regex, vendor_name, vendor_category)
    VENDOR_PATTERNS = [
        # Support AI
        (re.compile(r'zdassets\.com.*answer.?bot', re.I), 'Zendesk AI (Answer Bot)', 'Support AI'),
        (re.compile(r'zdassets\.com', re.I), 'Zendesk', 'Support AI'),
        (re.compile(r'intercomcdn\.com.*\bfin\b', re.I), 'Intercom Fin AI', 'Support AI'),
        (re.compile(r'intercomcdn\.com', re.I), 'Intercom', 'Support AI'),
        (re.compile(r'ada\.cx', re.I), 'Ada AI', 'Support AI'),
        (re.compile(r'freshdesk\.com.*freddy', re.I), 'Freshdesk Freddy AI', 'Support AI'),
        (re.compile(r'forethought\.ai', re.I), 'Forethought AI', 'Support AI'),

        # Sales/Marketing AI
        (re.compile(r'salesforce.*einstein', re.I), 'Salesforce Einstein', 'Sales AI'),
        (re.compile(r'hubspot\.com.*chatflow', re.I), 'HubSpot AI Chatflows', 'Sales AI'),
        (re.compile(r'drift\.com', re.I), 'Drift AI', 'Sales AI'),
        (re.compile(r'qualified\.com', re.I), 'Qualified AI', 'Sales AI'),
        (re.compile(r'6sense\.com', re.I), '6sense AI', 'Sales AI'),

        # Chatbot/Conversational AI
        (re.compile(r'chatgpt.*embed|embed.*chatgpt', re.I), 'ChatGPT Widget', 'Conversational AI'),
        (re.compile(r'voiceflow\.com', re.I), 'Voiceflow', 'Conversational AI'),
        (re.compile(r'botpress\.cloud', re.I), 'Botpress', 'Conversational AI'),
        (re.compile(r'chatbase\.co', re.I), 'Chatbase', 'Conversational AI'),
        (re.compile(r'customgpt\.ai', re.I), 'CustomGPT', 'Conversational AI'),
        (re.compile(r'tidio\.co', re.I), 'Tidio AI', 'Conversational AI'),
        (re.compile(r'landbot\.io', re.I), 'Landbot AI', 'Conversational AI'),

        # Analytics/Personalization AI
        (re.compile(r'algolia\.com.*recommend', re.I), 'Algolia AI Recommend', 'Analytics AI'),
        (re.compile(r'algolia\w*\.net', re.I), 'Algolia', 'Analytics AI'),
        (re.compile(r'dynamicyield\.com', re.I), 'Dynamic Yield AI', 'Analytics AI'),
        (re.compile(r'coveo\.com.*\bml\b', re.I), 'Coveo ML', 'Analytics AI'),
        (re.compile(r'coveo\.com', re.I), 'Coveo', 'Analytics AI'),

        # Content AI
        (re.compile(r'jasper\.ai', re.I), 'Jasper AI', 'Content AI'),
        (re.compile(r'writer\.com', re.I), 'Writer AI', 'Content AI'),
        (re.compile(r'copy\.ai', re.I), 'Copy.ai', 'Content AI'),

        # AI Code Assistants (config/license references)
        (re.compile(r'cursor\.sh|cursor\.com', re.I), 'Cursor AI', 'Code AI'),
        (re.compile(r'codeium\.com', re.I), 'Codeium', 'Code AI'),
        (re.compile(r'tabnine\.com', re.I), 'Tabnine', 'Code AI'),
    ]

    # AI crawler user-agents to check in robots.txt
    AI_BOT_DIRECTIVES = [
        'GPTBot',
        'ChatGPT-User',
        'Claude-Web',
        'Applebot-Extended',
        'Google-Extended',
        'Amazonbot',
        'CCBot',
        'anthropic-ai',
        'cohere-ai',
        'PerplexityBot',
    ]

    opts = {}

    optdescs = {}

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._robots_checked = {}

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "TARGET_WEB_CONTENT",
            "DOMAIN_NAME",
            "INTERNET_NAME",
        ]

    def producedEvents(self):
        return [
            "AI_VENDOR_WIDGET_DETECTED",
            "AI_SHADOW_SERVICE_DETECTED",
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def _scan_content_for_vendors(self, content, source, event):
        """Scan HTML content for AI vendor widget patterns."""
        found_vendors = set()

        for pattern, vendor_name, category in self.VENDOR_PATTERNS:
            if self.checkForStop():
                return

            if pattern.search(content):
                dedup_key = f"vendor:{vendor_name}:{source}"
                if dedup_key in self.results:
                    continue
                self.results[dedup_key] = True
                found_vendors.add((vendor_name, category))

                detail = (f"AI vendor widget detected: {vendor_name} "
                          f"({category}) on {source}")

                evt = SpiderFootEvent(
                    "AI_VENDOR_WIDGET_DETECTED",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

        # If multiple vendors found, also emit shadow AI signal
        if len(found_vendors) >= 2:
            vendor_list = ', '.join(v[0] for v in found_vendors)
            detail = (f"Multiple AI vendor integrations on {source}: "
                      f"{vendor_list}")

            evt = SpiderFootEvent(
                "AI_SHADOW_SERVICE_DETECTED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

    def _check_robots_txt(self, domain, event):
        """Check robots.txt for AI bot directives."""
        if domain in self._robots_checked:
            return
        self._robots_checked[domain] = True

        url = f"https://{domain}/robots.txt"
        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return

        content = res['content']
        found_directives = []
        blocked_bots = []
        allowed_bots = []

        for bot in self.AI_BOT_DIRECTIVES:
            # Look for User-agent: <bot> followed by Allow/Disallow
            pattern = re.compile(
                rf'User-agent:\s*{re.escape(bot)}\s*\n((?:(?:Allow|Disallow):.*\n?)*)',
                re.IGNORECASE
            )
            match = pattern.search(content)
            if match:
                directives = match.group(1).strip()
                found_directives.append((bot, directives))
                if 'Disallow: /' in directives:
                    blocked_bots.append(bot)
                else:
                    allowed_bots.append(bot)

        if found_directives:
            detail = (f"AI bot directives in robots.txt for {domain}: "
                      f"{len(blocked_bots)} blocked ({', '.join(blocked_bots) or 'none'}), "
                      f"{len(allowed_bots)} allowed ({', '.join(allowed_bots) or 'none'})")

            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventName == "TARGET_WEB_CONTENT":
            # Dedup by content hash (first 200 chars)
            content_key = f"content:{eventData[:200]}"
            if content_key in self.results:
                return
            self.results[content_key] = True

            source = event.actualSource if hasattr(event, 'actualSource') and event.actualSource else "unknown"
            self._scan_content_for_vendors(eventData, source, event)

        elif eventName in ("DOMAIN_NAME", "INTERNET_NAME"):
            # Check robots.txt for AI bot directives
            domain = eventData
            dedup_key = f"robots:{domain}"
            if dedup_key in self.results:
                return
            self.results[dedup_key] = True

            self._check_robots_txt(domain, event)


# End of sfp_ai_vendor_audit class
