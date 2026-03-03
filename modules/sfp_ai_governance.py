# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_governance
# Purpose:     Check for AI governance policies, responsible AI statements,
#              and AI ethics pages. Absence is itself a finding.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_governance(SpiderFootPlugin):

    meta = {
        'name': "AI Governance Policy Checker",
        'summary': "Checks for AI governance policies, responsible AI "
                   "statements, AI ethics pages, and AI bot directives. "
                   "Probes ~15 well-known governance URLs (/ai-policy, "
                   "/responsible-ai, /ai-ethics, /trust/ai, etc.), scans "
                   "web content for governance keywords, and checks "
                   "robots.txt for AI crawler directives. Absence of any "
                   "AI governance policy is itself a material finding.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Probes the target website for AI governance "
                           "policy pages and scans content for governance "
                           "indicators. No external API required.",
        }
    }

    # Governance policy URL paths to probe
    GOVERNANCE_URLS = [
        '/ai-policy',
        '/ai-governance',
        '/responsible-ai',
        '/ai-ethics',
        '/trust/ai',
        '/legal/ai-policy',
        '/policies/ai',
        '/about/ai',
        '/ai-principles',
        '/ml-policy',
        '/generative-ai-policy',
        '/privacy-policy',
        '/terms-of-service',
        '/acceptable-use',
        '/ai-safety',
    ]

    # Governance-related phrases to detect in content
    GOVERNANCE_KEYWORDS = [
        'responsible ai',
        'ai ethics',
        'ai governance',
        'ai policy',
        'model card',
        'algorithmic transparency',
        'ai risk',
        'ai safety',
        'ai principles',
        'ethical ai',
        'ai accountability',
        'ai bias',
        'ai fairness',
        'ai audit',
        'ai impact assessment',
    ]

    # AI crawler user-agent strings
    AI_BOT_AGENTS = [
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

    opts = {
        'check_robots_txt': True,
        'check_privacy_policy': True,
        'absence_is_finding': True,
    }

    optdescs = {
        'check_robots_txt': "Check robots.txt for AI bot directives.",
        'check_privacy_policy': "Scan privacy policy and ToS for AI clauses.",
        'absence_is_finding': "Report when no AI governance policy is found.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._governance_found = {}
        self._domains_probed = set()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        # Only DOMAIN_NAME — not INTERNET_NAME.  INTERNET_NAME includes
        # infrastructure hostnames from SSL certs (CRL endpoints, OCSP
        # responders, CA domains) that should never be probed for AI policies.
        return ["DOMAIN_NAME", "TARGET_WEB_CONTENT"]

    def producedEvents(self):
        return ["AI_GOVERNANCE_FINDING"]

    def _probe_governance_urls(self, domain, event):
        """Probe well-known governance URLs for AI policy content."""
        found_policies = []
        ai_specific_urls = [
            u for u in self.GOVERNANCE_URLS
            if u not in ('/privacy-policy', '/terms-of-service', '/acceptable-use')
        ]
        general_urls = ['/privacy-policy', '/terms-of-service', '/acceptable-use']

        # First check AI-specific governance URLs
        for path in ai_specific_urls:
            if self.checkForStop():
                return found_policies

            url = f"https://{domain}{path}"
            dedup_key = f"probe:{url}"
            if dedup_key in self.results:
                continue
            self.results[dedup_key] = True

            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'ASM-NG')
            )

            if not res or not res.get('content'):
                continue

            # Check for HTTP success and meaningful content
            code = str(res.get('code', ''))
            if not code.startswith('2'):
                continue

            content = res['content'].lower()
            # Verify the page actually mentions AI (not just a 404 page)
            has_ai_content = any(kw in content for kw in self.GOVERNANCE_KEYWORDS)

            if has_ai_content:
                found_policies.append(path)

                detail = (f"AI governance policy found at "
                          f"https://{domain}{path}. "
                          f"ACTION: Review the policy for completeness against "
                          f"EU AI Act Article 13, NIST AI RMF GOVERN 1.1, and "
                          f"ISO 42001 Clause 5.2 requirements.")

                evt = SpiderFootEvent(
                    "AI_GOVERNANCE_FINDING",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

        # Check general legal pages for AI clauses
        if self.opts['check_privacy_policy']:
            for path in general_urls:
                if self.checkForStop():
                    return found_policies

                url = f"https://{domain}{path}"
                dedup_key = f"probe:{url}"
                if dedup_key in self.results:
                    continue
                self.results[dedup_key] = True

                res = self.sf.fetchUrl(
                    url,
                    timeout=15,
                    useragent=self.opts.get('_useragent', 'ASM-NG')
                )

                if not res or not res.get('content'):
                    continue

                code = str(res.get('code', ''))
                if not code.startswith('2'):
                    continue

                content = res['content'].lower()
                ai_clauses = [kw for kw in self.GOVERNANCE_KEYWORDS if kw in content]

                if ai_clauses:
                    found_policies.append(path)

                    detail = (f"AI clauses found in {path} at "
                              f"https://{domain}{path}: "
                              f"{', '.join(ai_clauses[:5])}")

                    evt = SpiderFootEvent(
                        "AI_GOVERNANCE_FINDING",
                        detail,
                        self.__class__.__name__, event)
                    self.notifyListeners(evt)

        return found_policies

    def _check_robots_for_ai_bots(self, domain, event):
        """Check robots.txt for AI bot directives."""
        url = f"https://{domain}/robots.txt"
        dedup_key = f"robots:{domain}"
        if dedup_key in self.results:
            return
        self.results[dedup_key] = True

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return

        content = res['content']
        blocked = []
        allowed = []

        for bot in self.AI_BOT_AGENTS:
            pattern = re.compile(
                rf'User-agent:\s*{re.escape(bot)}',
                re.IGNORECASE
            )
            if pattern.search(content):
                # Check if blocked
                block_pattern = re.compile(
                    rf'User-agent:\s*{re.escape(bot)}\s*\n\s*Disallow:\s*/',
                    re.IGNORECASE
                )
                if block_pattern.search(content):
                    blocked.append(bot)
                else:
                    allowed.append(bot)

        if blocked or allowed:
            detail = (f"AI bot directives in robots.txt for {domain}: "
                      f"blocked={', '.join(blocked) or 'none'}, "
                      f"allowed={', '.join(allowed) or 'none'}. "
                      f"ACTION: Verify these directives align with the "
                      f"organization's AI data usage policy and assess "
                      f"whether additional AI crawlers should be addressed.")

            evt = SpiderFootEvent(
                "AI_GOVERNANCE_FINDING",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

    def _scan_content_for_governance(self, content, event):
        """Scan web content for AI governance indicators."""
        content_lower = content.lower()
        found_keywords = [kw for kw in self.GOVERNANCE_KEYWORDS if kw in content_lower]

        if found_keywords:
            detail = (f"AI governance keywords found in web content: "
                      f"{', '.join(found_keywords[:10])}. "
                      f"ACTION: Assess whether these mentions constitute a "
                      f"formal AI governance policy or are incidental "
                      f"references that do not satisfy framework requirements.")

            dedup_key = f"governance_kw:{','.join(sorted(found_keywords[:5]))}"
            if dedup_key not in self.results:
                self.results[dedup_key] = True

                evt = SpiderFootEvent(
                    "AI_GOVERNANCE_FINDING",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventName == "DOMAIN_NAME":
            domain = eventData

            if domain in self._domains_probed:
                return
            self._domains_probed.add(domain)

            # Only probe domains that belong to the target
            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                self.debug(f"Skipping {domain} — not part of target scope")
                return

            # Probe governance URLs
            found_policies = self._probe_governance_urls(domain, event)
            self._governance_found[domain] = found_policies

            # Check robots.txt for AI bot directives
            if self.opts['check_robots_txt']:
                self._check_robots_for_ai_bots(domain, event)

            # Absence finding — only for the root target domain, not
            # every subdomain.  One "no policy" result per scan is enough.
            target_domain = self.getTarget().targetValue
            if (self.opts['absence_is_finding']
                    and not found_policies
                    and domain == target_domain
                    and f"absence:{domain}" not in self.results):
                self.results[f"absence:{domain}"] = True

                detail = (f"No AI governance policy detected for {domain}: "
                          f"probed {len(self.GOVERNANCE_URLS)} well-known "
                          f"governance URLs with no AI policy content found. "
                          f"WHY IT MATTERS: EU AI Act Article 13 requires "
                          f"transparency obligations for AI systems; NIST AI "
                          f"RMF GOVERN 1.1 requires documented legal and "
                          f"regulatory compliance; ISO 42001 Clause 5.2 "
                          f"requires an AI policy appropriate to the "
                          f"organization's purpose. "
                          f"ACTION: (1) Determine whether the organization "
                          f"deploys or uses AI systems. (2) If yes, draft and "
                          f"publish an AI governance policy covering intended "
                          f"use, risk management, and transparency. (3) Engage "
                          f"legal/compliance to align the policy with "
                          f"applicable AI regulations.")

                evt = SpiderFootEvent(
                    "AI_GOVERNANCE_FINDING",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

        elif eventName == "TARGET_WEB_CONTENT":
            content_key = f"content:{eventData[:200]}"
            if content_key in self.results:
                return
            self.results[content_key] = True

            self._scan_content_for_governance(eventData, event)


# End of sfp_ai_governance class
