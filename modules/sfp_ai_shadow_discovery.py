# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_shadow_discovery
# Purpose:     Detect shadow AI SaaS integrations by scanning DNS records,
#              web content, and CSP headers for references to known AI
#              provider domains.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_shadow_discovery(SpiderFootPlugin):

    meta = {
        'name': "AI Shadow SaaS Discovery",
        'summary': "Detect shadow AI SaaS integrations by analysing DNS "
                   "records, web content, and HTTP headers for references "
                   "to known AI provider domains such as OpenAI, Anthropic, "
                   "Cohere, Mistral, and others.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Content Analysis"],
        'dataSource': {
            'website': "https://openai.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Passively identifies shadow AI SaaS usage by "
                           "inspecting DNS TXT/CNAME records, web page "
                           "content (fetch/XHR calls, script tags), and "
                           "Content-Security-Policy headers for references "
                           "to known AI API provider domains.",
        }
    }

    # Known AI SaaS provider domains
    AI_SAAS_DOMAINS = [
        'openai.com',
        'api.openai.com',
        'anthropic.com',
        'api.anthropic.com',
        'replicate.com',
        'together.ai',
        'api.together.xyz',
        'groq.com',
        'api.groq.com',
        'fireworks.ai',
        'api.fireworks.ai',
        'huggingface.co',
        'cohere.com',
        'api.cohere.ai',
        'mistral.ai',
        'api.mistral.ai',
        'deepseek.com',
        'api.deepseek.com',
        'perplexity.ai',
        'anyscale.com',
    ]

    # Regex patterns for matching AI domains in CSP headers and web content
    AI_CSP_PATTERNS = [
        re.compile(r'openai\.com', re.IGNORECASE),
        re.compile(r'anthropic\.com', re.IGNORECASE),
        re.compile(r'replicate\.com', re.IGNORECASE),
        re.compile(r'together\.(ai|xyz)', re.IGNORECASE),
        re.compile(r'groq\.com', re.IGNORECASE),
        re.compile(r'fireworks\.ai', re.IGNORECASE),
        re.compile(r'huggingface\.co', re.IGNORECASE),
        re.compile(r'cohere\.(com|ai)', re.IGNORECASE),
        re.compile(r'mistral\.ai', re.IGNORECASE),
        re.compile(r'deepseek\.com', re.IGNORECASE),
    ]

    # DNS TXT verification prefixes used by AI SaaS providers
    AI_TXT_VERIFICATION_PREFIXES = [
        ('openai-domain-verification', 'OpenAI'),
        ('anthropic-', 'Anthropic'),
        ('_replicate-', 'Replicate'),
        ('huggingface-', 'Hugging Face'),
        ('cohere-', 'Cohere'),
        ('mistral-', 'Mistral AI'),
        ('deepseek-', 'DeepSeek'),
        ('groq-', 'Groq'),
    ]

    # Regex patterns to detect fetch/XHR calls to AI API endpoints in web content
    AI_FETCH_PATTERNS = [
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.openai\.com""", re.IGNORECASE), 'OpenAI API'),
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.anthropic\.com""", re.IGNORECASE), 'Anthropic API'),
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.together\.xyz""", re.IGNORECASE), 'Together AI API'),
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.groq\.com""", re.IGNORECASE), 'Groq API'),
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.fireworks\.ai""", re.IGNORECASE), 'Fireworks AI API'),
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.cohere\.ai""", re.IGNORECASE), 'Cohere API'),
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.mistral\.ai""", re.IGNORECASE), 'Mistral AI API'),
        (re.compile(r"""(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*['"]https?://api\.deepseek\.com""", re.IGNORECASE), 'DeepSeek API'),
    ]

    # Regex patterns for <script src="..."> referencing AI CDN/SDK domains
    AI_SCRIPT_SRC_PATTERNS = [
        (re.compile(r'<script[^>]+src=["\']https?://[^"\']*openai\.com', re.IGNORECASE), 'OpenAI'),
        (re.compile(r'<script[^>]+src=["\']https?://[^"\']*anthropic\.com', re.IGNORECASE), 'Anthropic'),
        (re.compile(r'<script[^>]+src=["\']https?://[^"\']*huggingface\.co', re.IGNORECASE), 'Hugging Face'),
        (re.compile(r'<script[^>]+src=["\']https?://[^"\']*replicate\.com', re.IGNORECASE), 'Replicate'),
        (re.compile(r'<script[^>]+src=["\']https?://[^"\']*cohere\.(com|ai)', re.IGNORECASE), 'Cohere'),
    ]

    opts = {
        'check_dns_cnames': True,
        'check_web_content': True,
        'check_txt_records': True,
    }

    optdescs = {
        'check_dns_cnames': "Check DNS CNAME records for AI SaaS provider domains.",
        'check_web_content': "Scan web content for outbound AI API references.",
        'check_txt_records': "Check DNS TXT records for AI SaaS verification strings.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "DNS_TEXT",
            "TARGET_WEB_CONTENT",
        ]

    def producedEvents(self):
        return [
            "AI_SHADOW_SERVICE_DETECTED",
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def _emit_shadow_detection(self, detail, event):
        """Emit both AI_SHADOW_SERVICE_DETECTED and AI_INFRASTRUCTURE_DETECTED."""
        evt_shadow = SpiderFootEvent(
            "AI_SHADOW_SERVICE_DETECTED", detail,
            self.__class__.__name__, event)
        self.notifyListeners(evt_shadow)

        evt_infra = SpiderFootEvent(
            "AI_INFRASTRUCTURE_DETECTED",
            f"Shadow AI SaaS integration: {detail}",
            self.__class__.__name__, evt_shadow)
        self.notifyListeners(evt_infra)

    def _check_dns_txt(self, eventData, event):
        """Scan DNS TXT record content for AI SaaS verification strings."""
        if not self.opts['check_txt_records']:
            return

        txt_lower = eventData.lower()

        for prefix, provider in self.AI_TXT_VERIFICATION_PREFIXES:
            if prefix.lower() in txt_lower:
                detail = (f"DNS TXT record contains {provider} domain "
                          f"verification string: {eventData[:200]}")
                key = f"txt:{provider}:{eventData[:100]}"
                if key not in self.results:
                    self.results[key] = True
                    self._emit_shadow_detection(detail, event)

        # Also check for any AI SaaS domain references in TXT records
        for domain in self.AI_SAAS_DOMAINS:
            if domain.lower() in txt_lower:
                key = f"txt:domain:{domain}:{eventData[:80]}"
                if key not in self.results:
                    self.results[key] = True
                    detail = (f"DNS TXT record references AI SaaS domain "
                              f"'{domain}': {eventData[:200]}")
                    self._emit_shadow_detection(detail, event)

    def _check_web_content(self, eventData, event):
        """Scan web content for outbound AI API references."""
        if not self.opts['check_web_content']:
            return

        # Check for fetch/XHR calls to AI API endpoints
        for pattern, provider in self.AI_FETCH_PATTERNS:
            if pattern.search(eventData):
                key = f"fetch:{provider}"
                if key not in self.results:
                    self.results[key] = True
                    detail = (f"Web content contains outbound API call to "
                              f"{provider}")
                    self._emit_shadow_detection(detail, event)

        # Check for script src referencing AI CDN/SDKs
        for pattern, provider in self.AI_SCRIPT_SRC_PATTERNS:
            if pattern.search(eventData):
                key = f"script:{provider}"
                if key not in self.results:
                    self.results[key] = True
                    detail = (f"Web content loads script from {provider} "
                              f"domain")
                    self._emit_shadow_detection(detail, event)

        # Check for Content-Security-Policy headers embedded in meta tags
        # or for CSP-style connect-src / script-src directives in content
        csp_match = re.search(
            r'(?:content-security-policy|connect-src|script-src|default-src)'
            r'[^;"\'\n]{0,500}',
            eventData, re.IGNORECASE)
        if csp_match:
            csp_fragment = csp_match.group(0)
            for pattern in self.AI_CSP_PATTERNS:
                match = pattern.search(csp_fragment)
                if match:
                    matched_domain = match.group(0)
                    key = f"csp:{matched_domain}"
                    if key not in self.results:
                        self.results[key] = True
                        detail = (f"Content-Security-Policy references AI "
                                  f"domain '{matched_domain}'")
                        self._emit_shadow_detection(detail, event)

        # Generic scan for AI SaaS API domain references in content
        for domain in self.AI_SAAS_DOMAINS:
            if domain.startswith('api.') and domain in eventData:
                key = f"content:api:{domain}"
                if key not in self.results:
                    self.results[key] = True
                    detail = (f"Web content references AI API endpoint "
                              f"'{domain}'")
                    self._emit_shadow_detection(detail, event)

    def _check_well_known_openid(self, hostname, event):
        """Check .well-known/openid-configuration for AI SSO integrations."""
        url = f"https://{hostname}/.well-known/openid-configuration"
        key = f"wellknown:{hostname}"
        if key in self.results:
            return
        self.results[key] = True

        self.debug(f"Checking {url} for AI SSO integrations")

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return

        content = res['content']

        for pattern in self.AI_CSP_PATTERNS:
            match = pattern.search(content)
            if match:
                matched_domain = match.group(0)
                det_key = f"sso:{hostname}:{matched_domain}"
                if det_key not in self.results:
                    self.results[det_key] = True
                    detail = (f"OpenID configuration on {hostname} references "
                              f"AI domain '{matched_domain}' — possible SSO "
                              f"integration")
                    self._emit_shadow_detection(detail, event)

    def _check_dns_cname_for_ai(self, hostname, event):
        """Probe common AI SaaS subdomains via DNS CNAME/resolution check."""
        if not self.opts['check_dns_cnames']:
            return

        # Common subdomain prefixes that may CNAME to AI SaaS providers
        ai_subdomains = [
            'ai', 'api-ai', 'ml', 'llm', 'openai', 'gpt', 'chat',
            'copilot', 'assistant',
        ]

        for sub in ai_subdomains:
            if self.checkForStop():
                return

            fqdn = f"{sub}.{hostname}"
            key = f"cname:{fqdn}"
            if key in self.results:
                continue
            self.results[key] = True

            self.debug(f"Resolving {fqdn} for AI SaaS CNAME check")

            # Use fetchUrl to check if subdomain resolves by attempting
            # an HTTP HEAD-style request
            res = self.sf.fetchUrl(
                f"https://{fqdn}/",
                timeout=10,
                useragent=self.opts.get('_useragent', 'ASM-NG')
            )

            if not res:
                continue

            # Check if the response or any redirect points to AI SaaS domains
            real_url = res.get('realurl', '') or ''
            content = res.get('content', '') or ''

            for domain in self.AI_SAAS_DOMAINS:
                if domain in real_url or domain in content[:1000]:
                    det_key = f"cname_hit:{fqdn}:{domain}"
                    if det_key not in self.results:
                        self.results[det_key] = True
                        detail = (f"Subdomain {fqdn} resolves/redirects to "
                                  f"AI SaaS domain '{domain}'")
                        self._emit_shadow_detection(detail, event)
                    break

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # --- DNS_TEXT events ---
        if eventName == "DNS_TEXT":
            key = f"dns_txt:{eventData[:200]}"
            if key in self.results:
                self.debug(f"Already processed DNS_TEXT, skipping.")
                return
            self.results[key] = True

            self._check_dns_txt(eventData, event)
            return

        # --- TARGET_WEB_CONTENT events ---
        if eventName == "TARGET_WEB_CONTENT":
            # Dedup on a hash of the first 500 chars to avoid re-scanning
            # identical content
            content_key = f"web:{hash(eventData[:500])}"
            if content_key in self.results:
                self.debug(f"Already processed similar web content, skipping.")
                return
            self.results[content_key] = True

            self._check_web_content(eventData, event)
            return

        # --- DOMAIN_NAME / INTERNET_NAME events ---
        if eventName in ("DOMAIN_NAME", "INTERNET_NAME"):
            key = f"host:{eventData}"
            if key in self.results:
                self.debug(f"Already processed {eventData}, skipping.")
                return
            self.results[key] = True

            # Check .well-known/openid-configuration for AI SSO
            self._check_well_known_openid(eventData, event)

            # Probe common AI SaaS subdomains via DNS/HTTP
            self._check_dns_cname_for_ai(eventData, event)
            return


# End of sfp_ai_shadow_discovery class
