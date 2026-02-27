# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_csp
# Purpose:     Detect AI service dependencies from Content-Security-Policy
#              HTTP headers and discover OpenAI ChatGPT plugin manifests
#              at /.well-known/ai-plugin.json.
#
# Author:      ASM-NG
#
# Created:     2026-02-26
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_csp(SpiderFootPlugin):

    meta = {
        'name': "AI CSP Analyzer & Plugin Detector",
        'summary': "Detect AI service dependencies from CSP headers and "
                   "discover OpenAI ChatGPT plugin manifests.",
        'flags': [],
        'useCases': ["Footprint", "Passive", "AI Attack Surface"],
        'categories': ["Content Analysis"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Analyzes Content-Security-Policy headers to "
                           "identify allowed connections to AI service "
                           "domains (OpenAI, Anthropic, Cohere, Gemini, "
                           "Mistral, HuggingFace, etc.) and probes for "
                           "OpenAI ChatGPT plugin manifests at the "
                           "well-known endpoint.",
        }
    }

    # Exact-match AI service domains
    AI_SERVICE_DOMAINS = {
        'api.openai.com': 'OpenAI API',
        'api.anthropic.com': 'Anthropic API',
        'api.cohere.ai': 'Cohere API',
        'api.cohere.com': 'Cohere API',
        'generativelanguage.googleapis.com': 'Google Gemini API',
        'api.mistral.ai': 'Mistral AI API',
        'api-inference.huggingface.co': 'Hugging Face Inference API',
        'huggingface.co': 'Hugging Face',
        'api.replicate.com': 'Replicate API',
        'api.together.xyz': 'Together AI API',
        'api.groq.com': 'Groq API',
        'api.perplexity.ai': 'Perplexity AI API',
        'api.deepseek.com': 'DeepSeek API',
        'api.fireworks.ai': 'Fireworks AI API',
        'api.stability.ai': 'Stability AI API',
        'oaidalleapiprodscus.blob.core.windows.net': 'OpenAI DALL-E',
        'cdn.openai.com': 'OpenAI CDN',
        'chatbase.co': 'Chatbase AI Widget',
        'embed.tawk.to': 'Tawk.to Chat (potential AI)',
        'widget.intercom.io': 'Intercom (potential AI)',
        'js.driftt.com': 'Drift Chat (potential AI)',
        'cdn.voiceflow.com': 'Voiceflow AI Chat',
        'app.wonderchat.io': 'Wonderchat AI',
    }

    # Partial domain patterns: if a CSP domain contains one of these
    # substrings, it is flagged as AI-related infrastructure.
    AI_DOMAIN_PARTIAL_PATTERNS = [
        ('.openai.com', 'OpenAI'),
        ('.anthropic.com', 'Anthropic'),
        ('.sagemaker.', 'AWS SageMaker'),
        ('.aiplatform.googleapis.com', 'Google AI Platform (Vertex AI)'),
        ('.ml.azure.com', 'Azure Machine Learning'),
    ]

    # CSP directives from which to extract domain allow-lists.
    CSP_DIRECTIVES = [
        'connect-src',
        'script-src',
        'frame-src',
        'default-src',
    ]

    opts = {
        'check_ai_plugin': True,
        'plugin_timeout': 15,
    }

    optdescs = {
        'check_ai_plugin': "Probe for OpenAI ChatGPT plugin manifests at "
                           "/.well-known/ai-plugin.json on discovered hosts.",
        'plugin_timeout': "Timeout in seconds for the ai-plugin.json fetch.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "WEBSERVER_HTTPHEADERS",
            "INTERNET_NAME",
            "DOMAIN_NAME",
        ]

    def producedEvents(self):
        return [
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    # ------------------------------------------------------------------
    # CSP parsing helpers
    # ------------------------------------------------------------------

    def _parse_csp(self, csp_value):
        """Parse a CSP header value into a dict of directive -> list of sources.

        Example input:
            "default-src 'self'; connect-src api.openai.com cdn.example.com"
        Returns:
            {'default-src': ["'self'"], 'connect-src': ['api.openai.com', 'cdn.example.com']}
        """
        directives = {}
        # Directives are separated by semicolons
        for part in csp_value.split(';'):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if not tokens:
                continue
            directive_name = tokens[0].lower()
            sources = tokens[1:]
            directives[directive_name] = sources
        return directives

    def _extract_domains_from_sources(self, sources):
        """Extract hostnames/domains from a list of CSP source expressions.

        CSP sources can be bare hostnames, wildcard hosts (*.example.com),
        scheme-host combos (https://api.openai.com), or keywords ('self',
        'unsafe-inline', etc.).  We extract anything that looks like a
        domain name, stripping scheme prefixes, ports, and paths.
        """
        domains = set()
        for src in sources:
            src = src.strip()
            # Skip CSP keywords
            if src.startswith("'") and src.endswith("'"):
                continue
            if src in ('*', 'data:', 'blob:', 'mediastream:', 'filesystem:'):
                continue

            # Strip scheme prefix (https://, http://, wss://, ws://)
            cleaned = re.sub(r'^(?:https?|wss?|ftp)://', '', src)

            # Strip port and path
            cleaned = cleaned.split(':')[0]
            cleaned = cleaned.split('/')[0]

            # Strip leading wildcard prefix (*.)
            if cleaned.startswith('*.'):
                cleaned = cleaned[2:]

            # Basic domain validation: must have at least one dot
            if '.' in cleaned and len(cleaned) > 3:
                domains.add(cleaned.lower())

        return domains

    def _match_ai_domains(self, domains):
        """Match a set of domains against known AI service domains.

        Returns a list of (domain, service_name) tuples for matches.
        """
        matches = []
        seen_services = set()

        for domain in domains:
            # Exact match
            if domain in self.AI_SERVICE_DOMAINS:
                service = self.AI_SERVICE_DOMAINS[domain]
                key = f"{domain}:{service}"
                if key not in seen_services:
                    seen_services.add(key)
                    matches.append((domain, service))
                continue

            # Partial match
            for pattern, service in self.AI_DOMAIN_PARTIAL_PATTERNS:
                if pattern in domain:
                    key = f"{domain}:{service}"
                    if key not in seen_services:
                        seen_services.add(key)
                        matches.append((domain, f"{service} (via {domain})"))
                    break

        return matches

    # ------------------------------------------------------------------
    # AI Plugin detection
    # ------------------------------------------------------------------

    def _check_ai_plugin(self, hostname, event):
        """Probe for an OpenAI ChatGPT plugin manifest at the well-known URL.

        If found, emit AI_INFRASTRUCTURE_DETECTED with plugin details.
        """
        url = f"https://{hostname}/.well-known/ai-plugin.json"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=self.opts['plugin_timeout'],
                useragent=self.opts.get('_useragent', 'ASM-NG'),
            )
        except Exception:
            return

        if not res or not res.get('content'):
            return

        code = str(res.get('code', ''))
        if code not in ('200',):
            return

        content = res['content']

        try:
            plugin = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(plugin, dict):
            return

        # An ai-plugin.json must have at minimum a schema_version or
        # name_for_human to be considered valid.
        name = plugin.get('name_for_human', plugin.get('name_for_model', ''))
        description = plugin.get('description_for_human',
                                 plugin.get('description_for_model', ''))
        api_url = ''
        api_spec = plugin.get('api', {})
        if isinstance(api_spec, dict):
            api_url = api_spec.get('url', '')

        if not name and not plugin.get('schema_version'):
            return

        # Build a descriptive event message
        parts = [f"OpenAI ChatGPT plugin manifest found on {hostname}"]
        if name:
            parts.append(f"Name: {name}")
        if description:
            # Truncate long descriptions
            desc_short = description[:200]
            if len(description) > 200:
                desc_short += "..."
            parts.append(f"Description: {desc_short}")
        if api_url:
            parts.append(f"API spec: {api_url}")

        detail = " | ".join(parts)

        evt = SpiderFootEvent(
            "AI_INFRASTRUCTURE_DETECTED",
            detail,
            self.__name__, event)
        self.notifyListeners(evt)

    # ------------------------------------------------------------------
    # Main event handler
    # ------------------------------------------------------------------

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventSource = event.actualSource

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # ----- CSP header analysis (WEBSERVER_HTTPHEADERS) -----
        if eventName == "WEBSERVER_HTTPHEADERS":
            # Deduplicate by source URL
            csp_key = f"csp:{eventSource}"
            if csp_key in self.results:
                return
            self.results[csp_key] = True

            # Verify the source belongs to our target
            fqdn = self.sf.urlFQDN(eventSource)
            if not self.getTarget().matches(fqdn):
                self.debug(f"Ignoring headers from external host {fqdn}")
                return

            # Parse the JSON header blob
            try:
                headers = json.loads(eventData)
            except Exception:
                self.error("HTTP headers received in an unexpected format.")
                return

            # Find the Content-Security-Policy header (case-insensitive)
            csp_value = None
            for key in headers:
                if key.lower() == 'content-security-policy':
                    csp_value = headers[key]
                    break

            if not csp_value:
                return

            self.debug(f"Parsing CSP header from {eventSource}")

            # Parse CSP into directives
            directives = self._parse_csp(csp_value)

            # Collect domains from the directives we care about
            all_domains = set()
            for directive in self.CSP_DIRECTIVES:
                sources = directives.get(directive, [])
                if sources:
                    domains = self._extract_domains_from_sources(sources)
                    all_domains.update(domains)

            if not all_domains:
                return

            # Match against known AI service domains
            matches = self._match_ai_domains(all_domains)

            for domain, service in matches:
                if self.checkForStop():
                    return

                match_key = f"ai_csp:{fqdn}:{domain}"
                if match_key in self.results:
                    continue
                self.results[match_key] = True

                detail = (f"CSP allows connection to AI service: {service} "
                          f"(domain: {domain}) on {fqdn}")
                self.info(detail)

                evt = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED",
                    detail,
                    self.__name__, event)
                self.notifyListeners(evt)

        # ----- AI Plugin detection (INTERNET_NAME / DOMAIN_NAME) -----
        elif eventName in ("INTERNET_NAME", "DOMAIN_NAME"):
            if not self.opts['check_ai_plugin']:
                return

            # Deduplicate by hostname
            plugin_key = f"plugin:{eventData}"
            if plugin_key in self.results:
                return
            self.results[plugin_key] = True

            if not self.getTarget().matches(eventData):
                self.debug(f"Ignoring non-target hostname {eventData}")
                return

            if self.checkForStop():
                return

            self._check_ai_plugin(eventData, event)


# End of sfp_ai_csp class
