# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_subdomain
# Purpose:     Discover AI/ML-related subdomains through Certificate
#              Transparency logs and DNS brute-forcing with an AI-specific
#              wordlist.
#
# Author:      ASM-NG Enhancement Team
#
# Created:     2026-02-20
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import threading
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_subdomain(SpiderFootPlugin):

    meta = {
        'name': "AI Subdomain Discovery",
        'summary': "Discover AI/ML-related subdomains via Certificate "
            "Transparency logs (crt.sh) and DNS brute-forcing with an "
            "AI-specific wordlist. Targets patterns like inference.*, ml.*, "
            "ai.*, model.*, llm.*, serving.*, etc.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"],
        'dataSource': {
            'website': "https://crt.sh/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Discovers AI infrastructure subdomains by querying "
                "Certificate Transparency logs for AI-related subdomain "
                "patterns and brute-forcing common AI subdomain names. "
                "Based on research showing organizations consistently use "
                "predictable patterns like inference.*, ml.*, ai.*, model.*, "
                "llm.*, chat.*, serving.*, genai.*, and gpu.*.",
        }
    }

    # Default options
    opts = {
        'query_ct_logs': True,
        'dns_bruteforce': True,
        'check_cloud_patterns': True,
        '_maxthreads': 50,
    }

    # Option descriptions
    optdescs = {
        'query_ct_logs': "Query crt.sh Certificate Transparency logs for "
            "AI-related subdomain patterns.",
        'dns_bruteforce': "Brute-force AI-specific subdomains via DNS "
            "resolution using the bundled ai-subdomains.txt wordlist.",
        'check_cloud_patterns': "Check for cloud provider AI service patterns "
            "(e.g. *.sagemaker.*.amazonaws.com, *.inference.*.azurecontainer.io).",
        '_maxthreads': "Maximum threads for DNS brute-forcing.",
    }

    results = None
    errorState = False
    lock = None

    # AI subdomain patterns to filter from CT log results
    AI_SUBDOMAIN_RE = re.compile(
        r'(inference|ml[.-]|ai[.-]|model[s]?[.-]|llm|chat[.-]|copilot|'
        r'predict|serving|genai|gen-ai|gpu|triton|mlflow|ollama|'
        r'huggingface|sagemaker|bedrock|vertex|openai|notebook|jupyter|'
        r'tensorboard|embedding|vector|gradio|streamlit|vllm|torchserve|'
        r'bentoml|ray[.-]|langchain|langserve|diffusion|comfyui|'
        r'deeplearning|transformers|cuda|agent[s]?[.-])',
        re.I
    )

    # Cloud provider AI service CNAME patterns
    CLOUD_AI_PATTERNS = [
        re.compile(r'\.sagemaker\..*\.amazonaws\.com', re.I),
        re.compile(r'\.inference\..*\.azurecontainer\.io', re.I),
        re.compile(r'\.openai\.azure\.com', re.I),
        re.compile(r'\.cognitiveservices\.azure\.com', re.I),
        re.compile(r'\.endpoints\.huggingface\.cloud', re.I),
        re.compile(r'\.aiplatform\.googleapis\.com', re.I),
        re.compile(r'\.run\.app', re.I),  # Cloud Run (common for AI serving)
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.lock = threading.Lock()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def _query_crtsh(self, domain):
        """Query crt.sh for certificates matching the domain, return AI-related hostnames."""
        ai_hosts = set()

        res = self.sf.fetchUrl(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30,
            useragent=self.opts['_useragent']
        )

        if not res or not res.get('content'):
            self.info(f"No crt.sh results for {domain}")
            return ai_hosts

        try:
            certs = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            self.debug(f"Failed to parse crt.sh JSON for {domain}")
            return ai_hosts

        for cert in certs:
            names = cert.get('name_value', '')
            for name in names.split('\n'):
                name = name.strip().lower()
                if not name or name.startswith('*'):
                    continue
                if not name.endswith(f".{domain}") and name != domain:
                    continue
                # Check if the subdomain part matches AI patterns
                subdomain_part = name.replace(f".{domain}", "")
                if self.AI_SUBDOMAIN_RE.search(subdomain_part):
                    ai_hosts.add(name)

        return ai_hosts

    def _load_ai_wordlist(self):
        """Load the AI subdomain wordlist."""
        words = []
        try:
            from importlib.resources import files
            with (files('spiderfoot.dicts') / 'ai-subdomains.txt').open('r') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
        except Exception as e:
            self.error(f"Failed to load AI subdomain wordlist: {e}")
        return words

    def _resolve_host(self, hostname):
        """Try to resolve a hostname. Returns True if it resolves."""
        try:
            addrs = self.sf.resolveHost(hostname)
            if addrs:
                return True
        except Exception:
            pass
        return False

    def _brute_subdomain(self, domain, word, resolved_hosts):
        """Try to resolve a single AI subdomain."""
        hostname = f"{word}.{domain}"
        if self._resolve_host(hostname):
            with self.lock:
                resolved_hosts.add(hostname)

    def _dns_bruteforce(self, domain):
        """Brute-force AI subdomains via DNS."""
        words = self._load_ai_wordlist()
        if not words:
            return set()

        resolved_hosts = set()
        threads = []

        for word in words:
            if self.checkForStop():
                break

            hostname = f"{word}.{domain}"
            if hostname in self.results:
                continue

            t = threading.Thread(
                target=self._brute_subdomain,
                args=(domain, word, resolved_hosts))
            t.daemon = True
            threads.append(t)

            if len(threads) >= self.opts['_maxthreads']:
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=30)
                threads = []

        # Process remaining threads
        if threads:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

        return resolved_hosts

    def _check_cloud_ai_cnames(self, hostname):
        """Check if a hostname CNAMEs to a known cloud AI service."""
        try:
            cnames = self.sf.resolveHost(hostname)
            if not cnames:
                return None
            for cname in cnames:
                if isinstance(cname, str):
                    for pattern in self.CLOUD_AI_PATTERNS:
                        if pattern.search(cname):
                            return cname
        except Exception:
            pass
        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Already processed {eventData}, skipping.")
            return

        self.results[eventData] = True

        domain = eventData
        ai_hosts = set()

        # Layer 3a: CT log discovery
        if self.opts['query_ct_logs']:
            self.info(f"Querying crt.sh for AI-related subdomains of {domain}")
            ct_hosts = self._query_crtsh(domain)
            ai_hosts.update(ct_hosts)
            if ct_hosts:
                self.info(f"Found {len(ct_hosts)} AI-related hosts in CT logs for {domain}")

        # Layer 3b: DNS brute-forcing
        if self.opts['dns_bruteforce']:
            self.info(f"Brute-forcing AI subdomains of {domain}")
            brute_hosts = self._dns_bruteforce(domain)
            ai_hosts.update(brute_hosts)
            if brute_hosts:
                self.info(f"Resolved {len(brute_hosts)} AI subdomains for {domain}")

        # Emit events for discovered AI hostnames
        for hostname in ai_hosts:
            if self.checkForStop():
                return

            if hostname in self.results:
                continue
            self.results[hostname] = True

            # Check if hostname resolves
            if self._resolve_host(hostname):
                evt = SpiderFootEvent(
                    "INTERNET_NAME", hostname, self.__name__, event)
                self.notifyListeners(evt)

                # Emit AI infrastructure hint
                subdomain_part = hostname.replace(f".{domain}", "")
                ai_evt = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED",
                    f"AI-related subdomain: {hostname} (pattern: {subdomain_part})",
                    self.__name__, evt)
                self.notifyListeners(ai_evt)

                # Check for cloud AI CNAME patterns
                if self.opts['check_cloud_patterns']:
                    cloud_cname = self._check_cloud_ai_cnames(hostname)
                    if cloud_cname:
                        cloud_evt = SpiderFootEvent(
                            "AI_INFRASTRUCTURE_DETECTED",
                            f"Cloud AI service: {hostname} -> {cloud_cname}",
                            self.__name__, evt)
                        self.notifyListeners(cloud_evt)
            else:
                evt = SpiderFootEvent(
                    "INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_ai_subdomain class
