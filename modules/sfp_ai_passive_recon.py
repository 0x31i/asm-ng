# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_passive_recon
# Purpose:     Discover AI/ML infrastructure via Shodan and Censys AI-specific
#              dork queries, scoped to the scan target's IP space.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_passive_recon(SpiderFootPlugin):

    meta = {
        'name': "AI Passive Recon",
        'summary': "Discover AI/ML infrastructure via Shodan and Censys "
                   "AI-specific search dorks scoped to the target's IP space.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.shodan.io/",
            'model': "FREE_AUTH_LIMITED",
            'description': "Queries Shodan and Censys with AI-specific "
                           "search dorks (Ollama, MLflow, Triton, vLLM, "
                           "Ray, Gradio, Jupyter, ComfyUI, etc.) scoped "
                           "to the target's IP ranges and hostnames.",
        }
    }

    # Shodan dorks: each is (query_template, service_name)
    # {target} is replaced with the scoped IP/net/hostname filter
    SHODAN_AI_DORKS = [
        ('port:11434 "Ollama" {target}', 'Ollama'),
        ('http.title:"MLflow" port:5000 {target}', 'MLflow'),
        ('http.title:"Ray Dashboard" {target}', 'Ray Dashboard'),
        ('"tritonserver" port:8000 {target}', 'NVIDIA Triton'),
        ('http.title:"Gradio" {target}', 'Gradio'),
        ('http.title:"Jupyter" port:8888 {target}', 'Jupyter Notebook'),
        ('port:8265 "ray" {target}', 'Ray Cluster'),
        ('"v1/models" port:8000 {target}', 'OpenAI-Compatible API'),
        ('http.title:"ComfyUI" {target}', 'ComfyUI'),
        ('http.title:"Open WebUI" {target}', 'Open WebUI'),
        ('"litellm" port:4000 {target}', 'LiteLLM'),
    ]

    opts = {
        'shodan_api_key': '',
        'censys_api_key_uid': '',
        'censys_api_key_secret': '',
        'delay': 1.0,
        'max_results_per_dork': 100,
    }

    optdescs = {
        'shodan_api_key': "Shodan API key for AI-specific passive reconnaissance.",
        'censys_api_key_uid': "Censys API UID for AI-specific passive reconnaissance.",
        'censys_api_key_secret': "Censys API secret for AI-specific passive reconnaissance.",
        'delay': "Delay in seconds between API requests to respect rate limits.",
        'max_results_per_dork': "Maximum number of results to process per search dork.",
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
            "IP_ADDRESS",
            "NETBLOCK_OWNER",
            "DOMAIN_NAME",
            "INTERNET_NAME",
        ]

    def producedEvents(self):
        return [
            "AI_PASSIVE_RECON_HIT",
            "AI_INFRASTRUCTURE_DETECTED",
            "TCP_PORT_OPEN",
            "SOFTWARE_USED",
        ]

    def _query_shodan(self, query, event):
        """Run a Shodan search query and emit events for each result."""
        api_key = self.opts.get('shodan_api_key', '')
        if not api_key:
            return

        encoded = urllib.parse.quote(query)
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={encoded}&minify=true"

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return

        try:
            data = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            self.debug(f"Failed to parse Shodan response for query: {query}")
            return

        if 'error' in data:
            self.debug(f"Shodan API error: {data['error']}")
            return

        matches = data.get('matches', [])
        count = 0
        for match in matches:
            if count >= self.opts['max_results_per_dork']:
                break

            ip = match.get('ip_str', '')
            port = str(match.get('port', ''))
            if not ip or not port:
                continue

            key = f"{ip}:{port}"
            if key in self.results:
                continue
            self.results[key] = True
            count += 1

            product = match.get('product', '')
            org = match.get('org', '')

            # Emit TCP_PORT_OPEN so sfp_ai_fingerprint can do active probing
            evt_port = SpiderFootEvent(
                "TCP_PORT_OPEN", key, self.__class__.__name__, event)
            self.notifyListeners(evt_port)

            # Emit AI_PASSIVE_RECON_HIT with details
            detail = f"Shodan: {product or 'AI service'} on {key}"
            if org:
                detail += f" (org: {org})"
            evt_hit = SpiderFootEvent(
                "AI_PASSIVE_RECON_HIT", detail, self.__class__.__name__, event)
            self.notifyListeners(evt_hit)

            # Emit AI_INFRASTRUCTURE_DETECTED
            evt_ai = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                f"AI service detected via passive recon on {key}",
                self.__class__.__name__, evt_hit)
            self.notifyListeners(evt_ai)

    def _query_censys(self, target_filter, event):
        """Run Censys search queries for AI services."""
        uid = self.opts.get('censys_api_key_uid', '')
        secret = self.opts.get('censys_api_key_secret', '')
        if not uid or not secret:
            return

        # AI-specific Censys queries
        ai_queries = [
            f'services.port: 11434 AND services.banner: "Ollama" AND {target_filter}',
            f'services.port: 5000 AND services.http.response.html_title: "MLflow" AND {target_filter}',
            f'services.port: 8000 AND services.banner: "triton" AND {target_filter}',
            f'services.port: 8265 AND services.banner: "ray" AND {target_filter}',
            f'services.port: 7860 AND services.http.response.html_title: "Gradio" AND {target_filter}',
        ]

        import base64
        auth_str = base64.b64encode(f"{uid}:{secret}".encode()).decode()

        for query in ai_queries:
            url = "https://search.censys.io/api/v2/hosts/search"
            post_data = json.dumps({"q": query, "per_page": 25})

            res = self.sf.fetchUrl(
                url,
                timeout=30,
                useragent=self.opts.get('_useragent', 'ASM-NG'),
                postData=post_data,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Basic {auth_str}'
                }
            )

            if not res or not res.get('content'):
                continue

            try:
                data = json.loads(res['content'])
            except (json.JSONDecodeError, ValueError):
                continue

            for hit in data.get('result', {}).get('hits', []):
                ip = hit.get('ip', '')
                if not ip:
                    continue

                for svc in hit.get('services', []):
                    port = str(svc.get('port', ''))
                    if not port:
                        continue

                    key = f"{ip}:{port}"
                    if key in self.results:
                        continue
                    self.results[key] = True

                    evt_port = SpiderFootEvent(
                        "TCP_PORT_OPEN", key, self.__class__.__name__, event)
                    self.notifyListeners(evt_port)

                    svc_name = svc.get('service_name', 'AI service')
                    evt_hit = SpiderFootEvent(
                        "AI_PASSIVE_RECON_HIT",
                        f"Censys: {svc_name} on {key}",
                        self.__class__.__name__, event)
                    self.notifyListeners(evt_hit)

                    evt_ai = SpiderFootEvent(
                        "AI_INFRASTRUCTURE_DETECTED",
                        f"AI service detected via passive recon on {key}",
                        self.__class__.__name__, evt_hit)
                    self.notifyListeners(evt_ai)

            time.sleep(self.opts['delay'])

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

        has_shodan = bool(self.opts.get('shodan_api_key'))
        has_censys = bool(self.opts.get('censys_api_key_uid')
                         and self.opts.get('censys_api_key_secret'))

        if not has_shodan and not has_censys:
            self.debug("No Shodan or Censys API keys configured, skipping.")
            return

        # Build target scope filter
        if eventName == "IP_ADDRESS":
            shodan_filter = f"net:{eventData}"
            censys_filter = f"ip: {eventData}"
        elif eventName == "NETBLOCK_OWNER":
            shodan_filter = f"net:{eventData}"
            censys_filter = f"ip: {eventData}"
        elif eventName in ("DOMAIN_NAME", "INTERNET_NAME"):
            shodan_filter = f"hostname:{eventData}"
            censys_filter = f"dns.names: {eventData}"
        else:
            return

        # Run Shodan dorks
        if has_shodan:
            for dork_template, svc_name in self.SHODAN_AI_DORKS:
                if self.checkForStop():
                    return
                query = dork_template.format(target=shodan_filter)
                self._query_shodan(query, event)
                time.sleep(self.opts['delay'])

        # Run Censys queries
        if has_censys:
            self._query_censys(censys_filter, event)


# End of sfp_ai_passive_recon class
