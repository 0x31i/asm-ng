# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_ct_deep
# Purpose:     Deep mining of Certificate Transparency logs for AI-related
#              subdomains, wildcard certs, and historical AI infrastructure.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_ct_deep(SpiderFootPlugin):

    meta = {
        'name': "Deep CT Log AI Mining",
        'summary': "Deep-mines Certificate Transparency logs for AI-related "
                   "subdomains and infrastructure. Queries crt.sh with 25+ "
                   "AI-specific prefix patterns (ml.*, ai.*, model.*, "
                   "inference.*, llm.*, jupyter.*, etc.), analyzes cert "
                   "metadata including issuers and validity timelines, and "
                   "detects wildcard certs that imply AI infrastructure scale.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://crt.sh",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Queries the crt.sh Certificate Transparency log "
                           "aggregator with AI-specific subdomain patterns to "
                           "discover AI infrastructure certificates.",
        }
    }

    # AI-specific subdomain prefixes to query in CT logs
    CT_AI_PREFIXES = [
        'ml', 'ai', 'model', 'inference', 'llm', 'gpu', 'serving',
        'triton', 'ollama', 'mlflow', 'jupyter', 'notebook', 'vector',
        'rag', 'embedding', 'agent', 'mcp', 'chat', 'genai',
        'deeplearning', 'predict', 'training', 'finetune', 'huggingface',
        'bedrock',
    ]

    # Map prefix patterns to infrastructure categories
    CT_AI_CATEGORIES = {
        'inference': ['inference', 'serving', 'triton', 'ollama', 'predict', 'llm', 'model'],
        'training': ['training', 'finetune', 'gpu', 'deeplearning'],
        'data': ['vector', 'rag', 'embedding', 'mlflow'],
        'agent': ['agent', 'mcp', 'chat', 'genai'],
        'platform': ['ai', 'ml', 'jupyter', 'notebook', 'huggingface', 'bedrock'],
    }

    opts = {
        'max_queries_per_domain': 25,
        'check_wildcards': True,
        'historical_lookback': True,
    }

    optdescs = {
        'max_queries_per_domain': "Maximum number of crt.sh queries per domain "
                                  "to avoid rate limiting.",
        'check_wildcards': "Analyze wildcard certificates for AI subdomain coverage.",
        'historical_lookback': "Include expired certificates for historical evidence.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["AI_INFRASTRUCTURE_DETECTED", "AI_HISTORICAL_EVIDENCE"]

    def _categorize_prefix(self, prefix):
        """Return the infrastructure category for a given prefix."""
        for category, prefixes in self.CT_AI_CATEGORIES.items():
            if prefix in prefixes:
                return category
        return 'platform'

    def _query_crtsh(self, pattern, domain):
        """Query crt.sh for certificates matching a pattern.

        Returns:
            list: List of certificate entries, or empty list on failure.
        """
        url = f"https://crt.sh/?q={pattern}.{domain}&output=json"

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return []

        try:
            certs = json.loads(res['content'])
            if isinstance(certs, list):
                return certs
        except (json.JSONDecodeError, ValueError):
            pass

        return []

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Dedup by domain
        if eventData in self.results:
            self.debug(f"Already processed {eventData}, skipping.")
            return
        self.results[eventData] = True

        domain = eventData
        all_findings = {}
        wildcard_findings = []
        query_count = 0

        for prefix in self.CT_AI_PREFIXES:
            if self.checkForStop():
                return

            if query_count >= self.opts['max_queries_per_domain']:
                self.debug(f"Reached max queries ({self.opts['max_queries_per_domain']}) "
                           f"for {domain}, stopping.")
                break

            query_count += 1
            pattern = f"%.{prefix}" if prefix else prefix
            certs = self._query_crtsh(prefix, domain)

            if not certs:
                continue

            # Rate-limit to be polite to crt.sh
            time.sleep(1)

            for cert in certs:
                common_name = cert.get('common_name', '')
                name_value = cert.get('name_value', '')
                issuer = cert.get('issuer_name', '')
                not_before = cert.get('not_before', '')
                not_after = cert.get('not_after', '')
                cert_id = cert.get('id', '')

                # Skip if not actually matching our AI prefix
                names = f"{common_name} {name_value}".lower()
                if f"{prefix}." not in names and f"*.{prefix}." not in names:
                    continue

                category = self._categorize_prefix(prefix)
                finding_key = f"{common_name}:{cert_id}"

                if finding_key not in all_findings:
                    all_findings[finding_key] = {
                        'common_name': common_name,
                        'names': name_value,
                        'issuer': issuer,
                        'not_before': not_before,
                        'not_after': not_after,
                        'prefix': prefix,
                        'category': category,
                    }

                # Track wildcard certs
                if self.opts['check_wildcards'] and '*' in common_name:
                    wildcard_findings.append({
                        'common_name': common_name,
                        'prefix': prefix,
                        'category': category,
                    })

        if not all_findings:
            self.debug(f"No AI-related certificates found for {domain}.")
            return

        # Group findings by category
        by_category = {}
        for finding in all_findings.values():
            cat = finding['category']
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(finding)

        # Emit AI_INFRASTRUCTURE_DETECTED for each category group
        for category, findings in by_category.items():
            if self.checkForStop():
                return

            names = list(set(f['common_name'] for f in findings))
            detail = (f"CT log AI infrastructure ({category}): "
                      f"{len(findings)} cert(s) for {domain} — "
                      f"{', '.join(names[:10])}")
            if len(names) > 10:
                detail += f" (+{len(names) - 10} more)"

            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

        # Emit wildcard cert findings
        if wildcard_findings:
            unique_wildcards = list(set(
                f['common_name'] for f in wildcard_findings
            ))
            detail = (f"Wildcard certs covering AI subdomains for {domain}: "
                      f"{', '.join(unique_wildcards[:10])}")

            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

        # Emit historical evidence with timeline
        if self.opts['historical_lookback']:
            earliest = None
            for finding in all_findings.values():
                nb = finding.get('not_before', '')
                if nb and (earliest is None or nb < earliest):
                    earliest = nb

            if earliest:
                detail = (f"Historical CT evidence for {domain}: "
                          f"AI infrastructure first seen in certificates "
                          f"from {earliest[:10]}, {len(all_findings)} "
                          f"total AI-related cert(s) found across "
                          f"{len(by_category)} category(ies)")

                evt = SpiderFootEvent(
                    "AI_HISTORICAL_EVIDENCE",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)


# End of sfp_ai_ct_deep class
