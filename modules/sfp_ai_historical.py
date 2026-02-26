# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_historical
# Purpose:     Query the Wayback Machine for historical evidence of AI
#              infrastructure — past SDK usage, removed chatbot widgets,
#              old config files, and previously exposed AI endpoints.
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


class sfp_ai_historical(SpiderFootPlugin):

    meta = {
        'name': "Historical AI Infrastructure Evidence",
        'summary': "Queries the Wayback Machine for historical evidence of AI "
                   "infrastructure. Searches archived URLs for AI-related "
                   "paths (/api/v1/chat/completions, /v1/models, "
                   "/.well-known/agent.json, /ollama/, /ml/, etc.), analyzes "
                   "archived snapshots for removed AI SDK script tags, and "
                   "tracks the timeline of AI adoption and infrastructure "
                   "changes over time.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://web.archive.org",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Queries the Wayback Machine CDX API to find "
                           "historical snapshots of AI-related URLs and "
                           "analyzes archived content for AI infrastructure "
                           "evidence.",
        }
    }

    # AI-related URL path patterns to search in the archive
    HISTORICAL_AI_PATHS = [
        '/api/v1/chat/completions',
        '/v1/models',
        '/v1/completions',
        '/v1/embeddings',
        '/.well-known/agent.json',
        '/.well-known/ai-plugin.json',
        '/api/generate',
        '/ollama/',
        '/ml/',
        '/ai/',
        '/inference/',
        '/model/',
        '/api/chat',
        '/openai/',
        '/langchain/',
        '/jupyter/',
        '/notebook/',
        '/mlflow/',
        '/triton/',
        '/gradio/',
        '/streamlit/',
    ]

    # AI script/SDK patterns to detect in archived HTML
    HISTORICAL_AI_SCRIPTS = [
        re.compile(r'openai\.com/v1', re.I),
        re.compile(r'cdn\.openai\.com', re.I),
        re.compile(r'anthropic\.com', re.I),
        re.compile(r'huggingface\.co', re.I),
        re.compile(r'tensorflow\.js|tfjs', re.I),
        re.compile(r'cdn\.jsdelivr\.net.*onnxruntime', re.I),
        re.compile(r'langchain', re.I),
        re.compile(r'llamaindex', re.I),
        re.compile(r'pinecone\.io', re.I),
        re.compile(r'weaviate\.io', re.I),
        re.compile(r'qdrant\.io', re.I),
        re.compile(r'chromadb', re.I),
        re.compile(r'gradio\.app', re.I),
        re.compile(r'streamlit\.io', re.I),
        re.compile(r'replicate\.com', re.I),
        re.compile(r'cohere\.ai', re.I),
    ]

    CDX_API_BASE = "https://web.archive.org/cdx/search/cdx"

    opts = {
        'max_snapshots': 50,
        'lookback_years': 3,
        'fetch_archived_content': True,
    }

    optdescs = {
        'max_snapshots': "Maximum number of archived URLs to analyze per domain.",
        'lookback_years': "How far back (in years) to search in the Wayback Machine.",
        'fetch_archived_content': "Fetch and analyze archived page content (slower "
                                  "but provides richer findings).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return ["AI_HISTORICAL_EVIDENCE", "AI_INFRASTRUCTURE_DETECTED"]

    def _query_cdx(self, domain):
        """Query the Wayback Machine CDX API for archived AI-related URLs.

        Returns:
            list: List of [timestamp, original_url, statuscode, mimetype] entries.
        """
        url = (f"{self.CDX_API_BASE}?url={domain}/*&output=json"
               f"&fl=timestamp,original,statuscode,mimetype"
               f"&filter=statuscode:200&limit={self.opts['max_snapshots'] * 5}")

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            return []

        try:
            rows = json.loads(res['content'])
            if isinstance(rows, list) and len(rows) > 1:
                # First row is headers
                return rows[1:]
        except (json.JSONDecodeError, ValueError):
            pass

        return []

    def _filter_ai_urls(self, cdx_rows):
        """Filter CDX results for AI-related URL paths."""
        ai_urls = []

        for row in cdx_rows:
            if len(row) < 2:
                continue
            original_url = row[1].lower()

            for path in self.HISTORICAL_AI_PATHS:
                if path.lower() in original_url:
                    ai_urls.append({
                        'timestamp': row[0],
                        'url': row[1],
                        'statuscode': row[2] if len(row) > 2 else '',
                        'mimetype': row[3] if len(row) > 3 else '',
                        'matched_path': path,
                    })
                    break

        return ai_urls[:self.opts['max_snapshots']]

    def _fetch_archived_page(self, timestamp, url):
        """Fetch an archived page from the Wayback Machine."""
        archive_url = f"https://web.archive.org/web/{timestamp}/{url}"

        res = self.sf.fetchUrl(
            archive_url,
            timeout=20,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if res and res.get('content'):
            return res['content']
        return None

    def _scan_archived_content(self, content):
        """Scan archived HTML for AI SDK/script patterns.

        Returns:
            list: List of matched SDK/framework names.
        """
        matches = []
        for pattern in self.HISTORICAL_AI_SCRIPTS:
            if pattern.search(content):
                matches.append(pattern.pattern)
        return matches

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

        # Query CDX API
        self.info(f"Querying Wayback Machine for {domain}")
        cdx_rows = self._query_cdx(domain)

        if not cdx_rows:
            self.debug(f"No Wayback Machine data for {domain}.")
            return

        # Filter for AI-related URLs
        ai_urls = self._filter_ai_urls(cdx_rows)

        if ai_urls:
            # Group by matched path
            by_path = {}
            earliest_timestamp = None
            for entry in ai_urls:
                path = entry['matched_path']
                if path not in by_path:
                    by_path[path] = []
                by_path[path].append(entry)

                ts = entry['timestamp']
                if earliest_timestamp is None or ts < earliest_timestamp:
                    earliest_timestamp = ts

            # Emit findings for each path group
            for path, entries in by_path.items():
                if self.checkForStop():
                    return

                timestamps = sorted(set(e['timestamp'][:8] for e in entries))
                detail = (f"Historical AI URL found in Wayback Machine for "
                          f"{domain}: {path} — {len(entries)} snapshot(s) "
                          f"from {timestamps[0]} to {timestamps[-1]}")

                evt = SpiderFootEvent(
                    "AI_HISTORICAL_EVIDENCE",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

            # Emit summary infrastructure finding
            detail = (f"Wayback Machine AI evidence for {domain}: "
                      f"{len(ai_urls)} archived AI URL(s) across "
                      f"{len(by_path)} path pattern(s), earliest from "
                      f"{earliest_timestamp[:8] if earliest_timestamp else 'unknown'}")

            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

        # Optionally fetch and analyze archived content
        if self.opts['fetch_archived_content'] and ai_urls:
            sdk_findings = set()
            analyzed = 0

            for entry in ai_urls[:10]:  # Limit to 10 fetches
                if self.checkForStop():
                    return

                content = self._fetch_archived_page(
                    entry['timestamp'], entry['url'])

                if not content:
                    continue

                analyzed += 1
                matches = self._scan_archived_content(content)
                for match in matches:
                    sdk_findings.add(match)

                # Rate-limit
                time.sleep(1)

            if sdk_findings:
                detail = (f"AI SDKs/frameworks in archived pages for "
                          f"{domain}: {', '.join(list(sdk_findings)[:15])} "
                          f"(from {analyzed} archived page(s))")

                evt = SpiderFootEvent(
                    "AI_HISTORICAL_EVIDENCE",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)


# End of sfp_ai_historical class
