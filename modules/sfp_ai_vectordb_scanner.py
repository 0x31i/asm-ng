# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_vectordb_scanner
# Purpose:     Detect exposed vector databases (ChromaDB, Weaviate, Qdrant,
#              Milvus) used in RAG pipelines — probes health endpoints and
#              enumerates accessible collections/schemas.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_vectordb_scanner(SpiderFootPlugin):

    meta = {
        'name': "AI Vector Database Scanner",
        'summary': "Detect exposed vector databases (ChromaDB, Weaviate, Qdrant, "
                   "Milvus) commonly used in RAG pipelines. Probes health endpoints "
                   "and enumerates unauthenticated collection access to identify "
                   "exposed embedding stores and knowledge bases.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Probes for exposed vector database instances used in "
                           "RAG (Retrieval Augmented Generation) infrastructure. "
                           "Checks ChromaDB, Weaviate, Qdrant, and Milvus endpoints.",
        }
    }

    # Vector DB probes: (port, path, response_check_key, db_name, is_collection_list)
    VECTORDB_PROBES = [
        ('8000', '/api/v1/heartbeat', 'nanosecond', 'ChromaDB', False),
        ('8000', '/api/v1/collections', None, 'ChromaDB', True),
        ('8080', '/v1/.well-known/ready', None, 'Weaviate', False),
        ('8080', '/v1/schema', 'classes', 'Weaviate', True),
        ('6333', '/healthz', None, 'Qdrant', False),
        ('6333', '/collections', 'collections', 'Qdrant', True),
        ('9091', '/healthz', None, 'Milvus', False),
        ('19530', '/api/v1/health', None, 'Milvus', False),
    ]

    opts = {
        'probe_timeout': 10,
        'check_collection_data': True,
    }

    optdescs = {
        'probe_timeout': "Timeout in seconds for each vector DB probe.",
        'check_collection_data': "Check if collections contain accessible data.",
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
            "TCP_PORT_OPEN",
            "IP_ADDRESS",
            "INTERNET_NAME",
        ]

    def producedEvents(self):
        return [
            "AI_VECTORDB_EXPOSED",
            "AI_RAG_DATA_EXPOSED",
            "AI_ENDPOINT_UNAUTHENTICATED",
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def _extract_host_port(self, data):
        """Extract host:port from event data string."""
        # Try direct IP:port format
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        # Try hostname:port
        match = re.search(r'([\w.-]+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        return None, None

    def _probe_endpoint(self, host, port, path, response_check_key, db_name,
                        is_collection_list, event, scheme):
        """Probe a single vector DB endpoint and emit events on success.

        Returns True if the probe confirmed a vector database, False otherwise.
        """
        url = f"{scheme}://{host}:{port}{path}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=self.opts['probe_timeout'],
                useragent=self.opts.get('_useragent', 'ASM-NG')
            )
        except Exception:
            return False

        if not res:
            return False

        code = str(res.get('code', ''))
        content = res.get('content', '') or ''

        if not code.startswith('2'):
            return False

        # For health checks (is_collection_list=False), verify the response
        if not is_collection_list:
            if response_check_key:
                if response_check_key not in content:
                    return False

            # Health check passed — emit infrastructure detection
            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                f"{db_name} vector database detected on {host}:{port} "
                f"(health endpoint: {path})",
                self.__class__.__name__, event)
            self.notifyListeners(evt)
            return True

        # Collection listing (is_collection_list=True)
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return False

        # Validate the response has the expected key if specified
        if response_check_key:
            if isinstance(data, dict) and response_check_key not in data:
                return False

        # Determine if there are actual collections
        has_collections = False
        collection_info = ""

        if isinstance(data, list) and len(data) > 0:
            # ChromaDB returns a list of collections
            has_collections = True
            names = []
            for item in data:
                if isinstance(item, dict):
                    names.append(item.get('name', str(item)))
                else:
                    names.append(str(item))
            collection_info = f"{len(names)} collections: {', '.join(names[:10])}"
            if len(names) > 10:
                collection_info += f" ... (+{len(names) - 10} more)"

        elif isinstance(data, dict) and response_check_key:
            items = data.get(response_check_key, [])
            if isinstance(items, list) and len(items) > 0:
                has_collections = True
                names = []
                for item in items:
                    if isinstance(item, dict):
                        names.append(
                            item.get('name',
                                     item.get('class', str(item))))
                    else:
                        names.append(str(item))
                collection_info = (
                    f"{len(names)} collections: {', '.join(names[:10])}")
                if len(names) > 10:
                    collection_info += f" ... (+{len(names) - 10} more)"

        if has_collections and self.opts['check_collection_data']:
            # Exposed collections with data
            evt_exposed = SpiderFootEvent(
                "AI_VECTORDB_EXPOSED",
                f"{db_name} on {host}:{port} exposes {collection_info}",
                self.__class__.__name__, event)
            self.notifyListeners(evt_exposed)

            evt_rag = SpiderFootEvent(
                "AI_RAG_DATA_EXPOSED",
                f"RAG knowledge base data accessible via {db_name} on "
                f"{host}:{port} — {collection_info}",
                self.__class__.__name__, evt_exposed)
            self.notifyListeners(evt_rag)

            evt_unauth = SpiderFootEvent(
                "AI_ENDPOINT_UNAUTHENTICATED",
                f"{db_name} collection listing accessible without "
                f"authentication on {host}:{port}",
                self.__class__.__name__, evt_exposed)
            self.notifyListeners(evt_unauth)

            return True

        elif code.startswith('2'):
            # Endpoint responded but no collections (or empty)
            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                f"{db_name} vector database detected on {host}:{port} "
                f"(collection endpoint accessible: {path})",
                self.__class__.__name__, event)
            self.notifyListeners(evt)
            return True

        return False

    def _probe_host_port(self, host, port, event):
        """Probe all matching VECTORDB_PROBES for a given host:port."""
        key = f"vectordb:{host}:{port}"
        if key in self.results:
            return
        self.results[key] = True

        matching_probes = [p for p in self.VECTORDB_PROBES if p[0] == port]
        if not matching_probes:
            return

        for scheme in ['http', 'https']:
            for probe_port, path, response_check_key, db_name, is_collection_list in matching_probes:
                if self.checkForStop():
                    return
                self._probe_endpoint(
                    host, port, path, response_check_key, db_name,
                    is_collection_list, event, scheme)

    def _probe_all_ports(self, host, event):
        """Probe all vector DB ports against a host."""
        seen_ports = set()
        for probe_port, path, response_check_key, db_name, is_collection_list in self.VECTORDB_PROBES:
            if probe_port in seen_ports:
                continue
            seen_ports.add(probe_port)

            if self.checkForStop():
                return

            key = f"vectordb:{host}:{probe_port}"
            if key in self.results:
                continue
            self.results[key] = True

            for scheme in ['http', 'https']:
                probes_for_port = [p for p in self.VECTORDB_PROBES
                                   if p[0] == probe_port]
                for _, p_path, p_check_key, p_db_name, p_is_coll in probes_for_port:
                    if self.checkForStop():
                        return
                    self._probe_endpoint(
                        host, probe_port, p_path, p_check_key, p_db_name,
                        p_is_coll, event, scheme)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventName == "TCP_PORT_OPEN":
            host, port = self._extract_host_port(eventData)
            if not host or not port:
                return

            # Check if this port matches any vector DB probe port
            vectordb_ports = set(p[0] for p in self.VECTORDB_PROBES)
            if port not in vectordb_ports:
                return

            self._probe_host_port(host, port, event)

        elif eventName in ["IP_ADDRESS", "INTERNET_NAME"]:
            host = eventData.strip()

            key = f"vectordb:host:{host}"
            if key in self.results:
                return
            self.results[key] = True

            self._probe_all_ports(host, event)


# End of sfp_ai_vectordb_scanner class
