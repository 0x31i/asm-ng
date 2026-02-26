# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_model_registry
# Purpose:     Detect exposed model registries and hubs (MLflow, HuggingFace,
#              NVIDIA NGC, BentoML, Triton) — probes registry endpoints and
#              enumerates accessible models.
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


class sfp_ai_model_registry(SpiderFootPlugin):

    meta = {
        'name': "AI Model Registry Scanner",
        'summary': "Detect exposed model registries and hubs (MLflow, HuggingFace, "
                   "NVIDIA NGC, BentoML, Triton). Probes registry API endpoints "
                   "and enumerates unauthenticated model access to identify "
                   "exposed model stores and serving infrastructure.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Probes for exposed model registry instances used in "
                           "ML model management and serving infrastructure. "
                           "Checks MLflow, HuggingFace Hub, OCI registries, "
                           "BentoML, and NVIDIA Triton endpoints.",
        }
    }

    # Registry probes: (port, path, response_check, service_name)
    REGISTRY_PROBES = [
        ('5000', '/api/2.0/mlflow/registered-models/search', 'registered_models', 'MLflow Model Registry'),
        ('8080', '/api/models', 'models', 'HuggingFace Hub (Private)'),
        ('8000', '/v2/_catalog', 'repositories', 'OCI Container/Model Registry'),
        ('3000', '/', None, 'BentoML'),
        ('8000', '/v2/repository/index', None, 'NVIDIA Triton Model Repository'),
        ('8001', '/v2/repository/index', None, 'NVIDIA Triton Model Repository'),
    ]

    opts = {
        'probe_timeout': 10,
        'enumerate_models': True,
    }

    optdescs = {
        'probe_timeout': "Timeout in seconds for each model registry probe.",
        'enumerate_models': "Attempt to enumerate model names from accessible registries.",
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
            "INTERNET_NAME",
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def producedEvents(self):
        return [
            "AI_MODEL_REGISTRY_EXPOSED",
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_ENDPOINT_UNAUTHENTICATED",
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

    def _probe_registry(self, host, port, path, response_check, service_name,
                        event, scheme):
        """Probe a single model registry endpoint and emit events on match.

        Returns True if the probe confirmed a model registry, False otherwise.
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
        headers = res.get('headers', {}) or {}

        if not code.startswith('2'):
            return False

        # BentoML detection (port 3000, no specific response_check key)
        if service_name == 'BentoML' and response_check is None and port == '3000':
            # Check content or headers for bentoml indicators
            content_lower = content.lower()
            headers_str = str(headers).lower()
            if 'bentoml' not in content_lower and 'bento' not in content_lower \
                    and 'bentoml' not in headers_str and 'bento' not in headers_str:
                return False

            detail = f"{service_name} detected on {host}:{port}"

            evt_registry = SpiderFootEvent(
                "AI_MODEL_REGISTRY_EXPOSED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt_registry)

            evt_infra = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                f"{service_name} model serving platform detected on {host}:{port}",
                self.__class__.__name__, event)
            self.notifyListeners(evt_infra)

            evt_unauth = SpiderFootEvent(
                "AI_ENDPOINT_UNAUTHENTICATED",
                f"{service_name} accessible without authentication on {host}:{port}",
                self.__class__.__name__, event)
            self.notifyListeners(evt_unauth)

            return True

        # NVIDIA Triton Model Repository (/v2/repository/index) — response
        # is a JSON array of model objects, no specific response_check key
        if 'Triton' in service_name and response_check is None:
            try:
                data = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                return False

            if not isinstance(data, list):
                return False

            model_count = len(data)
            if self.opts['enumerate_models'] and model_count > 0:
                names = []
                for item in data:
                    if isinstance(item, dict):
                        names.append(item.get('name', str(item)))
                    else:
                        names.append(str(item))
                detail = (f"{service_name} on {host}:{port} exposes "
                          f"{model_count} models: {', '.join(names[:10])}")
                if len(names) > 10:
                    detail += f" ... (+{len(names) - 10} more)"
            else:
                detail = f"{service_name} on {host}:{port} (repository index accessible)"

            evt_registry = SpiderFootEvent(
                "AI_MODEL_REGISTRY_EXPOSED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt_registry)

            evt_infra = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                f"{service_name} detected on {host}:{port}",
                self.__class__.__name__, event)
            self.notifyListeners(evt_infra)

            evt_unauth = SpiderFootEvent(
                "AI_ENDPOINT_UNAUTHENTICATED",
                f"{service_name} repository index accessible without "
                f"authentication on {host}:{port}",
                self.__class__.__name__, event)
            self.notifyListeners(evt_unauth)

            return True

        # JSON endpoints with a response_check key (MLflow, HuggingFace, OCI)
        if response_check:
            try:
                data = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                return False

            if not isinstance(data, dict) or response_check not in data:
                return False

            items = data.get(response_check, [])
            if not isinstance(items, list):
                return False

            item_count = len(items)
            if self.opts['enumerate_models'] and item_count > 0:
                names = []
                for item in items:
                    if isinstance(item, dict):
                        names.append(
                            item.get('name',
                                     item.get('id', str(item))))
                    else:
                        names.append(str(item))
                detail = (f"{service_name} on {host}:{port} exposes "
                          f"{item_count} models: {', '.join(names[:10])}")
                if len(names) > 10:
                    detail += f" ... (+{len(names) - 10} more)"
            else:
                detail = (f"{service_name} on {host}:{port} "
                          f"({response_check} endpoint accessible)")

            evt_registry = SpiderFootEvent(
                "AI_MODEL_REGISTRY_EXPOSED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt_registry)

            evt_infra = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                f"{service_name} detected on {host}:{port}",
                self.__class__.__name__, event)
            self.notifyListeners(evt_infra)

            evt_unauth = SpiderFootEvent(
                "AI_ENDPOINT_UNAUTHENTICATED",
                f"{service_name} {response_check} accessible without "
                f"authentication on {host}:{port}",
                self.__class__.__name__, event)
            self.notifyListeners(evt_unauth)

            return True

        return False

    def _probe_host_port(self, host, port, event):
        """Probe all matching REGISTRY_PROBES for a given host:port."""
        key = f"registry:{host}:{port}"
        if key in self.results:
            return
        self.results[key] = True

        matching_probes = [p for p in self.REGISTRY_PROBES if p[0] == port]
        if not matching_probes:
            return

        for scheme in ['http', 'https']:
            for probe_port, path, response_check, service_name in matching_probes:
                if self.checkForStop():
                    return
                self._probe_registry(
                    host, port, path, response_check, service_name,
                    event, scheme)

    def _probe_all_ports(self, host, event):
        """Probe all model registry ports against a host."""
        seen_ports = set()
        for probe_port, path, response_check, service_name in self.REGISTRY_PROBES:
            if probe_port in seen_ports:
                continue
            seen_ports.add(probe_port)

            if self.checkForStop():
                return

            key = f"registry:{host}:{probe_port}"
            if key in self.results:
                continue
            self.results[key] = True

            for scheme in ['http', 'https']:
                probes_for_port = [p for p in self.REGISTRY_PROBES
                                   if p[0] == probe_port]
                for _, p_path, p_check, p_svc in probes_for_port:
                    if self.checkForStop():
                        return
                    self._probe_registry(
                        host, probe_port, p_path, p_check, p_svc,
                        event, scheme)

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

            # Check if this port matches any registry probe port
            registry_ports = set(p[0] for p in self.REGISTRY_PROBES)
            if port not in registry_ports:
                return

            self._probe_host_port(host, port, event)

        elif eventName == "INTERNET_NAME":
            host = eventData.strip()

            key = f"registry:host:{host}"
            if key in self.results:
                return
            self.results[key] = True

            self._probe_all_ports(host, event)

        elif eventName == "AI_INFRASTRUCTURE_DETECTED":
            # Only process if it mentions relevant services
            data_lower = eventData.lower()
            if not any(kw in data_lower for kw in
                       ['mlflow', 'triton', 'bento', 'registry', 'model']):
                return

            host, port = self._extract_host_port(eventData)
            if not host:
                return

            if port:
                self._probe_host_port(host, port, event)
            else:
                # No port in the event data — probe all registry ports
                self._probe_all_ports(host, event)


# End of sfp_ai_model_registry class
