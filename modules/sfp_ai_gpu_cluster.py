# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_gpu_cluster
# Purpose:     Detect exposed GPU/compute cluster management interfaces
#              (NVIDIA DCGM, SLURM, Ray, Determined AI, Kubeflow) on the
#              external attack surface.
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


class sfp_ai_gpu_cluster(SpiderFootPlugin):

    meta = {
        'name': "AI GPU Cluster Scanner",
        'summary': "Detect exposed GPU/compute cluster management interfaces "
                   "including NVIDIA DCGM Exporter, SLURM REST API, Ray "
                   "Dashboard, Determined AI, and Kubeflow Pipelines.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Probes for exposed GPU and compute cluster "
                           "management interfaces by sending HTTP requests "
                           "to known service ports and API paths.",
        }
    }

    # GPU/Compute cluster probes: (port, path, response_check, service_name)
    # response_check is matched against response content (text for metrics,
    # JSON key for API endpoints).
    GPU_PROBES = [
        ('9400', '/metrics', 'DCGM_FI_DEV_GPU_UTIL', 'NVIDIA DCGM Exporter'),
        ('6817', '/slurm/v0.0.39/diag', 'meta', 'SLURM REST API'),
        ('8265', '/api/nodes', 'data', 'Ray Dashboard'),
        ('8080', '/api/v1/experiments', 'experiments', 'Determined AI'),
        ('8080', '/pipeline/apis/v2beta1/pipelines', 'pipelines', 'Kubeflow Pipelines'),
    ]

    opts = {
        'probe_timeout': 10,
        'check_prometheus_metrics': True,
    }

    optdescs = {
        'probe_timeout': "Timeout in seconds for each GPU cluster probe.",
        'check_prometheus_metrics': "Parse Prometheus metrics endpoints for GPU utilization data.",
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
            "AI_COMPUTE_CLUSTER_EXPOSED",
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_ENDPOINT_UNAUTHENTICATED",
        ]

    def _extract_host_port(self, data):
        """Extract host and port from event data string."""
        # Try IP:port
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        # Try hostname:port
        match = re.search(r'([\w.-]+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        return None, None

    def _probe_service(self, host, port, path, response_check, service_name, event):
        """Probe a single GPU/compute service endpoint.

        Tries http first, then https. For DCGM (port 9400) the response is
        Prometheus text metrics; for all others the response is expected to
        be JSON containing the response_check key.

        Returns True if the service was detected.
        """
        for scheme in ['http', 'https']:
            if self.checkForStop():
                return False

            url = f"{scheme}://{host}:{port}{path}"

            try:
                res = self.sf.fetchUrl(
                    url,
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts.get('_useragent', 'ASM-NG')
                )
            except Exception:
                continue

            if not res:
                continue

            code = str(res.get('code', ''))
            content = res.get('content', '') or ''

            if not code.startswith('2'):
                continue

            detected = False

            # DCGM Exporter returns Prometheus text metrics, not JSON
            if port == '9400':
                if response_check in content:
                    detected = True

                    # Optionally extract GPU utilization metrics
                    if self.opts['check_prometheus_metrics']:
                        gpu_lines = []
                        for line in content.split('\n'):
                            if line.startswith('DCGM_FI_DEV_GPU_UTIL'):
                                gpu_lines.append(line.strip())
                        if gpu_lines:
                            metrics_summary = '; '.join(gpu_lines[:5])
                            if len(gpu_lines) > 5:
                                metrics_summary += f' (+{len(gpu_lines) - 5} more)'
                            detail = (f"{service_name} on {host}:{port} - "
                                      f"GPU metrics exposed: {metrics_summary}")
                        else:
                            detail = (f"{service_name} on {host}:{port} - "
                                      f"Prometheus metrics endpoint exposed")
                    else:
                        detail = (f"{service_name} on {host}:{port} - "
                                  f"Prometheus metrics endpoint exposed")
            else:
                # JSON API endpoints
                try:
                    data = json.loads(content)
                except (json.JSONDecodeError, ValueError):
                    continue

                if isinstance(data, dict) and response_check in data:
                    detected = True
                    detail = (f"{service_name} on {host}:{port} - "
                              f"API responded with '{response_check}' key")
                elif isinstance(data, list):
                    # Some APIs return a list at top level
                    detected = True
                    detail = (f"{service_name} on {host}:{port} - "
                              f"API responded with list data")

            if detected:
                # Emit AI_COMPUTE_CLUSTER_EXPOSED
                evt_cluster = SpiderFootEvent(
                    "AI_COMPUTE_CLUSTER_EXPOSED",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt_cluster)

                # Emit AI_INFRASTRUCTURE_DETECTED
                evt_infra = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED",
                    f"{service_name} detected on {host}:{port} ({scheme})",
                    self.__class__.__name__, event)
                self.notifyListeners(evt_infra)

                # Emit AI_ENDPOINT_UNAUTHENTICATED
                evt_unauth = SpiderFootEvent(
                    "AI_ENDPOINT_UNAUTHENTICATED",
                    f"{service_name} on {host}:{port} accessible without authentication",
                    self.__class__.__name__, event)
                self.notifyListeners(evt_unauth)

                return True

        return False

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

            # Only probe GPU_PROBES entries whose port matches
            matching_probes = [p for p in self.GPU_PROBES if p[0] == port]
            if not matching_probes:
                return

            for probe_port, path, response_check, service_name in matching_probes:
                if self.checkForStop():
                    return

                key = f"gpu:{host}:{port}:{path}"
                if key in self.results:
                    continue
                self.results[key] = True

                self._probe_service(
                    host, port, path, response_check, service_name, event)

        elif eventName in ("IP_ADDRESS", "INTERNET_NAME"):
            host = eventData

            for probe_port, path, response_check, service_name in self.GPU_PROBES:
                if self.checkForStop():
                    return

                key = f"gpu:{host}:{probe_port}:{path}"
                if key in self.results:
                    continue
                self.results[key] = True

                self._probe_service(
                    host, probe_port, path, response_check, service_name, event)


# End of sfp_ai_gpu_cluster class
