# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_bom
# Purpose:     Aggregate all AI scan findings into a structured, machine-readable
#              AI Bill of Materials (AI-BOM) inventory.
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


class sfp_ai_bom(SpiderFootPlugin):

    meta = {
        'name': "AI Bill of Materials Generator",
        'summary': "Aggregates all AI scan findings into a structured, "
                   "machine-readable AI Bill of Materials (AI-BOM) inventory "
                   "covering models, endpoints, agents, vector databases, "
                   "compute clusters, data pipelines, and shadow AI services.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Reporting and Analysis"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Aggregates findings from all AI discovery modules "
                           "into a single AI Bill of Materials (AI-BOM) JSON "
                           "document. No external tools or API keys required; "
                           "operates purely on events produced by other modules.",
        }
    }

    opts = {
        'min_components': 1,
        'include_software': True,
    }

    optdescs = {
        'min_components': "Minimum number of AI components to trigger BOM generation.",
        'include_software': "Include SOFTWARE_USED events that reference AI frameworks.",
    }

    results = None
    errorState = False

    # AI-related keywords for filtering SOFTWARE_USED events
    AI_SOFTWARE_KEYWORDS = [
        'ollama', 'mlflow', 'triton', 'vllm', 'ray', 'gradio',
        'jupyter', 'mcp', 'langchain', 'openai', 'anthropic',
        'huggingface', 'tensorflow', 'pytorch', 'comfyui',
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._components = []
        self._bom_generated = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_MODEL_EXPOSED",
            "AI_ENDPOINT_UNAUTHENTICATED",
            "AI_MCP_SERVER_EXPOSED",
            "AI_VECTORDB_EXPOSED",
            "AI_AGENT_INFRASTRUCTURE_DETECTED",
            "AI_COMPUTE_CLUSTER_EXPOSED",
            "AI_DATA_PIPELINE_EXPOSED",
            "AI_MODEL_REGISTRY_EXPOSED",
            "AI_SHADOW_SERVICE_DETECTED",
            "AI_VENDOR_WIDGET_DETECTED",
            "AI_HISTORICAL_EVIDENCE",
            "SOFTWARE_USED",
        ]

    def producedEvents(self):
        return []

    def _classify_component(self, event_type):
        """Map an event type to an AI-BOM component type string."""
        mapping = {
            'AI_MODEL_EXPOSED': 'inference_endpoint',
            'AI_ENDPOINT_UNAUTHENTICATED': 'unauthenticated_endpoint',
            'AI_MCP_SERVER_EXPOSED': 'mcp_server',
            'AI_VECTORDB_EXPOSED': 'vector_database',
            'AI_AGENT_INFRASTRUCTURE_DETECTED': 'agent_framework',
            'AI_COMPUTE_CLUSTER_EXPOSED': 'gpu_cluster',
            'AI_DATA_PIPELINE_EXPOSED': 'data_pipeline',
            'AI_MODEL_REGISTRY_EXPOSED': 'model_registry',
            'AI_SHADOW_SERVICE_DETECTED': 'shadow_ai_service',
            'AI_VENDOR_WIDGET_DETECTED': 'vendor_widget',
            'AI_HISTORICAL_EVIDENCE': 'historical_evidence',
            'AI_INFRASTRUCTURE_DETECTED': 'ai_infrastructure',
            'SOFTWARE_USED': 'software',
        }
        return mapping.get(event_type, 'unknown')

    def _extract_location(self, data):
        """Try to extract a host:port string from event data."""
        # Match IP:port
        match = re.search(r'(\d+\.\d+\.\d+\.\d+:\d+)', data)
        if match:
            return match.group(1)
        # Match hostname:port
        match = re.search(r'([\w.-]+:\d+)', data)
        if match:
            return match.group(1)
        return ""

    def _generate_bom(self, event):
        """Build the AI-BOM JSON structure and emit it as an event."""
        bom = {
            "ai_bom_version": "1.0",
            "target": self.getTarget().targetValue if self.getTarget() else "unknown",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "components": self._components,
            "summary": {
                "total_components": len(self._components),
                "unauthenticated": sum(
                    1 for c in self._components
                    if not c.get('authenticated', True)
                ),
                "by_type": {}
            }
        }

        # Count components by type
        for component in self._components:
            ctype = component.get('type', 'unknown')
            bom["summary"]["by_type"][ctype] = \
                bom["summary"]["by_type"].get(ctype, 0) + 1

        self._bom_json = json.dumps(bom)
        self.debug(f"AI-BOM generated with {len(self._components)} components")

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # For SOFTWARE_USED, only process if it references AI frameworks
        if eventName == "SOFTWARE_USED":
            if not self.opts['include_software']:
                return
            data_lower = eventData.lower()
            if not any(kw in data_lower for kw in self.AI_SOFTWARE_KEYWORDS):
                return

        # Dedup using a hash of the event data
        event_key = f"{eventName}:{eventData[:200]}"
        if event_key in self.results:
            self.debug(f"Already processed {event_key}, skipping.")
            return
        self.results[event_key] = True

        # Build component entry
        component = {
            "type": self._classify_component(eventName),
            "name": eventData[:100],
            "location": self._extract_location(eventData),
            "authenticated": eventName != 'AI_ENDPOINT_UNAUTHENTICATED',
            "source_event": eventName,
        }

        self._components.append(component)

        self.debug(f"AI-BOM: accumulated {len(self._components)} component(s)")

        # Generate BOM once threshold is met, then re-generate on each
        # subsequent component (event data will differ so DB dedup is fine)
        if len(self._components) >= self.opts['min_components']:
            self._generate_bom(event)
            self._bom_generated = True


# End of sfp_ai_bom class
