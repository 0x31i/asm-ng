# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_agent_mapper
# Purpose:     Detect agentic AI infrastructure (CrewAI, LangServe, AutoGen,
#              Semantic Kernel, Google A2A Protocol) by probing known agent
#              framework endpoints on discovered hosts and open ports.
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


class sfp_ai_agent_mapper(SpiderFootPlugin):

    meta = {
        'name': "AI Agent Infrastructure Mapper",
        'summary': "Detect agentic AI frameworks (CrewAI, LangServe, AutoGen, "
                   "Semantic Kernel, Google A2A Protocol) by probing known "
                   "agent orchestration endpoints on discovered hosts and "
                   "open ports.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Probes for agentic AI infrastructure by sending "
                           "HTTP requests to known framework-specific API "
                           "paths for CrewAI, LangServe, AutoGen, Semantic "
                           "Kernel, and the Google A2A protocol.",
        }
    }

    # Agent framework probe definitions.
    # Each tuple: (path, response_check_key, framework_name)
    # If response_check_key is None, any 2xx response confirms the framework.
    # If set, the key must appear in the parsed JSON response body.
    AGENT_PROBES = [
        ('/crew/kickoff', None, 'CrewAI'),
        ('/api/v1/crews', 'crews', 'CrewAI'),
        ('/invoke', None, 'LangServe'),
        ('/playground', None, 'LangServe'),
        ('/docs', 'openapi', 'LangServe/FastAPI'),
        ('/api/agents', 'agents', 'AutoGen'),
        ('/api/skills', 'skills', 'Semantic Kernel'),
        ('/api/planner', None, 'Semantic Kernel'),
        ('/.well-known/agent.json', 'agent', 'A2A Protocol'),
    ]

    # Ports commonly used by agent frameworks
    AGENT_CANDIDATE_PORTS = [
        '80', '443', '3000', '8000', '8080', '8888', '5000', '4000'
    ]

    opts = {
        'probe_timeout': 10,
        'check_a2a_protocol': True,
    }

    optdescs = {
        'probe_timeout': "Timeout in seconds for each agent framework probe.",
        'check_a2a_protocol': "Check for Google A2A (Agent-to-Agent) protocol endpoints.",
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
            "AI_AGENT_INFRASTRUCTURE_DETECTED",
            "AI_AGENT_TOOL_EXPOSED",
            "AI_ENDPOINT_UNAUTHENTICATED",
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def _extract_host_port(self, data):
        """Extract host and port from event data string."""
        # Try direct IP:port format
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        # Try hostname:port
        match = re.search(r'([\w.-]+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        return None, None

    def _probe_agent_endpoints(self, host, port, event):
        """Probe a host:port for agent framework endpoints.

        Tries both HTTP and HTTPS schemes. Emits events for any confirmed
        agent infrastructure.
        """
        for scheme in ['http', 'https']:
            base_url = f"{scheme}://{host}:{port}"

            for path, check_key, framework in self.AGENT_PROBES:
                if self.checkForStop():
                    return

                # Skip A2A probes if disabled
                if framework == 'A2A Protocol' and not self.opts['check_a2a_protocol']:
                    continue

                url = f"{base_url}{path}"
                self.debug(f"Probing {url} for {framework}")

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

                # Must be a 2xx response to consider it a hit
                if not code.startswith('2'):
                    continue

                confirmed = False

                if check_key is None:
                    # Any 2xx response confirms the framework
                    confirmed = True
                else:
                    # The check_key must appear in the JSON response
                    try:
                        body = json.loads(content)
                        if isinstance(body, dict) and check_key in body:
                            confirmed = True
                    except (json.JSONDecodeError, ValueError):
                        # Also check raw content as fallback
                        if check_key.lower() in content.lower():
                            confirmed = True

                if not confirmed:
                    continue

                self.debug(f"Confirmed {framework} on {host}:{port}{path} ({scheme})")

                # --- Emit AI_INFRASTRUCTURE_DETECTED ---
                evt_infra = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED",
                    f"{framework} agent infrastructure detected on "
                    f"{host}:{port} ({scheme}) via {path}",
                    self.__class__.__name__, event)
                self.notifyListeners(evt_infra)

                # --- Emit AI_AGENT_INFRASTRUCTURE_DETECTED ---
                evt_agent = SpiderFootEvent(
                    "AI_AGENT_INFRASTRUCTURE_DETECTED",
                    f"{framework} on {host}:{port}{path} ({scheme})",
                    self.__class__.__name__, evt_infra)
                self.notifyListeners(evt_agent)

                # --- Handle A2A Protocol specifically ---
                if framework == 'A2A Protocol':
                    self._process_a2a(content, host, port, scheme, evt_infra)

                # --- Check for exposed tools/skills in JSON responses ---
                self._check_exposed_tools(
                    content, framework, host, port, scheme, path, evt_infra)

    def _process_a2a(self, content, host, port, scheme, parent_event):
        """Process a confirmed A2A agent.json response.

        Extracts agent capabilities and emits detailed events.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(data, dict):
            return

        agent_info = data.get('agent', data)
        agent_name = agent_info.get('name', 'Unknown Agent')
        capabilities = agent_info.get('capabilities', [])
        skills = agent_info.get('skills', [])

        detail_parts = [f"A2A Agent '{agent_name}' on {host}:{port} ({scheme})"]

        if capabilities:
            if isinstance(capabilities, list):
                cap_names = [str(c) for c in capabilities[:10]]
                detail_parts.append(f"Capabilities: {', '.join(cap_names)}")

        if skills:
            if isinstance(skills, list):
                skill_names = []
                for s in skills[:10]:
                    if isinstance(s, dict):
                        skill_names.append(s.get('name', str(s)))
                    else:
                        skill_names.append(str(s))
                detail_parts.append(f"Skills: {', '.join(skill_names)}")

                # Skills listed means tools are exposed
                evt_tool = SpiderFootEvent(
                    "AI_AGENT_TOOL_EXPOSED",
                    f"A2A Agent '{agent_name}' exposes {len(skills)} skills "
                    f"on {host}:{port} ({scheme})",
                    self.__class__.__name__, parent_event)
                self.notifyListeners(evt_tool)

                evt_unauth = SpiderFootEvent(
                    "AI_ENDPOINT_UNAUTHENTICATED",
                    f"A2A Agent '{agent_name}' skills accessible without auth "
                    f"on {host}:{port}",
                    self.__class__.__name__, evt_tool)
                self.notifyListeners(evt_unauth)

    def _check_exposed_tools(self, content, framework, host, port,
                             scheme, path, parent_event):
        """Check if the response contains exposed tools or skills.

        Looks for common agent framework response patterns that list
        available tools, skills, or agents.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(data, dict):
            return

        # Look for tool/skill/agent lists in the response
        tool_keys = ['tools', 'skills', 'agents', 'crews', 'functions',
                     'actions', 'plugins']
        for key in tool_keys:
            items = data.get(key)
            if not items or not isinstance(items, list):
                continue
            if len(items) == 0:
                continue

            # Extract names from the items
            names = []
            for item in items[:20]:
                if isinstance(item, dict):
                    name = item.get('name', item.get('id',
                           item.get('title', str(item)[:50])))
                    names.append(str(name))
                elif isinstance(item, str):
                    names.append(item)

            if not names:
                continue

            name_list = ', '.join(names[:10])
            if len(names) > 10:
                name_list += f' (+{len(names) - 10} more)'

            evt_tool = SpiderFootEvent(
                "AI_AGENT_TOOL_EXPOSED",
                f"{framework} on {host}:{port}{path} exposes "
                f"{len(items)} {key}: {name_list}",
                self.__class__.__name__, parent_event)
            self.notifyListeners(evt_tool)

            evt_unauth = SpiderFootEvent(
                "AI_ENDPOINT_UNAUTHENTICATED",
                f"{framework} {key} accessible without auth on "
                f"{host}:{port}{path} ({scheme})",
                self.__class__.__name__, evt_tool)
            self.notifyListeners(evt_unauth)

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

            # Only probe candidate agent ports
            if port not in self.AGENT_CANDIDATE_PORTS:
                return

            key = f"agent:{host}:{port}"
            if key in self.results:
                return
            self.results[key] = True

            self._probe_agent_endpoints(host, port, event)

        elif eventName == "INTERNET_NAME":
            key = f"agent:hostname:{eventData}"
            if key in self.results:
                return
            self.results[key] = True

            for port in self.AGENT_CANDIDATE_PORTS:
                if self.checkForStop():
                    return

                port_key = f"agent:{eventData}:{port}"
                if port_key in self.results:
                    continue
                self.results[port_key] = True

                self._probe_agent_endpoints(eventData, port, event)

        elif eventName == "AI_INFRASTRUCTURE_DETECTED":
            # Only process if it mentions agent-related keywords
            lower_data = eventData.lower()
            if not any(kw in lower_data for kw in ['agent', 'langserve', 'crewai']):
                return

            host, port = self._extract_host_port(eventData)
            if not host:
                return

            key = f"agent:{host}:{port}"
            if key in self.results:
                return
            self.results[key] = True

            self._probe_agent_endpoints(host, port, event)


# End of sfp_ai_agent_mapper class
