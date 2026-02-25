# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_mcp_detect
# Purpose:     Deep MCP (Model Context Protocol) server enumeration via
#              JSON-RPC 2.0 probing — discovers exposed tools, resources,
#              and prompts on MCP servers.
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


class sfp_ai_mcp_detect(SpiderFootPlugin):

    meta = {
        'name': "AI MCP Server Detector",
        'summary': "Deep MCP (Model Context Protocol) server detection via "
                   "JSON-RPC 2.0 probing. Enumerates exposed tools, resources, "
                   "and prompts on discovered MCP endpoints.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://modelcontextprotocol.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Probes for MCP servers using JSON-RPC 2.0 protocol "
                           "methods (tools/list, resources/list, prompts/list, "
                           "rpc.discover) and SSE transport detection.",
        }
    }

    # JSON-RPC 2.0 methods to probe, in order
    MCP_METHODS = [
        ("rpc.discover", None, "JSON-RPC capability discovery"),
        ("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "asm-ng-scanner", "version": "1.0"}
        }, "MCP initialize handshake"),
        ("tools/list", None, "MCP tools enumeration"),
        ("resources/list", None, "MCP resources enumeration"),
        ("prompts/list", None, "MCP prompts enumeration"),
    ]

    # Candidate ports where MCP servers commonly run
    MCP_CANDIDATE_PORTS = ['80', '443', '3000', '8000', '8080', '3001',
                           '4000', '5000', '8888']

    # Paths to try for MCP endpoints
    MCP_PATHS = ['/', '/mcp', '/api/mcp', '/rpc', '/jsonrpc']

    opts = {
        'probe_timeout': 15,
        'check_sse_transport': True,
        'max_tools_to_list': 50,
    }

    optdescs = {
        'probe_timeout': "Timeout in seconds for each MCP probe request.",
        'check_sse_transport': "Check for SSE (Server-Sent Events) MCP transport endpoints.",
        'max_tools_to_list': "Maximum number of tool/resource names to include in event data.",
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
            "AI_INFRASTRUCTURE_DETECTED",
            "TCP_PORT_OPEN",
            "INTERNET_NAME",
        ]

    def producedEvents(self):
        return [
            "AI_MCP_SERVER_EXPOSED",
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_ENDPOINT_UNAUTHENTICATED",
            "SOFTWARE_USED",
        ]

    def _build_jsonrpc_request(self, method, params=None, req_id=1):
        """Build a well-formed JSON-RPC 2.0 request payload."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": req_id,
        }
        if params is not None:
            payload["params"] = params
        return json.dumps(payload)

    def _probe_mcp_endpoint(self, base_url, path="/"):
        """Send JSON-RPC 2.0 probes to a potential MCP endpoint.

        Returns a dict of successful method → response data, or empty dict.
        """
        url = f"{base_url.rstrip('/')}{path}"
        found = {}
        req_id = 1

        for method, params, desc in self.MCP_METHODS:
            payload = self._build_jsonrpc_request(method, params, req_id)
            req_id += 1

            try:
                res = self.sf.fetchUrl(
                    url,
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts.get('_useragent', 'ASM-NG'),
                    postData=payload,
                    headers={'Content-Type': 'application/json'}
                )
            except Exception:
                continue

            if not res or not res.get('content'):
                # A 200 with no content on initialize could still mean MCP
                if res and res.get('code') and str(res['code']) == '200':
                    if method == 'initialize':
                        found[method] = {}
                continue

            content = res['content']

            # Check for valid JSON-RPC response
            try:
                resp = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                continue

            # JSON-RPC 2.0 responses have "jsonrpc" key
            if isinstance(resp, dict) and resp.get('jsonrpc') == '2.0':
                if 'result' in resp:
                    found[method] = resp['result']
                elif 'error' in resp:
                    # Even an error response confirms JSON-RPC is active
                    err = resp['error']
                    # Method not found is normal; other errors confirm MCP
                    if isinstance(err, dict):
                        code = err.get('code', 0)
                        # -32601 = method not found — try next method
                        if code == -32601:
                            continue
                        # Other errors mean server is responding to JSON-RPC
                        found[method] = {'_error': err}

        return found

    def _check_sse_transport(self, base_url):
        """Check for SSE-based MCP transport endpoints."""
        for path in ['/sse', '/events', '/mcp/sse']:
            url = f"{base_url.rstrip('/')}{path}"
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

            # Check content type for SSE
            headers = res.get('headers', {}) or {}
            content_type = ''
            for k, v in headers.items():
                if k.lower() == 'content-type':
                    content_type = v.lower()
                    break

            if 'text/event-stream' in content_type:
                return path

            # Also check content for SSE markers
            content = res.get('content', '') or ''
            if content.startswith('data:') or 'event:' in content[:200]:
                return path

        return None

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

    def _truncate_list(self, items, max_items=None):
        """Truncate a list for display, adding '...' if needed."""
        if max_items is None:
            max_items = self.opts['max_tools_to_list']
        if len(items) <= max_items:
            return ', '.join(str(i) for i in items)
        shown = ', '.join(str(i) for i in items[:max_items])
        return f"{shown}, ... (+{len(items) - max_items} more)"

    def _process_mcp_results(self, host_port, results, event, scheme="http"):
        """Process MCP probe results and emit events."""
        if not results:
            return

        # If we got ANY successful JSON-RPC response, it's an MCP server
        evt_infra = SpiderFootEvent(
            "AI_INFRASTRUCTURE_DETECTED",
            f"MCP Server detected on {host_port} ({scheme})",
            self.__class__.__name__, event)
        self.notifyListeners(evt_infra)

        evt_sw = SpiderFootEvent(
            "SOFTWARE_USED",
            "MCP Server (Model Context Protocol)",
            self.__class__.__name__, evt_infra)
        self.notifyListeners(evt_sw)

        # Process tools/list
        tools_result = results.get('tools/list', {})
        if isinstance(tools_result, dict) and '_error' not in tools_result:
            tools = tools_result.get('tools', [])
            if isinstance(tools, list) and tools:
                tool_names = [t.get('name', 'unknown') for t in tools
                              if isinstance(t, dict)]
                detail = (f"MCP Server at {host_port} exposes "
                          f"{len(tool_names)} tools: "
                          f"{self._truncate_list(tool_names)}")
                evt = SpiderFootEvent(
                    "AI_MCP_SERVER_EXPOSED", detail,
                    self.__class__.__name__, evt_infra)
                self.notifyListeners(evt)

                # Unauthenticated tool access is critical
                evt_unauth = SpiderFootEvent(
                    "AI_ENDPOINT_UNAUTHENTICATED",
                    f"MCP tools accessible without auth on {host_port}",
                    self.__class__.__name__, evt)
                self.notifyListeners(evt_unauth)

        # Process resources/list
        res_result = results.get('resources/list', {})
        if isinstance(res_result, dict) and '_error' not in res_result:
            resources = res_result.get('resources', [])
            if isinstance(resources, list) and resources:
                res_names = [r.get('uri', r.get('name', 'unknown'))
                             for r in resources if isinstance(r, dict)]
                detail = (f"MCP Server at {host_port} exposes "
                          f"{len(res_names)} resources: "
                          f"{self._truncate_list(res_names)}")
                evt = SpiderFootEvent(
                    "AI_MCP_SERVER_EXPOSED", detail,
                    self.__class__.__name__, evt_infra)
                self.notifyListeners(evt)

        # Process prompts/list
        prompts_result = results.get('prompts/list', {})
        if isinstance(prompts_result, dict) and '_error' not in prompts_result:
            prompts = prompts_result.get('prompts', [])
            if isinstance(prompts, list) and prompts:
                prompt_names = [p.get('name', 'unknown') for p in prompts
                                if isinstance(p, dict)]
                detail = (f"MCP Server at {host_port} exposes "
                          f"{len(prompt_names)} prompts: "
                          f"{self._truncate_list(prompt_names)}")
                evt = SpiderFootEvent(
                    "AI_MCP_SERVER_EXPOSED", detail,
                    self.__class__.__name__, evt_infra)
                self.notifyListeners(evt)

        # Process initialize response
        init_result = results.get('initialize', {})
        if isinstance(init_result, dict) and '_error' not in init_result:
            caps = init_result.get('capabilities', {})
            server_info = init_result.get('serverInfo', {})
            if server_info:
                name = server_info.get('name', '')
                version = server_info.get('version', '')
                if name:
                    detail = f"MCP Server: {name}"
                    if version:
                        detail += f" v{version}"
                    detail += f" on {host_port}"
                    evt = SpiderFootEvent(
                        "SOFTWARE_USED", detail,
                        self.__class__.__name__, evt_infra)
                    self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventName == "AI_INFRASTRUCTURE_DETECTED":
            # Only process if it mentions MCP
            if 'mcp' not in eventData.lower():
                return

            host, port = self._extract_host_port(eventData)
            if not host:
                return

            key = f"mcp:{host}:{port}"
            if key in self.results:
                return
            self.results[key] = True

            for scheme in ['http', 'https']:
                base_url = f"{scheme}://{host}:{port}"
                for path in self.MCP_PATHS:
                    results = self._probe_mcp_endpoint(base_url, path)
                    if results:
                        self._process_mcp_results(
                            f"{host}:{port}", results, event, scheme)

                        if self.opts['check_sse_transport']:
                            sse_path = self._check_sse_transport(base_url)
                            if sse_path:
                                evt = SpiderFootEvent(
                                    "AI_MCP_SERVER_EXPOSED",
                                    f"MCP SSE transport at {host}:{port}{sse_path}",
                                    self.__class__.__name__, event)
                                self.notifyListeners(evt)
                        return  # Found on this scheme, done

        elif eventName == "TCP_PORT_OPEN":
            host, port = self._extract_host_port(eventData)
            if not host or not port:
                return

            # Only probe candidate MCP ports
            if port not in self.MCP_CANDIDATE_PORTS:
                return

            key = f"mcp:{host}:{port}"
            if key in self.results:
                return
            self.results[key] = True

            for scheme in ['http', 'https']:
                base_url = f"{scheme}://{host}:{port}"
                for path in self.MCP_PATHS:
                    if self.checkForStop():
                        return
                    results = self._probe_mcp_endpoint(base_url, path)
                    if results:
                        self._process_mcp_results(
                            f"{host}:{port}", results, event, scheme)

                        if self.opts['check_sse_transport']:
                            sse_path = self._check_sse_transport(base_url)
                            if sse_path:
                                evt = SpiderFootEvent(
                                    "AI_MCP_SERVER_EXPOSED",
                                    f"MCP SSE transport at {host}:{port}{sse_path}",
                                    self.__class__.__name__, event)
                                self.notifyListeners(evt)
                        return

        elif eventName == "INTERNET_NAME":
            # Probe common ports on discovered hostnames
            key = f"mcp:hostname:{eventData}"
            if key in self.results:
                return
            self.results[key] = True

            for port in self.MCP_CANDIDATE_PORTS:
                if self.checkForStop():
                    return
                for scheme in ['http', 'https']:
                    base_url = f"{scheme}://{eventData}:{port}"
                    results = self._probe_mcp_endpoint(base_url, '/')
                    if results:
                        self._process_mcp_results(
                            f"{eventData}:{port}", results, event, scheme)
                        break  # Found on this port/scheme


# End of sfp_ai_mcp_detect class
