# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_vulnscan
# Purpose:     AI-specific vulnerability scanning using Nuclei with
#              protectai/ai-exploits templates, with built-in fallback
#              checks when Nuclei is not installed.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import os
import re
import shutil
import sys
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_vulnscan(SpiderFootPlugin):

    meta = {
        'name': "AI Vulnerability Scanner",
        'summary': "Scan confirmed AI infrastructure for known vulnerabilities "
                   "using Nuclei with AI-specific templates (protectai/ai-exploits). "
                   "Falls back to built-in HTTP checks when Nuclei is unavailable.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://github.com/protectai/ai-exploits",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Uses Nuclei vulnerability scanner with AI-specific "
                           "templates from protectai/ai-exploits to check for "
                           "known CVEs and misconfigurations in AI/ML services.",
        }
    }

    # Built-in vulnerability checks (used when Nuclei is not available)
    # Each: (path, method, expected_in_response, vuln_name, severity, description)
    BUILTIN_CHECKS = [
        ('/api/2.0/mlflow/experiments/list', 'GET', '"experiments"',
         'MLflow Unauthenticated Access', 'HIGH',
         'MLflow tracking server accessible without authentication. '
         'Exposes experiment data, model artifacts, and dataset references.'),
        ('/api/tags', 'GET', '"models"',
         'Ollama Unauthenticated Access', 'HIGH',
         'Ollama LLM server accessible without authentication. '
         'Allows model listing, inference, and potential model theft.'),
        ('/api/cluster_status', 'GET', '"result"',
         'Ray Dashboard Unauthenticated', 'CRITICAL',
         'Ray Dashboard exposed without authentication. '
         'Known RCE vulnerability history (CVE-2023-48022/CVE-2023-6019).'),
        ('/info', 'GET', '"version"',
         'Gradio Interface Exposed', 'MEDIUM',
         'Gradio ML demo interface exposed. Check for SSRF and '
         'file access vulnerabilities.'),
        ('/api/kernels', 'GET', '[',
         'Jupyter Notebook Unauthenticated', 'CRITICAL',
         'Jupyter Notebook accessible without authentication. '
         'Allows arbitrary code execution on the server.'),
        ('/v1/models', 'GET', '"data"',
         'OpenAI-Compatible API Unauthenticated', 'HIGH',
         'OpenAI-compatible inference API accessible without authentication. '
         'Allows model listing and inference.'),
        ('/api/system', 'GET', '',
         'AnythingLLM Unauthenticated', 'HIGH',
         'AnythingLLM server accessible without authentication.'),
        ('/api/v1/collections', 'GET', '[',
         'ChromaDB Unauthenticated', 'HIGH',
         'ChromaDB vector database accessible without authentication. '
         'Exposes RAG knowledge base data.'),
        ('/v1/schema', 'GET', '"classes"',
         'Weaviate Unauthenticated', 'HIGH',
         'Weaviate vector database accessible without authentication. '
         'Exposes vector collections and schema.'),
        ('/collections', 'GET', '"result"',
         'Qdrant Unauthenticated', 'HIGH',
         'Qdrant vector database accessible without authentication.'),
    ]

    opts = {
        'nuclei_path': '',
        'ai_template_path': '',
        'fallback_checks': True,
        'scan_timeout': 300,
    }

    optdescs = {
        'nuclei_path': "Path to the Nuclei binary. Leave empty to use built-in checks only.",
        'ai_template_path': "Path to AI-specific Nuclei templates (e.g., protectai/ai-exploits).",
        'fallback_checks': "Run built-in HTTP vulnerability checks when Nuclei is unavailable.",
        'scan_timeout': "Maximum time in seconds for a Nuclei scan per target.",
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
            "AI_ENDPOINT_UNAUTHENTICATED",
        ]

    def producedEvents(self):
        return [
            "AI_LLM_VULN_DETECTED",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
        ]

    def _extract_host_port_scheme(self, data):
        """Extract host, port, and scheme from event data."""
        # Try to find scheme://host:port pattern
        match = re.search(r'(https?)://([^/:]+):(\d+)', data)
        if match:
            return match.group(2), match.group(3), match.group(1)

        # Try IP:port pattern
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', data)
        if match:
            return match.group(1), match.group(2), 'http'

        # Try hostname:port
        match = re.search(r'([\w.-]+):(\d+)', data)
        if match:
            return match.group(1), match.group(2), 'http'

        return None, None, None

    def _run_nuclei(self, target, event):
        """Run Nuclei with AI-specific templates against a target."""
        exe = self.opts['nuclei_path']
        if exe and not os.path.isfile(exe):
            # Try as command name
            resolved = shutil.which(exe)
            if resolved:
                exe = resolved
            else:
                self.debug(f"Nuclei not found at {exe}")
                return False

        if not exe:
            exe = shutil.which('nuclei')
            if not exe:
                return False

        template_path = self.opts.get('ai_template_path', '')
        args = [
            exe,
            "-silent",
            "-json",
            "-concurrency", "50",
            "-retries", "1",
            "-no-interactsh",
        ]

        if template_path and os.path.exists(template_path):
            args.extend(["-t", template_path])
        else:
            # Use tag-based filtering for AI templates
            args.extend(["-tags", "ai,ml,llm,mlflow,ollama,ray,triton,jupyter"])

        try:
            p = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(
                    input=target.encode(sys.stdin.encoding or 'utf-8'),
                    timeout=self.opts['scan_timeout']
                )
                if p.returncode != 0:
                    self.debug(f"Nuclei exited with code {p.returncode}")
                    return False
                content = stdout.decode(sys.stdout.encoding or 'utf-8')
            except TimeoutExpired:
                p.kill()
                p.communicate()
                self.debug("Nuclei scan timed out")
                return False
        except Exception as e:
            self.error(f"Failed to run Nuclei: {e}")
            return False

        if not content:
            return True  # Ran successfully but no findings

        self._parse_nuclei_output(content, event)
        return True

    def _parse_nuclei_output(self, content, event):
        """Parse Nuclei JSON-line output into events."""
        for line in content.split("\n"):
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            template_name = data.get('info', {}).get('name', 'Unknown')
            template_id = data.get('template-id', '')
            severity = data.get('info', {}).get('severity', 'info')
            matched_at = data.get('matched-at', '')

            # Check for CVEs
            cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", line)
            if cve_matches:
                for cve in cve_matches:
                    etype, cvetext = self.sf.cveInfo(cve)
                    evt = SpiderFootEvent(
                        etype, cvetext, self.__class__.__name__, event)
                    self.notifyListeners(evt)
            else:
                # Map severity to event type
                if severity == 'critical':
                    etype = "VULNERABILITY_CVE_CRITICAL"
                elif severity == 'high':
                    etype = "VULNERABILITY_CVE_HIGH"
                elif severity == 'medium':
                    etype = "VULNERABILITY_CVE_MEDIUM"
                elif severity == 'low':
                    etype = "VULNERABILITY_CVE_LOW"
                else:
                    etype = "VULNERABILITY_GENERAL"

                detail = f"Template: {template_name} ({template_id})\n"
                detail += f"Severity: {severity}\n"
                detail += f"Matched at: {matched_at}\n"

                refs = data.get('info', {}).get('reference', [])
                if refs and isinstance(refs, list):
                    detail += f"Reference: <SFURL>{refs[0]}</SFURL>"

                evt = SpiderFootEvent(etype, detail, self.__class__.__name__, event)
                self.notifyListeners(evt)

            # Also emit AI-specific vuln event
            ai_detail = f"{template_name} [{severity}] on {matched_at}"
            evt_ai = SpiderFootEvent(
                "AI_LLM_VULN_DETECTED", ai_detail, self.__class__.__name__, event)
            self.notifyListeners(evt_ai)

    def _run_builtin_checks(self, host, port, scheme, event):
        """Run built-in HTTP vulnerability checks."""
        base_url = f"{scheme}://{host}:{port}"

        for path, method, expected, vuln_name, severity, description in self.BUILTIN_CHECKS:
            if self.checkForStop():
                return

            url = f"{base_url}{path}"
            check_key = f"check:{host}:{port}{path}"
            if check_key in self.results:
                continue
            self.results[check_key] = True

            try:
                res = self.sf.fetchUrl(
                    url,
                    timeout=15,
                    useragent=self.opts.get('_useragent', 'ASM-NG')
                )
            except Exception:
                continue

            if not res:
                continue

            code = str(res.get('code', ''))
            content = res.get('content', '') or ''

            # Check for successful response
            is_vuln = False
            if code.startswith('2'):  # 2xx status
                if expected:
                    if expected.lower() in content.lower():
                        is_vuln = True
                else:
                    # Empty expected means any 200 is a finding
                    is_vuln = True

            if is_vuln:
                # Map severity to event type
                severity_map = {
                    'CRITICAL': 'VULNERABILITY_CVE_CRITICAL',
                    'HIGH': 'VULNERABILITY_CVE_HIGH',
                    'MEDIUM': 'VULNERABILITY_CVE_MEDIUM',
                    'LOW': 'VULNERABILITY_CVE_LOW',
                }
                etype = severity_map.get(severity, 'VULNERABILITY_GENERAL')

                detail = f"Vulnerability: {vuln_name}\n"
                detail += f"Severity: {severity}\n"
                detail += f"URL: {url}\n"
                detail += f"Description: {description}"

                evt = SpiderFootEvent(etype, detail, self.__class__.__name__, event)
                self.notifyListeners(evt)

                # AI-specific event
                ai_detail = f"{vuln_name} [{severity}] on {host}:{port}"
                evt_ai = SpiderFootEvent(
                    "AI_LLM_VULN_DETECTED", ai_detail, self.__class__.__name__, event)
                self.notifyListeners(evt_ai)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Don't process our own events
        if event.module == self.__class__.__name__:
            return

        host, port, scheme = self._extract_host_port_scheme(eventData)
        if not host:
            return

        key = f"vulnscan:{host}:{port}"
        if key in self.results:
            return
        self.results[key] = True

        target = f"{scheme}://{host}:{port}"

        # Try Nuclei first
        nuclei_ran = self._run_nuclei(target, event)

        # If Nuclei didn't run (not installed), use built-in checks
        if not nuclei_ran and self.opts['fallback_checks']:
            self._run_builtin_checks(host, port, scheme, event)


# End of sfp_ai_vulnscan class
