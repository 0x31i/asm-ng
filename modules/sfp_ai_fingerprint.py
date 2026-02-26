# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_fingerprint
# Purpose:     Detect and fingerprint AI/ML inference infrastructure on the
#              external attack surface by analyzing open ports and banners,
#              then actively probing with framework-specific HTTP requests.
#
# Author:      ASM-NG Enhancement Team
#
# Created:     2026-02-20
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_fingerprint(SpiderFootPlugin):

    meta = {
        'name': "AI Infrastructure Fingerprinter",
        'summary': "Detect and fingerprint exposed AI/ML inference services "
            "(Ollama, Triton, vLLM, LiteLLM, LocalAI, TorchServe, MLflow, "
            "BentoML, Gradio, ComfyUI, Stable Diffusion WebUI, Weaviate, "
            "ChromaDB, Milvus, Qdrant, Open WebUI, AnythingLLM, LangServe, "
            "TabbyAPI, and more) by analyzing open ports, banners, and "
            "sending framework-specific HTTP probes with graphw00f-style "
            "backend differentiation.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://github.com/Tencent/AI-Infra-Guard",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Identifies AI/ML serving infrastructure on the "
                "external attack surface using port analysis, banner "
                "fingerprinting, and active HTTP probes based on known "
                "framework API paths. Methodology informed by Cisco Talos "
                "research on exposed AI endpoints and Tencent AI-Infra-Guard "
                "fingerprint rules.",
        }
    }

    # Default options
    opts = {
        'active_fingerprint': True,
        'check_auth': True,
        'probe_timeout': 15,
    }

    # Option descriptions
    optdescs = {
        'active_fingerprint': "Send HTTP probes to confirm AI framework identity. "
            "Disable for passive-only detection from banners and port numbers.",
        'check_auth': "After identifying an AI endpoint, check whether it "
            "allows unauthenticated access to models and inference.",
        'probe_timeout': "Timeout in seconds for each fingerprint HTTP probe.",
    }

    results = None
    errorState = False

    # Known AI service ports mapped to their likely frameworks.
    # A port appearing here triggers active fingerprinting.
    AI_PORTS = {
        '11434': ['ollama'],
        '8000': ['triton', 'vllm', 'fastapi_ml', 'chromadb'],
        '8001': ['triton_grpc'],
        '8002': ['triton_metrics'],
        '8501': ['tfserving', 'streamlit'],
        '8500': ['tfserving_grpc'],
        '8080': ['torchserve', 'weaviate', 'open_webui', 'langserve'],
        '8081': ['torchserve_mgmt'],
        '5000': ['mlflow'],
        '3000': ['bentoml', 'open_webui', 'flowise'],
        '7860': ['gradio', 'stable_diffusion_webui'],
        '8265': ['ray_dashboard'],
        '1234': ['lm_studio'],
        '8888': ['jupyter'],
        '6333': ['qdrant'],
        '6334': ['qdrant_grpc'],
        '19530': ['milvus'],
        '9091': ['milvus_metrics'],
        '8188': ['comfyui'],
        '3001': ['anythingllm'],
        '7861': ['text_generation_webui'],
        '4000': ['litellm'],
        '5002': ['tabbyapi'],
        '3100': ['dify'],
        '9400': ['dcgm_exporter'],
        '6817': ['slurm_controller'],
        '6818': ['slurm_daemon'],
    }

    # Banner substrings that suggest AI infrastructure regardless of port.
    AI_BANNER_PATTERNS = [
        (re.compile(r'ollama', re.I), 'Ollama'),
        (re.compile(r'triton\s*inference\s*server|tritonserver|nv-status', re.I), 'NVIDIA Triton'),
        (re.compile(r'vllm|vllm-engine', re.I), 'vLLM'),
        (re.compile(r'torchserve', re.I), 'TorchServe'),
        (re.compile(r'mlflow', re.I), 'MLflow'),
        (re.compile(r'bentoml', re.I), 'BentoML'),
        (re.compile(r'gradio', re.I), 'Gradio'),
        (re.compile(r'ray\s*dashboard', re.I), 'Ray Dashboard'),
        (re.compile(r'streamlit', re.I), 'Streamlit'),
        (re.compile(r'jupyter|jupyterhub', re.I), 'Jupyter'),
        (re.compile(r'hugging\s*face|text-generation-inference', re.I), 'HuggingFace TGI'),
        (re.compile(r'localai', re.I), 'LocalAI'),
        (re.compile(r'lm\s*studio', re.I), 'LM Studio'),
        (re.compile(r'comfyui', re.I), 'ComfyUI'),
        (re.compile(r'langserve|langchain', re.I), 'LangServe'),
        # New banner patterns
        (re.compile(r'stable\s*diffusion|automatic1111|sd-webui', re.I), 'Stable Diffusion WebUI'),
        (re.compile(r'anythingllm', re.I), 'AnythingLLM'),
        (re.compile(r'open\s*webui', re.I), 'Open WebUI'),
        (re.compile(r'litellm', re.I), 'LiteLLM'),
        (re.compile(r'tabbyapi|tabby-api', re.I), 'TabbyAPI'),
        (re.compile(r'text-generation-webui|oobabooga', re.I), 'text-generation-webui'),
        (re.compile(r'chromadb|chroma', re.I), 'ChromaDB'),
        (re.compile(r'weaviate', re.I), 'Weaviate'),
        (re.compile(r'milvus', re.I), 'Milvus'),
        (re.compile(r'flowise', re.I), 'Flowise'),
        (re.compile(r'dify', re.I), 'Dify'),
        (re.compile(r'koboldai|koboldcpp', re.I), 'KoboldAI'),
        (re.compile(r'label.?studio', re.I), 'Label Studio'),
        (re.compile(r'airflow', re.I), 'Apache Airflow'),
    ]

    # Framework-specific probe definitions.
    # Each probe: (method, path, expected_in_body, framework_name)
    PROBES = [
        # Ollama
        ('GET', '/api/tags', '"models"', 'Ollama'),
        # NVIDIA Triton
        ('GET', '/v2/health/ready', '200', 'NVIDIA Triton'),
        ('POST', '/v2/repository/index', '"name"', 'NVIDIA Triton'),
        # OpenAI-compatible (vLLM, LiteLLM, LocalAI, LM Studio)
        ('GET', '/v1/models', '"data"', 'OpenAI-Compatible API'),
        # TensorFlow Serving
        ('GET', '/v1/models', '"model_version_status"', 'TensorFlow Serving'),
        # TorchServe
        ('GET', '/ping', '"Healthy"', 'TorchServe'),
        # TorchServe management
        ('GET', '/models', '"models"', 'TorchServe'),
        # MLflow
        ('GET', '/api/2.0/mlflow/experiments/list', '"experiments"', 'MLflow'),
        # BentoML
        ('GET', '/healthz', '', 'BentoML'),
        ('GET', '/docs', 'swagger', 'BentoML'),
        # Gradio
        ('GET', '/info', 'gradio', 'Gradio'),
        # Ray Dashboard
        ('GET', '/api/cluster_status', '"result"', 'Ray Dashboard'),
        # Streamlit
        ('GET', '/_stcore/health', '', 'Streamlit'),
        # MCP Server (JSON-RPC 2.0)
        ('POST', '/', '{"jsonrpc"', 'MCP Server'),
        # --- New probes for additional frameworks ---
        # LiteLLM
        ('GET', '/health/liveliness', '', 'LiteLLM'),
        ('GET', '/health/readiness', '', 'LiteLLM'),
        # LocalAI
        ('GET', '/readyz', '', 'LocalAI'),
        # text-generation-webui
        ('GET', '/api/v1/model', '"model_name"', 'text-generation-webui'),
        # ComfyUI
        ('GET', '/system_stats', '"system"', 'ComfyUI'),
        ('GET', '/object_info', '', 'ComfyUI'),
        # Stable Diffusion WebUI (Automatic1111)
        ('GET', '/sdapi/v1/options', '"sd_model_checkpoint"', 'Stable Diffusion WebUI'),
        # Open WebUI
        ('GET', '/api/config', '', 'Open WebUI'),
        # AnythingLLM
        ('GET', '/api/system', '', 'AnythingLLM'),
        # LangServe
        ('GET', '/docs', 'langserve', 'LangServe'),
        # Weaviate
        ('GET', '/v1/schema', '"classes"', 'Weaviate'),
        ('GET', '/v1/.well-known/ready', '', 'Weaviate'),
        # ChromaDB
        ('GET', '/api/v1/collections', '', 'ChromaDB'),
        ('GET', '/api/v1/heartbeat', '"nanosecond heartbeat"', 'ChromaDB'),
        # Milvus
        ('GET', '/api/v1/health', '', 'Milvus'),
        # Qdrant (additional probes)
        ('GET', '/collections', '"result"', 'Qdrant'),
        # TabbyAPI
        ('GET', '/v1/model/list', '', 'TabbyAPI'),
        # Dify
        ('GET', '/api/health', '', 'Dify'),
        # Flowise
        ('GET', '/api/v1/flows', '', 'Flowise'),
        # Label Studio
        ('GET', '/api/version', 'label-studio', 'Label Studio'),
        # Apache Airflow
        ('GET', '/api/v1/health', '"metadatabase"', 'Apache Airflow'),
    ]

    # OpenAI-Compatible Backend Differentiator (graphw00f technique).
    # When /v1/models or /v1/chat/completions responds, send targeted
    # probes to distinguish the specific backend framework.
    OPENAI_BACKEND_SIGNATURES = [
        # vLLM: error body contains "vllm" or "AsyncLLMEngine"
        {
            'method': 'POST', 'path': '/v1/chat/completions',
            'body': '{"model": "NONEXISTENT_12345", "messages": [{"role": "user", "content": "test"}]}',
            'match_field': 'body',
            'match_patterns': [re.compile(r'vllm|AsyncLLMEngine|vllm\.entrypoints', re.I)],
            'framework': 'vLLM',
        },
        # LiteLLM: unique health endpoint
        {
            'method': 'GET', 'path': '/health/liveliness', 'body': None,
            'match_field': 'status', 'match_patterns': [re.compile(r'^200$')],
            'framework': 'LiteLLM',
        },
        # LiteLLM: readiness with litellm in body
        {
            'method': 'GET', 'path': '/health/readiness', 'body': None,
            'match_field': 'body', 'match_patterns': [re.compile(r'litellm', re.I)],
            'framework': 'LiteLLM',
        },
        # LocalAI: X-Powered-By or body contains localai
        {
            'method': 'GET', 'path': '/v1/models', 'body': None,
            'match_field': 'header', 'header_name': 'x-powered-by',
            'match_patterns': [re.compile(r'LocalAI', re.I)],
            'framework': 'LocalAI',
        },
        # text-generation-webui: /api/v1/model endpoint
        {
            'method': 'GET', 'path': '/api/v1/model', 'body': None,
            'match_field': 'body',
            'match_patterns': [re.compile(r'"model_name"|text-generation', re.I)],
            'framework': 'text-generation-webui',
        },
        # TabbyAPI: /v1/model/list endpoint
        {
            'method': 'GET', 'path': '/v1/model/list', 'body': None,
            'match_field': 'body',
            'match_patterns': [re.compile(r'tabby|TabbyAPI', re.I)],
            'framework': 'TabbyAPI',
        },
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "TCP_PORT_OPEN",
            "TCP_PORT_OPEN_BANNER",
            "WEBSERVER_BANNER",
        ]

    def producedEvents(self):
        return [
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_MODEL_EXPOSED",
            "AI_ENDPOINT_UNAUTHENTICATED",
            "SOFTWARE_USED",
        ]

    def _extract_host_port(self, data):
        """Extract host and port from 'host:port' string."""
        if ':' not in data:
            return None, None
        parts = data.rsplit(':', 1)
        return parts[0], parts[1]

    def _probe_endpoint(self, base_url, method, path, expected, framework):
        """Send a single HTTP probe and return (framework, details) or None."""
        url = f"{base_url}{path}"

        try:
            if method == 'POST' and framework == 'MCP Server':
                # MCP uses JSON-RPC 2.0
                post_data = json.dumps({
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "id": 1
                })
                res = self.sf.fetchUrl(
                    url,
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts['_useragent'],
                    postData=post_data,
                    headers={'Content-Type': 'application/json'}
                )
            elif method == 'POST':
                res = self.sf.fetchUrl(
                    url,
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts['_useragent'],
                    postData="{}",
                    headers={'Content-Type': 'application/json'}
                )
            else:
                res = self.sf.fetchUrl(
                    url,
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts['_useragent']
                )
        except Exception:
            return None

        if not res or not res.get('content'):
            # Some probes succeed on status code alone (e.g. /v2/health/ready)
            if res and res.get('code') and str(res['code']) == '200' and not expected:
                return (framework, f"HTTP 200 on {path}")
            return None

        content = res['content']
        code = str(res.get('code', ''))

        # For Triton health check, 200 is the signal
        if expected == '200' and code == '200':
            return (framework, f"HTTP 200 on {path}")

        if expected and expected.lower() in content.lower():
            return (framework, self._truncate(content, 300))

        return None

    def _truncate(self, text, length):
        """Truncate text to a maximum length."""
        if len(text) <= length:
            return text
        return text[:length] + "..."

    def _differentiate_openai_backend(self, base_url):
        """Apply graphw00f technique to differentiate OpenAI-compatible backends.

        When a host serves /v1/models or /v1/chat/completions, multiple
        frameworks could be behind it. Send targeted probes and analyze
        error signatures to identify the specific backend.

        Returns: (framework_name, details) or None
        """
        for sig in self.OPENAI_BACKEND_SIGNATURES:
            if self.checkForStop():
                return None

            url = f"{base_url}{sig['path']}"
            try:
                if sig['method'] == 'POST' and sig['body']:
                    res = self.sf.fetchUrl(
                        url,
                        timeout=self.opts['probe_timeout'],
                        useragent=self.opts['_useragent'],
                        postData=sig['body'],
                        headers={'Content-Type': 'application/json'}
                    )
                else:
                    res = self.sf.fetchUrl(
                        url,
                        timeout=self.opts['probe_timeout'],
                        useragent=self.opts['_useragent']
                    )
            except Exception:
                continue

            if not res:
                continue

            if sig['match_field'] == 'body' and res.get('content'):
                for pattern in sig['match_patterns']:
                    if pattern.search(res['content']):
                        return (sig['framework'],
                                f"Identified via error fingerprint on {sig['path']}")

            elif sig['match_field'] == 'header' and res.get('headers'):
                header_name = sig.get('header_name', '')
                header_val = ''
                if isinstance(res['headers'], dict):
                    header_val = res['headers'].get(header_name, '')
                for pattern in sig['match_patterns']:
                    if pattern.search(str(header_val)):
                        return (sig['framework'],
                                f"Identified via {header_name} header")

            elif sig['match_field'] == 'status' and res.get('code'):
                for pattern in sig['match_patterns']:
                    if pattern.search(str(res['code'])):
                        return (sig['framework'],
                                f"Identified via HTTP {res['code']} on {sig['path']}")

        return None

    def _check_models_exposed(self, base_url, framework):
        """Check if models are accessible without authentication.

        Returns a list of model identifiers found, or empty list.
        """
        models = []

        model_endpoints = {
            'Ollama': '/api/tags',
            'NVIDIA Triton': '/v2/repository/index',
            'OpenAI-Compatible API': '/v1/models',
            'TensorFlow Serving': '/v1/models',
            'TorchServe': '/models',
            'MLflow': '/api/2.0/mlflow/experiments/list',
            # New frameworks
            'vLLM': '/v1/models',
            'LiteLLM': '/v1/models',
            'LocalAI': '/v1/models',
            'LM Studio': '/v1/models',
            'text-generation-webui': '/api/v1/model',
            'TabbyAPI': '/v1/model/list',
            'Weaviate': '/v1/schema',
            'ChromaDB': '/api/v1/collections',
            'Milvus': '/api/v1/collections',
            'Qdrant': '/collections',
        }

        endpoint = model_endpoints.get(framework)
        if not endpoint:
            return models

        try:
            if framework == 'NVIDIA Triton' and endpoint == '/v2/repository/index':
                res = self.sf.fetchUrl(
                    f"{base_url}{endpoint}",
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts['_useragent'],
                    postData="{}",
                    headers={'Content-Type': 'application/json'}
                )
            else:
                res = self.sf.fetchUrl(
                    f"{base_url}{endpoint}",
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts['_useragent']
                )
        except Exception:
            return models

        if not res or not res.get('content'):
            return models

        try:
            data = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            return models

        # Extract model names based on framework response format
        if framework == 'Ollama':
            for m in data.get('models', []):
                name = m.get('name', m.get('model', ''))
                if name:
                    models.append(name)
        elif framework == 'NVIDIA Triton':
            if isinstance(data, list):
                for m in data:
                    name = m.get('name', '')
                    if name:
                        models.append(name)
        elif framework in ('OpenAI-Compatible API', 'TensorFlow Serving'):
            for m in data.get('data', data.get('model_version_status', [])):
                if isinstance(m, dict):
                    name = m.get('id', m.get('model_name', ''))
                    if name:
                        models.append(name)
        elif framework == 'TorchServe':
            for name, _ in data.get('models', {}).items() if isinstance(data.get('models'), dict) else []:
                models.append(name)
        elif framework == 'MLflow':
            for exp in data.get('experiments', []):
                name = exp.get('name', '')
                if name:
                    models.append(name)
        elif framework == 'Weaviate':
            for cls in data.get('classes', []):
                name = cls.get('class', '')
                if name:
                    models.append(f"collection:{name}")
        elif framework == 'ChromaDB':
            if isinstance(data, list):
                for coll in data:
                    name = coll.get('name', '') if isinstance(coll, dict) else str(coll)
                    if name:
                        models.append(f"collection:{name}")
        elif framework == 'Qdrant':
            for coll in data.get('result', {}).get('collections', []):
                name = coll.get('name', '')
                if name:
                    models.append(f"collection:{name}")
        elif framework in ('vLLM', 'LiteLLM', 'LocalAI', 'LM Studio', 'TabbyAPI'):
            # These all use OpenAI-compatible /v1/models format
            for m in data.get('data', []):
                if isinstance(m, dict):
                    name = m.get('id', '')
                    if name:
                        models.append(name)

        return models[:20]  # Cap at 20 to avoid noise

    def _check_admin_exposed(self, base_url, framework):
        """Check if management/admin endpoints are exposed without auth.

        Returns description of exposed admin surface, or None.
        """
        admin_endpoints = {
            'Ollama': [('/api/delete', 'DELETE model endpoint')],
            'NVIDIA Triton': [('/v2/repository/index', 'Model repository management')],
            'TorchServe': [('/models', 'Model management API (port 8081)')],
            'MLflow': [
                ('/api/2.0/mlflow/registered-models/list', 'Model registry'),
            ],
            'Ray Dashboard': [('/api/cluster_status', 'Cluster management')],
            'LiteLLM': [('/key/info', 'API key management')],
            'ComfyUI': [('/system_stats', 'System statistics')],
            'Stable Diffusion WebUI': [('/sdapi/v1/cmd-flags', 'Command flags')],
            'Jupyter': [('/api/kernels', 'Kernel management')],
            'Weaviate': [('/v1/schema', 'Schema management')],
            'ChromaDB': [('/api/v1/collections', 'Collection management')],
            'Milvus': [('/api/v1/collections', 'Collection management')],
            'Qdrant': [('/collections', 'Collection management')],
        }

        endpoints = admin_endpoints.get(framework, [])
        exposed = []

        for path, description in endpoints:
            if self.checkForStop():
                return None
            try:
                res = self.sf.fetchUrl(
                    f"{base_url}{path}",
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts['_useragent']
                )
                if res and res.get('code') and int(res['code']) < 400:
                    exposed.append(f"{path} ({description})")
            except Exception:
                continue

        if exposed:
            return f"Admin endpoints accessible: {', '.join(exposed[:3])}"
        return None

    def _fingerprint_from_banner(self, banner):
        """Check banner text against known AI patterns. Returns framework name or None."""
        for pattern, framework in self.AI_BANNER_PATTERNS:
            if pattern.search(banner):
                return framework
        return None

    def _do_active_fingerprint(self, host, port, event):
        """Perform active fingerprinting on a host:port.

        Sends framework-specific HTTP probes and emits events for confirmed
        AI infrastructure.
        """
        key = f"{host}:{port}"
        if key in self.results:
            return
        self.results[key] = True

        # Try HTTPS first, fall back to HTTP
        for scheme in ['https', 'http']:
            base_url = f"{scheme}://{host}:{port}"

            for method, path, expected, framework in self.PROBES:
                if self.checkForStop():
                    return

                result = self._probe_endpoint(base_url, method, path, expected, framework)
                if result:
                    fw_name, details = result

                    # graphw00f differentiator for OpenAI-compatible APIs
                    if fw_name == 'OpenAI-Compatible API':
                        backend = self._differentiate_openai_backend(base_url)
                        if backend:
                            fw_name = backend[0]
                            details = backend[1]

                    self.info(f"Confirmed {fw_name} on {key} via {path}")

                    # Emit AI_INFRASTRUCTURE_DETECTED
                    evt = SpiderFootEvent(
                        "AI_INFRASTRUCTURE_DETECTED",
                        f"{fw_name} detected on {key} ({scheme})",
                        self.__name__, event)
                    self.notifyListeners(evt)

                    # Emit SOFTWARE_USED
                    sw_evt = SpiderFootEvent(
                        "SOFTWARE_USED",
                        fw_name,
                        self.__name__, event)
                    self.notifyListeners(sw_evt)

                    # Check for unauthenticated model access
                    if self.opts['check_auth']:
                        exposed_models = self._check_models_exposed(base_url, fw_name)
                        if exposed_models:
                            model_list = ", ".join(exposed_models[:5])
                            if len(exposed_models) > 5:
                                model_list += f" (+{len(exposed_models) - 5} more)"

                            # Emit AI_MODEL_EXPOSED
                            model_evt = SpiderFootEvent(
                                "AI_MODEL_EXPOSED",
                                f"{fw_name} on {key}: {model_list}",
                                self.__name__, evt)
                            self.notifyListeners(model_evt)

                            # Emit AI_ENDPOINT_UNAUTHENTICATED
                            unauth_evt = SpiderFootEvent(
                                "AI_ENDPOINT_UNAUTHENTICATED",
                                f"{fw_name} on {key} allows unauthenticated "
                                f"model listing ({len(exposed_models)} models)",
                                self.__name__, evt)
                            self.notifyListeners(unauth_evt)

                        # Check for exposed admin/management endpoints
                        admin_check = self._check_admin_exposed(base_url, fw_name)
                        if admin_check:
                            admin_evt = SpiderFootEvent(
                                "AI_ENDPOINT_UNAUTHENTICATED",
                                f"{fw_name} on {key}: {admin_check}",
                                self.__name__, evt)
                            self.notifyListeners(admin_evt)

                    # Found a match on this scheme, stop probing
                    return

            # If HTTPS had no matches, try HTTP
            continue

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

            # Check if the port is a known AI service port
            if port in self.AI_PORTS:
                self.info(f"Potential AI port detected: {eventData} "
                          f"(candidates: {', '.join(self.AI_PORTS[port])})")

                if self.opts['active_fingerprint']:
                    self._do_active_fingerprint(host, port, event)
                else:
                    # Passive-only: emit based on port alone
                    candidates = ", ".join(self.AI_PORTS[port])
                    evt = SpiderFootEvent(
                        "AI_INFRASTRUCTURE_DETECTED",
                        f"Possible AI service on {eventData} "
                        f"(port matches: {candidates})",
                        self.__name__, event)
                    self.notifyListeners(evt)

        elif eventName in ("TCP_PORT_OPEN_BANNER", "WEBSERVER_BANNER"):
            framework = self._fingerprint_from_banner(eventData)
            if framework:
                # Avoid duplicate results for the same banner
                banner_key = f"banner:{eventData[:100]}"
                if banner_key in self.results:
                    return
                self.results[banner_key] = True

                self.info(f"AI framework detected in banner: {framework}")

                evt = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED",
                    f"{framework} (detected via banner fingerprint)",
                    self.__name__, event)
                self.notifyListeners(evt)

                sw_evt = SpiderFootEvent(
                    "SOFTWARE_USED",
                    framework,
                    self.__name__, event)
                self.notifyListeners(sw_evt)


# End of sfp_ai_fingerprint class
