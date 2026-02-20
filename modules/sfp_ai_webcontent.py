# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_webcontent
# Purpose:     Detect embedded AI/ML integrations in web content by scanning
#              for SDK imports, chat widget markers, API key leaks, and
#              inference endpoint references.
#
# Author:      ASM-NG Enhancement Team
#
# Created:     2026-02-20
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_webcontent(SpiderFootPlugin):

    meta = {
        'name': "AI Web Content Analyzer",
        'summary': "Detect embedded AI/ML integrations in web content: SDK "
            "imports (OpenAI, Anthropic, Vercel AI, LangChain), chat widget "
            "markers, leaked API keys, and AI endpoint references in "
            "JavaScript and HTML.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Content Analysis"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Analyzes already-fetched web content for signs of "
                "AI/ML integration. Detects JavaScript SDK imports for major "
                "AI providers, identifies chat widget embed codes, finds "
                "leaked AI service API keys, and locates references to AI "
                "inference endpoints in bundled JavaScript.",
        }
    }

    # Default options
    opts = {
        'detect_sdks': True,
        'detect_api_keys': True,
        'detect_widgets': True,
        'detect_endpoints': True,
        'min_key_entropy': True,
    }

    # Option descriptions
    optdescs = {
        'detect_sdks': "Detect AI SDK imports in JavaScript "
            "(openai, @anthropic-ai/sdk, langchain, etc.).",
        'detect_api_keys': "Detect leaked AI service API keys "
            "(OpenAI sk-*, HuggingFace hf_*, Anthropic sk-ant-*, etc.).",
        'detect_widgets': "Detect AI chat widget embed codes "
            "(Ada, Voiceflow, Chatbase, Intercom AI, etc.).",
        'detect_endpoints': "Detect AI inference API endpoint references "
            "(/v1/chat/completions, /api/generate, etc.).",
        'min_key_entropy': "Filter out low-entropy strings that match API key "
            "patterns but are likely false positives.",
    }

    results = None
    errorState = False

    # --- SDK DETECTION PATTERNS ---
    # Matches import/require statements and CDN script tags for AI SDKs
    SDK_PATTERNS = [
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*openai''', re.I),
            'OpenAI SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@anthropic-ai/sdk''', re.I),
            'Anthropic SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@vercel/ai''', re.I),
            'Vercel AI SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*langchain''', re.I),
            'LangChain'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@langchain''', re.I),
            'LangChain'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@huggingface/inference''', re.I),
            'HuggingFace Inference'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*cohere-ai''', re.I),
            'Cohere SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@google/generative-ai''', re.I),
            'Google Generative AI SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@google-ai/generativelanguage''', re.I),
            'Google AI SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*replicate''', re.I),
            'Replicate SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@mistralai''', re.I),
            'Mistral AI SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*@pinecone-database''', re.I),
            'Pinecone SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*chromadb''', re.I),
            'ChromaDB SDK'),
        (re.compile(r'''(?:import|require|from)\s*[\(\['"]\s*weaviate-client''', re.I),
            'Weaviate SDK'),
        # CDN script tags
        (re.compile(r'src=["\'][^"\']*cdn[^"\']*openai[^"\']*["\']', re.I),
            'OpenAI CDN'),
        (re.compile(r'src=["\'][^"\']*cdn[^"\']*anthropic[^"\']*["\']', re.I),
            'Anthropic CDN'),
    ]

    # --- API KEY PATTERNS ---
    # Each tuple: (pattern, provider, key_prefix_for_display)
    API_KEY_PATTERNS = [
        # OpenAI keys (sk-... or sk-proj-...)
        (re.compile(r'(?:^|["\'\s=:,])(?P<key>sk-[a-zA-Z0-9]{20,})(?:["\'\s,;]|$)'),
            'OpenAI', 'sk-'),
        # Anthropic keys
        (re.compile(r'(?:^|["\'\s=:,])(?P<key>sk-ant-[a-zA-Z0-9_-]{20,})(?:["\'\s,;]|$)'),
            'Anthropic', 'sk-ant-'),
        # HuggingFace tokens
        (re.compile(r'(?:^|["\'\s=:,])(?P<key>hf_[a-zA-Z0-9]{20,})(?:["\'\s,;]|$)'),
            'HuggingFace', 'hf_'),
        # Google AI / Vertex
        (re.compile(r'(?:^|["\'\s=:,])(?P<key>AIza[a-zA-Z0-9_-]{35})(?:["\'\s,;]|$)'),
            'Google AI', 'AIza'),
        # Cohere
        (re.compile(r'(?:^|["\'\s=:,])(?P<key>[a-zA-Z0-9]{40})(?:["\'\s,;]|$)'),
            None, None),  # Too generic, skip unless clearly labeled
        # Pinecone
        (re.compile(r'(?:^|["\'\s=:,])(?P<key>pcsk_[a-zA-Z0-9_-]{20,})(?:["\'\s,;]|$)'),
            'Pinecone', 'pcsk_'),
        # Replicate
        (re.compile(r'(?:^|["\'\s=:,])(?P<key>r8_[a-zA-Z0-9]{20,})(?:["\'\s,;]|$)'),
            'Replicate', 'r8_'),
    ]

    # --- CHAT WIDGET PATTERNS ---
    WIDGET_PATTERNS = [
        (re.compile(r'window\.__ada\b', re.I), 'Ada AI Chat'),
        (re.compile(r'window\.voiceflow\b', re.I), 'Voiceflow'),
        (re.compile(r'chatbase\.co/embed', re.I), 'Chatbase'),
        (re.compile(r'cdn\.botpress\.cloud', re.I), 'Botpress'),
        (re.compile(r'widget\.intercom\.io.*ai|intercomSettings.*ai', re.I), 'Intercom AI'),
        (re.compile(r'drift\.com.*ai|driftt\.com.*ai', re.I), 'Drift AI'),
        (re.compile(r'cdn\.customgpt\.ai', re.I), 'CustomGPT'),
        (re.compile(r'app\.chaindesk\.ai', re.I), 'Chaindesk'),
        (re.compile(r'embed\.fixie\.ai', re.I), 'Fixie AI'),
        (re.compile(r'widget\.writesonic\.com', re.I), 'Writesonic/Botsonic'),
        (re.compile(r'copilot\.microsoft\.com/embed', re.I), 'Microsoft Copilot'),
        (re.compile(r'cdn\.zapier\.com/packages/partner-sdk', re.I), 'Zapier AI Chatbot'),
    ]

    # --- AI ENDPOINT PATTERNS ---
    ENDPOINT_PATTERNS = [
        (re.compile(r'/v1/chat/completions', re.I), 'OpenAI-compatible Chat API'),
        (re.compile(r'/v1/completions', re.I), 'OpenAI-compatible Completions API'),
        (re.compile(r'/v1/embeddings', re.I), 'OpenAI-compatible Embeddings API'),
        (re.compile(r'/v1/images/generations', re.I), 'OpenAI-compatible Image API'),
        (re.compile(r'/v1/audio/transcriptions', re.I), 'OpenAI-compatible Audio API'),
        (re.compile(r'/api/generate\b', re.I), 'Ollama Generate API'),
        (re.compile(r'/api/chat\b', re.I), 'Ollama Chat API'),
        (re.compile(r'/v2/models/[^/]+/infer', re.I), 'KServe v2 Inference'),
        (re.compile(r'/v1/models/[^/]+:predict', re.I), 'KServe v1 Prediction'),
        (re.compile(r'/api/2\.0/mlflow/', re.I), 'MLflow API'),
        (re.compile(r'/v2/repository/index', re.I), 'Triton Model Repository'),
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "TARGET_WEB_CONTENT",
            "URL_JAVASCRIPT",
        ]

    def producedEvents(self):
        return [
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_API_KEY_LEAKED",
            "SOFTWARE_USED",
        ]

    def _has_sufficient_entropy(self, key_str):
        """Check if a string has enough character diversity to be a real key."""
        if not self.opts['min_key_entropy']:
            return True
        unique_chars = len(set(key_str))
        # Real API keys have high character diversity
        return unique_chars >= min(10, len(key_str) // 3)

    def _mask_key(self, key):
        """Mask an API key for safe display: show prefix + last 4 chars."""
        if len(key) <= 8:
            return key[:4] + "****"
        return key[:8] + "****" + key[-4:]

    def _scan_for_sdks(self, content, event):
        """Scan content for AI SDK imports."""
        found = set()
        for pattern, sdk_name in self.SDK_PATTERNS:
            if pattern.search(content):
                if sdk_name not in found:
                    found.add(sdk_name)
                    self.info(f"Detected {sdk_name} in web content")

                    evt = SpiderFootEvent(
                        "AI_INFRASTRUCTURE_DETECTED",
                        f"AI SDK embedded: {sdk_name}",
                        self.__name__, event)
                    self.notifyListeners(evt)

                    sw_evt = SpiderFootEvent(
                        "SOFTWARE_USED",
                        sdk_name,
                        self.__name__, event)
                    self.notifyListeners(sw_evt)

    def _scan_for_api_keys(self, content, event):
        """Scan content for leaked AI API keys."""
        found_keys = set()
        for pattern, provider, prefix in self.API_KEY_PATTERNS:
            if provider is None:
                # Skip overly generic patterns
                continue
            for match in pattern.finditer(content):
                key = match.group('key')
                if key in found_keys:
                    continue
                if not self._has_sufficient_entropy(key):
                    continue
                found_keys.add(key)

                masked = self._mask_key(key)
                self.info(f"Potential {provider} API key leaked: {masked}")

                evt = SpiderFootEvent(
                    "AI_API_KEY_LEAKED",
                    f"{provider} API key: {masked}",
                    self.__name__, event)
                self.notifyListeners(evt)

    def _scan_for_widgets(self, content, event):
        """Scan content for AI chat widget markers."""
        found = set()
        for pattern, widget_name in self.WIDGET_PATTERNS:
            if pattern.search(content):
                if widget_name not in found:
                    found.add(widget_name)
                    self.info(f"Detected {widget_name} widget in web content")

                    evt = SpiderFootEvent(
                        "AI_INFRASTRUCTURE_DETECTED",
                        f"AI chat widget: {widget_name}",
                        self.__name__, event)
                    self.notifyListeners(evt)

                    sw_evt = SpiderFootEvent(
                        "SOFTWARE_USED",
                        widget_name,
                        self.__name__, event)
                    self.notifyListeners(sw_evt)

    def _scan_for_endpoints(self, content, event):
        """Scan content for AI API endpoint references."""
        found = set()
        for pattern, endpoint_name in self.ENDPOINT_PATTERNS:
            if pattern.search(content):
                if endpoint_name not in found:
                    found.add(endpoint_name)
                    self.info(f"AI endpoint reference found: {endpoint_name}")

                    evt = SpiderFootEvent(
                        "AI_INFRASTRUCTURE_DETECTED",
                        f"AI endpoint reference: {endpoint_name}",
                        self.__name__, event)
                    self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        # Skip very short content
        if not eventData or len(eventData) < 50:
            return

        # Deduplicate on content hash
        content_key = f"{eventName}:{hash(eventData[:500])}"
        if content_key in self.results:
            return
        self.results[content_key] = True

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['detect_sdks']:
            self._scan_for_sdks(eventData, event)

        if self.opts['detect_api_keys']:
            self._scan_for_api_keys(eventData, event)

        if self.opts['detect_widgets']:
            self._scan_for_widgets(eventData, event)

        if self.opts['detect_endpoints']:
            self._scan_for_endpoints(eventData, event)


# End of sfp_ai_webcontent class
