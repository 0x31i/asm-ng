# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_jsdetect
# Purpose:     Detect JavaScript AI SDK references, AI chat widget embeds,
#              streaming API patterns, and AI-specific error messages that
#              reveal AI service usage in web content.
#
# Author:      ASM-NG Enhancement Team
#
# Created:     2026-02-26
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_jsdetect(SpiderFootPlugin):

    meta = {
        'name': "AI JavaScript & Content Detector",
        'summary': "Detect AI SDK imports, chat widgets, streaming API patterns, "
            "and AI error messages in web content.",
        'flags': [],
        'useCases': ["Footprint", "Passive", "AI Attack Surface"],
        'categories': ["Content Analysis"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Scans already-fetched TARGET_WEB_CONTENT for "
                "JavaScript AI SDK import statements, embedded AI chat widget "
                "scripts, streaming/REST API patterns indicating an AI backend, "
                "and leaked AI error messages or API key variable names.",
        }
    }

    # Default options
    opts = {
        'detect_api_keys': True,
        'max_content_bytes': 512000,
    }

    # Option descriptions
    optdescs = {
        'detect_api_keys': "Also look for leaked AI API keys in content.",
        'max_content_bytes': "Maximum number of bytes of content to scan per "
            "event (default 500 KB). Prevents excessive CPU on huge pages.",
    }

    results = None
    errorState = False
    _compiled_patterns = None

    # ---------------------------------------------------------------
    # Pattern definitions (raw tuples; compiled once in setup())
    # ---------------------------------------------------------------

    # 1. AI SDK imports/references in JavaScript
    AI_SDK_PATTERNS = [
        (r'(?:from\s+|require\s*\(\s*["\'])openai["\'/]', 'OpenAI SDK'),
        (r'(?:from\s+|require\s*\(\s*["\'])@anthropic-ai/sdk["\'/]', 'Anthropic SDK'),
        (r'(?:from\s+|require\s*\(\s*["\'])@google/generative-ai["\'/]', 'Google Generative AI SDK'),
        (r'(?:from\s+|require\s*\(\s*["\'])cohere-ai["\'/]', 'Cohere SDK'),
        (r'(?:from\s+|require\s*\(\s*["\'])replicate["\'/]', 'Replicate SDK'),
        (r'(?:from\s+|require\s*\(\s*["\'])langchain["\'/]', 'LangChain'),
        (r'(?:from\s+|require\s*\(\s*["\'])llamaindex["\'/]', 'LlamaIndex'),
        (r'(?:from\s+|require\s*\(\s*["\'])@vercel/ai["\'/]', 'Vercel AI SDK'),
        (r'(?:from\s+|require\s*\(\s*["\'])ai["\'/]', 'Vercel AI SDK'),
        (r'(?:from\s+|require\s*\(\s*["\'])@huggingface/inference["\'/]', 'Hugging Face Inference'),
    ]

    # 2. AI chat widget scripts (in script src attributes or inline)
    AI_WIDGET_PATTERNS = [
        (r'chatbase\.co/embed', 'Chatbase AI Chat Widget'),
        (r'cdn\.voiceflow\.com', 'Voiceflow AI Chat'),
        (r'app\.wonderchat\.io', 'Wonderchat AI'),
        (r'widget\.writesonic\.com', 'Writesonic AI Chat'),
        (r'cdn\.botpress\.cloud', 'Botpress AI Chat'),
        (r'chatbot\.design/widget', 'Chatbot.design Widget'),
    ]

    # 3. Streaming/API patterns that indicate an AI backend
    AI_API_PATTERNS = [
        (r'/v1/chat/completions', 'OpenAI-compatible Chat API endpoint'),
        (r'/v1/completions', 'OpenAI-compatible Completions API endpoint'),
        (r'/v1/embeddings', 'OpenAI-compatible Embeddings API endpoint'),
        (r'/api/generate', 'Ollama-style Generate API endpoint'),
        (r'text/event-stream.*(?:chat|completion|generate|ai)', 'AI Streaming API (SSE)'),
        (r'EventSource\s*\([^)]*(?:chat|completion|generate|ai)', 'AI EventSource Streaming'),
    ]

    # 4. AI-related error strings (leaked through web content)
    AI_ERROR_PATTERNS = [
        (r'(?:openai|anthropic|cohere).*(?:rate.?limit|quota|exceeded)', 'AI API Rate Limit Error Leaked'),
        (r'model.*(?:gpt-[34]|claude|gemini|llama|mistral)', 'AI Model Name Leaked'),
        (r'(?:context.?length|token.?limit|max.?tokens?).*exceeded', 'AI Token Limit Error Leaked'),
        (r'(?:OPENAI|ANTHROPIC|COHERE|HF)_API_KEY', 'AI API Key Variable Name Leaked'),
        (r'sk-[a-zA-Z0-9]{20,}', 'Potential OpenAI API Key Leaked'),
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        # Compile all regex patterns once for performance
        self._compiled_patterns = []

        all_raw = (
            [('sdk', p, n) for p, n in self.AI_SDK_PATTERNS]
            + [('widget', p, n) for p, n in self.AI_WIDGET_PATTERNS]
            + [('api', p, n) for p, n in self.AI_API_PATTERNS]
            + [('error', p, n) for p, n in self.AI_ERROR_PATTERNS]
        )

        for category, pattern, name in all_raw:
            # Skip potential API key detection if the option is disabled
            if not self.opts['detect_api_keys'] and name == 'Potential OpenAI API Key Leaked':
                continue
            self._compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE), name, category)
            )

    def watchedEvents(self):
        return [
            "TARGET_WEB_CONTENT",
        ]

    def producedEvents(self):
        return [
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def _category_label(self, category):
        """Return a human-readable prefix for the detection category."""
        labels = {
            'sdk': 'AI SDK import detected',
            'widget': 'AI chat widget detected',
            'api': 'AI API pattern detected',
            'error': 'AI error/leak detected',
        }
        return labels.get(category, 'AI indicator detected')

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        # Skip very short or empty content
        if not eventData or len(eventData) < 50:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Deduplicate by content hash to avoid re-scanning identical pages
        content_key = f"{eventName}:{hash(eventData[:500])}"
        if content_key in self.results:
            return
        self.results[content_key] = True

        # Truncate content to configured max to avoid CPU issues on huge pages
        max_bytes = self.opts.get('max_content_bytes', 512000)
        content = eventData[:max_bytes]

        # Derive a source identifier for deduplication of findings
        source_url = event.actualSource if hasattr(event, 'actualSource') and event.actualSource else str(event.sourceEvent)

        # Track (source_url, pattern_name) pairs to deduplicate within this event
        seen = set()

        for compiled_re, pattern_name, category in self._compiled_patterns:
            if self.checkForStop():
                return

            if compiled_re.search(content):
                dedup_key = f"{source_url}|{pattern_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Also deduplicate across events via self.results
                global_key = f"finding:{dedup_key}"
                if global_key in self.results:
                    continue
                self.results[global_key] = True

                label = self._category_label(category)
                description = f"{label}: {pattern_name}"

                self.info(f"{description} (source: {source_url})")

                evt = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED",
                    description,
                    self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_ai_jsdetect class
