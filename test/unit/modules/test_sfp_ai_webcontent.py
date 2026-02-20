import pytest
import unittest

from modules.sfp_ai_webcontent import sfp_ai_webcontent
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiWebcontent(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_webcontent()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_webcontent()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_webcontent()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_webcontent()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_webcontent()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_mask_key(self):
        module = sfp_ai_webcontent()
        masked = module._mask_key("sk-1234567890abcdefghijklmnop")
        self.assertTrue(masked.startswith("sk-12345"))
        self.assertTrue(masked.endswith("mnop"))
        self.assertIn("****", masked)

    def test_mask_key_short(self):
        module = sfp_ai_webcontent()
        masked = module._mask_key("sk-1234")
        self.assertIn("****", masked)

    def test_has_sufficient_entropy(self):
        module = sfp_ai_webcontent()
        # Real API key - high entropy
        self.assertTrue(module._has_sufficient_entropy(
            "sk-proj-abc123XYZ789defGHI456"))
        # Low entropy string
        self.assertFalse(module._has_sufficient_entropy(
            "aaaaaaaaaaaaaaaaaaaaa"))

    def test_sdk_patterns_match_openai(self):
        module = sfp_ai_webcontent()
        content = 'import openai from "openai";'
        found = False
        for pattern, sdk_name in module.SDK_PATTERNS:
            if pattern.search(content):
                found = True
                self.assertEqual(sdk_name, "OpenAI SDK")
                break
        self.assertTrue(found, "OpenAI SDK pattern should match")

    def test_sdk_patterns_match_anthropic(self):
        module = sfp_ai_webcontent()
        content = "import Anthropic from '@anthropic-ai/sdk';"
        found = False
        for pattern, sdk_name in module.SDK_PATTERNS:
            if pattern.search(content):
                found = True
                self.assertEqual(sdk_name, "Anthropic SDK")
                break
        self.assertTrue(found, "Anthropic SDK pattern should match")

    def test_sdk_patterns_match_langchain(self):
        module = sfp_ai_webcontent()
        content = 'from "langchain/llms/openai" import OpenAI;'
        found = False
        for pattern, sdk_name in module.SDK_PATTERNS:
            if pattern.search(content):
                found = True
                self.assertIn("LangChain", sdk_name)
                break
        self.assertTrue(found, "LangChain SDK pattern should match")

    def test_widget_patterns_match_chatbase(self):
        module = sfp_ai_webcontent()
        content = '<script src="https://chatbase.co/embed/widget.js"></script>'
        found = False
        for pattern, widget_name in module.WIDGET_PATTERNS:
            if pattern.search(content):
                found = True
                self.assertEqual(widget_name, "Chatbase")
                break
        self.assertTrue(found, "Chatbase widget pattern should match")

    def test_endpoint_patterns_match_chat_completions(self):
        module = sfp_ai_webcontent()
        content = 'fetch("/v1/chat/completions", { method: "POST" })'
        found = False
        for pattern, ep_name in module.ENDPOINT_PATTERNS:
            if pattern.search(content):
                found = True
                self.assertIn("Chat", ep_name)
                break
        self.assertTrue(found, "Chat completions endpoint pattern should match")

    def test_api_key_patterns_match_openai(self):
        module = sfp_ai_webcontent()
        content = 'const apiKey = "sk-abcdefghijklmnopqrstuvwxyz12345678";'
        found = False
        for pattern, provider, prefix in module.API_KEY_PATTERNS:
            if provider is None:
                continue
            for match in pattern.finditer(content):
                key = match.group('key')
                if key.startswith('sk-') and not key.startswith('sk-ant-'):
                    found = True
                    self.assertEqual(provider, "OpenAI")
                    break
            if found:
                break
        self.assertTrue(found, "OpenAI API key pattern should match")

    def test_no_match_on_normal_content(self):
        module = sfp_ai_webcontent()
        content = '<html><body><h1>Hello World</h1><p>Normal web page.</p></body></html>'
        # SDK patterns should not match
        for pattern, _ in module.SDK_PATTERNS:
            self.assertIsNone(pattern.search(content))
        # Widget patterns should not match
        for pattern, _ in module.WIDGET_PATTERNS:
            self.assertIsNone(pattern.search(content))

    @safe_recursion(max_depth=5)
    def test_handleEvent_short_content_ignored(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_webcontent()
        module.setup(sf, dict())

        target_value = 'example.com'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        # Very short content should be skipped
        web_evt = SpiderFootEvent("TARGET_WEB_CONTENT", "short",
                                  "sfp_spider", evt)
        result = module.handleEvent(web_evt)
        self.assertIsNone(result)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()
