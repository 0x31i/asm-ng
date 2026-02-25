import pytest
import unittest

from modules.sfp_ai_llm_probe import sfp_ai_llm_probe
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiLlmProbe(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_llm_probe()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_llm_probe()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_llm_probe()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_llm_probe()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_llm_probe()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_chat_endpoints_should_be_dict(self):
        module = sfp_ai_llm_probe()
        self.assertIsInstance(module.CHAT_ENDPOINTS, dict)
        self.assertGreater(len(module.CHAT_ENDPOINTS), 0)
        # Each entry should map to (path, format)
        for fw, (path, fmt) in module.CHAT_ENDPOINTS.items():
            self.assertTrue(path.startswith('/'))
            self.assertIn(fmt, ('openai', 'ollama'))

    def test_llm_frameworks_should_be_list(self):
        module = sfp_ai_llm_probe()
        self.assertIsInstance(module.LLM_FRAMEWORKS, list)
        self.assertIn('ollama', module.LLM_FRAMEWORKS)
        self.assertIn('vllm', module.LLM_FRAMEWORKS)

    def test_detect_framework_ollama(self):
        module = sfp_ai_llm_probe()
        result = module._detect_framework(
            "Ollama detected on 192.168.1.1:11434 (http)")
        self.assertEqual(result, 'ollama')

    def test_detect_framework_vllm(self):
        module = sfp_ai_llm_probe()
        result = module._detect_framework(
            "vLLM detected on 10.0.0.1:8000 (http)")
        self.assertEqual(result, 'vllm')

    def test_detect_framework_none(self):
        module = sfp_ai_llm_probe()
        result = module._detect_framework(
            "Weaviate detected on 10.0.0.1:8080 (http)")
        self.assertIsNone(result)

    def test_get_chat_endpoint_ollama(self):
        module = sfp_ai_llm_probe()
        path, fmt = module._get_chat_endpoint('ollama')
        self.assertEqual(path, '/api/chat')
        self.assertEqual(fmt, 'ollama')

    def test_get_chat_endpoint_default(self):
        module = sfp_ai_llm_probe()
        path, fmt = module._get_chat_endpoint('unknown')
        self.assertEqual(path, '/v1/chat/completions')
        self.assertEqual(fmt, 'openai')

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_llm_probe()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    @safe_recursion(max_depth=5)
    def test_handleEvent_non_llm_framework(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_llm_probe()
        module.setup(sf, dict())

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        evt = SpiderFootEvent('ROOT', 'example.com', '', '')
        # Weaviate is not an LLM framework, should be skipped
        ai_evt = SpiderFootEvent(
            "AI_INFRASTRUCTURE_DETECTED",
            "Weaviate detected on 192.168.1.1:8080 (http)",
            "sfp_ai_fingerprint", evt)
        result = module.handleEvent(ai_evt)
        self.assertIsNone(result)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
