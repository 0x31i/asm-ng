import pytest
import unittest

from modules.sfp_ai_subdomain import sfp_ai_subdomain
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiSubdomain(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_subdomain()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_subdomain()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_subdomain()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_subdomain()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_subdomain()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_subdomain_regex_matches(self):
        module = sfp_ai_subdomain()
        # Should match AI-related subdomain patterns
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("inference"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("ml-platform"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("ai-gateway"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("llm"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("model-serving"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("genai"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("gpu"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("ollama"))
        self.assertIsNotNone(module.AI_SUBDOMAIN_RE.search("triton"))

    def test_ai_subdomain_regex_no_match(self):
        module = sfp_ai_subdomain()
        # Should NOT match generic subdomain patterns
        self.assertIsNone(module.AI_SUBDOMAIN_RE.search("www"))
        self.assertIsNone(module.AI_SUBDOMAIN_RE.search("mail"))
        self.assertIsNone(module.AI_SUBDOMAIN_RE.search("ftp"))
        self.assertIsNone(module.AI_SUBDOMAIN_RE.search("blog"))

    def test_load_ai_wordlist(self):
        module = sfp_ai_subdomain()
        words = module._load_ai_wordlist()
        self.assertIsInstance(words, list)
        self.assertGreater(len(words), 0)
        self.assertIn('inference', words)
        self.assertIn('ollama', words)
        self.assertIn('ml', words)

    def test_watches_domain_name(self):
        module = sfp_ai_subdomain()
        self.assertIn("DOMAIN_NAME", module.watchedEvents())

    def test_produces_internet_name(self):
        module = sfp_ai_subdomain()
        self.assertIn("INTERNET_NAME", module.producedEvents())
        self.assertIn("AI_INFRASTRUCTURE_DETECTED", module.producedEvents())

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()
