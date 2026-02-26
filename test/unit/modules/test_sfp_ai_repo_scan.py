import pytest
import unittest

from modules.sfp_ai_repo_scan import sfp_ai_repo_scan
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiRepoScan(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_repo_scan()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_repo_scan()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_repo_scan()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_repo_scan()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_repo_scan()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_repo_scan()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_ai_file_patterns_should_be_list(self):
        module = sfp_ai_repo_scan()
        self.assertIsInstance(module.AI_FILE_PATTERNS, list)
        self.assertGreater(len(module.AI_FILE_PATTERNS), 0)

    def test_ai_key_patterns_should_be_list(self):
        module = sfp_ai_repo_scan()
        self.assertIsInstance(module.AI_KEY_PATTERNS, list)
        self.assertGreater(len(module.AI_KEY_PATTERNS), 0)
        for pattern in module.AI_KEY_PATTERNS:
            self.assertIsInstance(pattern, tuple)
            self.assertEqual(len(pattern), 2)

    def test_ai_framework_keywords_should_be_list(self):
        module = sfp_ai_repo_scan()
        self.assertIsInstance(module.AI_FRAMEWORK_KEYWORDS, list)
        self.assertGreater(len(module.AI_FRAMEWORK_KEYWORDS), 0)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
