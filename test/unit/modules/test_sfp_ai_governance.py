import pytest
import unittest

from modules.sfp_ai_governance import sfp_ai_governance
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiGovernance(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_governance()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_governance()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_governance()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_governance()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_governance()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_governance()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_governance_urls_should_be_list(self):
        module = sfp_ai_governance()
        self.assertIsInstance(module.GOVERNANCE_URLS, list)
        self.assertGreater(len(module.GOVERNANCE_URLS), 0)

    def test_ai_bot_agents_should_be_list(self):
        module = sfp_ai_governance()
        self.assertIsInstance(module.AI_BOT_AGENTS, list)
        self.assertGreater(len(module.AI_BOT_AGENTS), 0)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
