import pytest
import unittest

from modules.sfp_ai_historical import sfp_ai_historical
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiHistorical(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_historical()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_historical()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_historical()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_historical()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_historical()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_historical()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_historical_ai_paths_should_be_list(self):
        module = sfp_ai_historical()
        self.assertIsInstance(module.HISTORICAL_AI_PATHS, list)
        self.assertGreater(len(module.HISTORICAL_AI_PATHS), 0)

    def test_cdx_api_base_should_be_string(self):
        module = sfp_ai_historical()
        self.assertIsInstance(module.CDX_API_BASE, str)
        self.assertTrue(module.CDX_API_BASE.startswith('https://'))

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
