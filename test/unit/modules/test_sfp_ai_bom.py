import pytest
import unittest

from modules.sfp_ai_bom import sfp_ai_bom
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiBom(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_bom()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_bom()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_bom()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_bom()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_bom()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_bom()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_watched_events_covers_ai_types(self):
        module = sfp_ai_bom()
        watched = module.watchedEvents()
        self.assertIn('AI_INFRASTRUCTURE_DETECTED', watched)
        self.assertIn('AI_MODEL_EXPOSED', watched)
        self.assertIn('AI_VECTORDB_EXPOSED', watched)
        self.assertIn('AI_AGENT_INFRASTRUCTURE_DETECTED', watched)
        self.assertIn('SOFTWARE_USED', watched)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
