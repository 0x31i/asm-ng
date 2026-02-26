import pytest
import unittest

from modules.sfp_ai_compliance import sfp_ai_compliance
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiCompliance(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_compliance()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_compliance()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_compliance()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_compliance()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_compliance()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_compliance()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_compliance_mapping_should_be_dict(self):
        module = sfp_ai_compliance()
        self.assertIsInstance(module.COMPLIANCE_MAPPING, dict)
        self.assertGreater(len(module.COMPLIANCE_MAPPING), 0)
        for event_type, checkpoints in module.COMPLIANCE_MAPPING.items():
            self.assertIsInstance(checkpoints, list)
            for cp in checkpoints:
                self.assertIn('framework', cp)
                self.assertIn('reference', cp)
                self.assertIn('gap_text', cp)
                self.assertIn('severity', cp)

    def test_frameworks_should_be_list(self):
        module = sfp_ai_compliance()
        self.assertIsInstance(module.FRAMEWORKS, list)
        self.assertGreater(len(module.FRAMEWORKS), 0)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
