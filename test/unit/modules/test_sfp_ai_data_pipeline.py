import pytest
import unittest

from modules.sfp_ai_data_pipeline import sfp_ai_data_pipeline
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiDataPipeline(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_data_pipeline()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_data_pipeline()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_data_pipeline()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_data_pipeline()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_data_pipeline()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_data_pipeline()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_pipeline_probes_should_be_list(self):
        module = sfp_ai_data_pipeline()
        self.assertIsInstance(module.PIPELINE_PROBES, list)
        self.assertGreater(len(module.PIPELINE_PROBES), 0)
        for probe in module.PIPELINE_PROBES:
            self.assertIsInstance(probe, tuple)
            self.assertGreaterEqual(len(probe), 4)

    def test_ml_dag_keywords_should_be_list(self):
        module = sfp_ai_data_pipeline()
        self.assertIsInstance(module.ML_DAG_KEYWORDS, list)
        self.assertGreater(len(module.ML_DAG_KEYWORDS), 0)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
