import pytest
import unittest

from modules.sfp_ai_gpu_cluster import sfp_ai_gpu_cluster
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiGpuCluster(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_gpu_cluster()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_gpu_cluster()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_gpu_cluster()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_gpu_cluster()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_gpu_cluster()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_gpu_cluster()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_gpu_probes_should_be_list(self):
        module = sfp_ai_gpu_cluster()
        self.assertIsInstance(module.GPU_PROBES, list)
        self.assertGreater(len(module.GPU_PROBES), 0)
        for probe in module.GPU_PROBES:
            self.assertIsInstance(probe, tuple)
            self.assertEqual(len(probe), 4)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
