import pytest
import unittest

from modules.sfp_ai_vulnscan import sfp_ai_vulnscan
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiVulnscan(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_vulnscan()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_vulnscan()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_vulnscan()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_vulnscan()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_vulnscan()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_builtin_checks_should_be_list(self):
        module = sfp_ai_vulnscan()
        self.assertIsInstance(module.BUILTIN_CHECKS, list)
        self.assertGreater(len(module.BUILTIN_CHECKS), 0)
        # Each check should be a 6-tuple
        for check in module.BUILTIN_CHECKS:
            self.assertEqual(len(check), 6)

    def test_extract_host_port_scheme_ip(self):
        module = sfp_ai_vulnscan()
        host, port, scheme = module._extract_host_port_scheme(
            "Ollama detected on 192.168.1.1:11434 (http)")
        self.assertEqual(host, "192.168.1.1")
        self.assertEqual(port, "11434")

    def test_extract_host_port_scheme_url(self):
        module = sfp_ai_vulnscan()
        host, port, scheme = module._extract_host_port_scheme(
            "http://10.0.0.1:8000")
        self.assertEqual(host, "10.0.0.1")
        self.assertEqual(port, "8000")
        self.assertEqual(scheme, "http")

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_vulnscan()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def test_has_tool_flag(self):
        module = sfp_ai_vulnscan()
        self.assertIn('tool', module.meta['flags'])

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
