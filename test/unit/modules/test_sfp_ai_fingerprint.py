import pytest
import unittest

from modules.sfp_ai_fingerprint import sfp_ai_fingerprint
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiFingerprint(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_fingerprint()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_fingerprint()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_fingerprint()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_fingerprint()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_fingerprint()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_ai_ports_should_be_dict(self):
        module = sfp_ai_fingerprint()
        self.assertIsInstance(module.AI_PORTS, dict)
        self.assertIn('11434', module.AI_PORTS)  # Ollama
        self.assertIn('5000', module.AI_PORTS)   # MLflow
        self.assertIn('8000', module.AI_PORTS)    # Triton/vLLM

    def test_banner_patterns_should_be_list(self):
        module = sfp_ai_fingerprint()
        self.assertIsInstance(module.AI_BANNER_PATTERNS, list)
        self.assertGreater(len(module.AI_BANNER_PATTERNS), 0)

    def test_fingerprint_from_banner_ollama(self):
        module = sfp_ai_fingerprint()
        result = module._fingerprint_from_banner("Ollama/0.4.1")
        self.assertEqual(result, "Ollama")

    def test_fingerprint_from_banner_triton(self):
        module = sfp_ai_fingerprint()
        result = module._fingerprint_from_banner("tritonserver 2.40.0")
        self.assertEqual(result, "NVIDIA Triton")

    def test_fingerprint_from_banner_no_match(self):
        module = sfp_ai_fingerprint()
        result = module._fingerprint_from_banner("Apache/2.4.52")
        self.assertIsNone(result)

    def test_extract_host_port(self):
        module = sfp_ai_fingerprint()
        host, port = module._extract_host_port("192.168.1.1:11434")
        self.assertEqual(host, "192.168.1.1")
        self.assertEqual(port, "11434")

    def test_extract_host_port_no_port(self):
        module = sfp_ai_fingerprint()
        host, port = module._extract_host_port("192.168.1.1")
        self.assertIsNone(host)
        self.assertIsNone(port)

    @safe_recursion(max_depth=5)
    def test_handleEvent_non_ai_port(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_fingerprint()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        # Port 80 is not an AI port, should not trigger fingerprinting
        port_evt = SpiderFootEvent("TCP_PORT_OPEN", "192.168.1.1:80",
                                   "sfp_portscan_tcp", evt)
        result = module.handleEvent(port_evt)
        self.assertIsNone(result)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()
