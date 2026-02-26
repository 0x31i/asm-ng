import pytest
import unittest
import json

from modules.sfp_ai_mcp_detect import sfp_ai_mcp_detect
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiMcpDetect(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_mcp_detect()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_mcp_detect()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_mcp_detect()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_mcp_detect()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_mcp_detect()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_mcp_methods_should_be_list(self):
        module = sfp_ai_mcp_detect()
        self.assertIsInstance(module.MCP_METHODS, list)
        self.assertGreater(len(module.MCP_METHODS), 0)
        # Each method should be a tuple of (method, params, description)
        for method_tuple in module.MCP_METHODS:
            self.assertEqual(len(method_tuple), 3)

    def test_build_jsonrpc_request(self):
        module = sfp_ai_mcp_detect()
        payload = module._build_jsonrpc_request("tools/list", None, 1)
        data = json.loads(payload)
        self.assertEqual(data['jsonrpc'], '2.0')
        self.assertEqual(data['method'], 'tools/list')
        self.assertEqual(data['id'], 1)
        self.assertNotIn('params', data)

    def test_build_jsonrpc_request_with_params(self):
        module = sfp_ai_mcp_detect()
        params = {"key": "value"}
        payload = module._build_jsonrpc_request("initialize", params, 2)
        data = json.loads(payload)
        self.assertEqual(data['params'], {"key": "value"})

    def test_mcp_candidate_ports_should_be_list(self):
        module = sfp_ai_mcp_detect()
        self.assertIsInstance(module.MCP_CANDIDATE_PORTS, list)
        self.assertIn('8080', module.MCP_CANDIDATE_PORTS)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_mcp_detect()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    @safe_recursion(max_depth=5)
    def test_handleEvent_non_mcp_infrastructure(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_mcp_detect()
        module.setup(sf, dict())

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        evt = SpiderFootEvent('ROOT', 'example.com', '', '')
        # AI_INFRASTRUCTURE_DETECTED that doesn't mention MCP should be skipped
        ai_evt = SpiderFootEvent(
            "AI_INFRASTRUCTURE_DETECTED",
            "Ollama detected on 192.168.1.1:11434 (http)",
            "sfp_ai_fingerprint", evt)
        result = module.handleEvent(ai_evt)
        self.assertIsNone(result)

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
