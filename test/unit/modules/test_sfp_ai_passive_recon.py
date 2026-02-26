import pytest
import unittest

from modules.sfp_ai_passive_recon import sfp_ai_passive_recon
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAiPassiveRecon(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_ai_passive_recon()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_passive_recon()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ai_passive_recon()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ai_passive_recon()
        self.assertIsInstance(module.producedEvents(), list)

    def test_meta_should_have_required_keys(self):
        module = sfp_ai_passive_recon()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)

    def test_shodan_dorks_should_be_list(self):
        module = sfp_ai_passive_recon()
        self.assertIsInstance(module.SHODAN_AI_DORKS, list)
        self.assertGreater(len(module.SHODAN_AI_DORKS), 0)
        # Each dork should be a tuple of (query_template, service_name)
        for dork in module.SHODAN_AI_DORKS:
            self.assertEqual(len(dork), 2)
            self.assertIn('{target}', dork[0])

    @safe_recursion(max_depth=5)
    def test_handleEvent_no_api_key(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_ai_passive_recon()
        module.setup(sf, dict())

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        evt = SpiderFootEvent('ROOT', 'example.com', '', '')
        domain_evt = SpiderFootEvent(
            "DOMAIN_NAME", "example.com", "sfp_dnsresolve", evt)
        # Should return without error when no API key is set
        result = module.handleEvent(domain_evt)
        self.assertIsNone(result)

    def test_ai_attack_surface_in_usecases(self):
        module = sfp_ai_passive_recon()
        self.assertIn('AI Attack Surface', module.meta['useCases'])

    def setUp(self):
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        super().tearDown()
