import pytest
import unittest

from modules.sfp_brand_darkweb import sfp_brand_darkweb
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase


class TestModuleBrandDarkweb(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_brand_darkweb()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_brand_darkweb()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_brand_darkweb()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_brand_darkweb()
        self.assertIsInstance(module.producedEvents(), list)

    def test_generatePermutations(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_brand_darkweb()
        module.setup(sf, dict())

        perms = module.generatePermutations('example.com')
        self.assertIsInstance(perms, list)
        self.assertTrue(len(perms) > 0)
        # Original should not be in permutations
        self.assertNotIn('example', perms)

    def test_handleEvent_domain_no_result(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_brand_darkweb()
        module.setup(sf, dict())

        target_value = 'example.com'
        target_type = 'DOMAIN_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example.com'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        event = SpiderFootEvent('DOMAIN_NAME', 'example.com',
                                self.__class__.__name__, evt)
        result = module.handleEvent(event)
        self.assertIsNone(result)

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()
