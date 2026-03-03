import pytest
import unittest

from modules.sfp_darkweb_aggregate import sfp_darkweb_aggregate
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase


class TestModuleDarkwebAggregate(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_darkweb_aggregate()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_darkweb_aggregate()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_darkweb_aggregate()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_darkweb_aggregate()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_domain_no_result(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_darkweb_aggregate()
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
