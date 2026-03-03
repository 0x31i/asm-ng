import pytest
import unittest

from modules.sfp_tool_h8mail import sfp_tool_h8mail
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_base import SpiderFootTestBase


class TestModuleToolH8mail(SpiderFootTestBase):

    def test_opts(self):
        module = sfp_tool_h8mail()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_h8mail()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_tool_h8mail()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_tool_h8mail()
        self.assertIsInstance(module.producedEvents(), list)

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()
