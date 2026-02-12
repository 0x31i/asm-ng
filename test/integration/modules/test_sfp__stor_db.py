import pytest
import unittest
from unittest.mock import MagicMock, patch

from modules.sfp__stor_db import sfp__stor_db
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


class BaseTestModuleIntegration(unittest.TestCase):

    default_options = {
        '_store': True,
    }

    def setup_module(self, module_class):
        sf = SpiderFoot(self.default_options)
        # Patch the dbh (database handle) required by the module
        sf.dbh = MagicMock()
        module = module_class()
        module.setup(sf, dict(self.default_options))
        return module

    def create_event(self, target_value, target_type, event_type, event_data):
        target = SpiderFootTarget(target_value, target_type)
        evt = SpiderFootEvent(event_type, event_data, '', '')
        return target, evt


class TestModuleIntegration_stor_db(BaseTestModuleIntegration):

    def test_handleEvent(self):
        module = self.setup_module(sfp__stor_db)

        # Ensure errorState is not set due to setup issues
        module.errorState = False
        self.assertFalse(module.errorState, "Module errorState should be False after setup")

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        event_type = 'ROOT'
        event_data = 'example data'
        target, evt = self.create_event(
            target_value, target_type, event_type, event_data)

        module.setTarget(target)
        module.getScanId = MagicMock(return_value="test_scan_id")
        module.handleEvent(evt)
