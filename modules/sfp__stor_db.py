# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stor_db
# Purpose:      SpiderFoot plug-in for storing events to the SQLite database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootPlugin


class sfp__stor_db(SpiderFootPlugin):
    """SpiderFoot plug-in for storing events to the SQLite database."""

    meta = {
        'name': "Database Storage",
        'summary': "Stores scan results into the back-end SQLite database. You will need this.",
        'flags': ["slow"]
    }

    _priority = 0
    opts = {
        # max bytes for any piece of info stored (0 = unlimited)
        'maxstorage': 1024,
        '_store': True
    }
    optdescs = {
        'maxstorage': "Maximum bytes to store for any piece of information retrieved (0 = unlimited.)"
    }

    def setup(self, sfc, userOpts=dict()):
        """Set up the module with user options.

        Args:
            sfc: SpiderFoot instance
            userOpts (dict): User options
        """
        self.sf = sfc
        self.errorState = False

        if not hasattr(sfc, 'dbh') or sfc.dbh is None:
            self.error("SpiderFoot database handle not initialized - cannot store events")
            self.errorState = True
            return

        self.__sfdb__ = self.sf.dbh

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        """Define the events this module is interested in for input.

        Returns:
            list: List of event types
        """
        return ["*"]

    def handleEvent(self, sfEvent):
        """Handle events sent to this module.

        Args:
            sfEvent: SpiderFoot event
        """
        if not self.opts['_store']:
            return

        if self.errorState:
            return

        if not self.__sfdb__:
            self.error("Database handle not available for storage")
            return

        if self.opts['maxstorage'] != 0 and len(sfEvent.data) > self.opts['maxstorage']:
            self.debug("Storing an event: " + sfEvent.eventType)
            self.__sfdb__.scanEventStore(
                self.getScanId(), sfEvent, self.opts['maxstorage'])
            return

        self.debug("Storing an event: " + sfEvent.eventType)
        self.__sfdb__.scanEventStore(self.getScanId(), sfEvent)

# End of sfp__stor_db class
