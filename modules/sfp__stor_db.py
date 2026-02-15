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

        truncateSize = self.opts['maxstorage'] if self.opts['maxstorage'] != 0 and len(sfEvent.data) > self.opts['maxstorage'] else 0

        self.debug("Storing an event: " + sfEvent.eventType)

        # Retry with backoff for transient database errors (e.g. "database is locked").
        # Without this, a single IOError propagates to threadWorker() which sets
        # errorState=True and permanently kills all event storage for the scan.
        import time as _time
        max_attempts = 4
        for attempt in range(max_attempts):
            try:
                if truncateSize:
                    self.__sfdb__.scanEventStore(
                        self.getScanId(), sfEvent, truncateSize)
                else:
                    self.__sfdb__.scanEventStore(self.getScanId(), sfEvent)
                return  # success
            except IOError as e:
                err_str = str(e)
                if "locked" in err_str and attempt < max_attempts - 1:
                    _time.sleep(2 ** attempt)  # 1s, 2s, 4s
                    continue
                # Non-transient error or final attempt: log and drop this event
                # but do NOT let it propagate to threadWorker() which would
                # permanently disable storage via errorState=True
                self.error(f"Failed to store event {sfEvent.eventType} after {attempt + 1} attempts: {e}")
                return

# End of sfp__stor_db class
