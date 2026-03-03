# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_h8mail
# Purpose:     SpiderFoot plug-in for using h8mail to perform email OSINT
#              and breach hunting.
#              Tool: https://github.com/khast3x/h8mail
#
# Author:      ASM-NG Team
#
# Created:     2026-03-02
# Copyright:   (c) ASM-NG Team
# Licence:     MIT
# -------------------------------------------------------------------------------

import glob
import json
import os
import shutil
import sys
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_tool_h8mail(SpiderFootPlugin):

    meta = {
        'name': "Tool - h8mail",
        'summary': "Email OSINT and breach hunting tool. Finds breached credentials "
        "for email addresses using local and remote breach databases.",
        'flags': ["tool", "slow"],
        'useCases': ["Investigate", "Dark Web Exposure"],
        'categories': ["Leaks, Dumps and Breaches"],
        'toolDetails': {
            'name': "h8mail",
            'description': "Email OSINT & Password Breach Hunting Tool. "
            "Uses multiple breach databases to find compromised credentials.",
            'website': "https://github.com/khast3x/h8mail",
            'repository': "https://github.com/khast3x/h8mail",
        }
    }

    opts = {
        'h8mail_path': 'h8mail',
        'config_file': '',
        'timeout': 120,
    }

    optdescs = {
        'h8mail_path': "Path to the h8mail binary (or just 'h8mail' if in PATH).",
        'config_file': "Path to h8mail config file with API keys (optional).",
        'timeout': "Timeout in seconds for h8mail execution.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["EMAILADDR"]

    def producedEvents(self):
        return [
            "EMAILADDR_COMPROMISED",
            "PASSWORD_COMPROMISED",
            "HASH_COMPROMISED",
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        exe = self.opts.get('h8mail_path', 'h8mail')

        # Auto-detect h8mail if the default 'h8mail' is not found on PATH
        if exe == 'h8mail' and not shutil.which('h8mail'):
            candidates = [
                # macOS pip --user install
                os.path.expanduser(f'~/Library/Python/{sys.version_info.major}.{sys.version_info.minor}/bin/h8mail'),
                # Linux pip --user install
                os.path.expanduser('~/.local/bin/h8mail'),
                # Common venv locations
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'venv', 'bin', 'h8mail'),
                '/usr/local/bin/h8mail',
                '/opt/venv/bin/h8mail',
            ]
            # Also check ~/Library/Python/3.*/bin/h8mail for macOS version mismatches
            for match in glob.glob(os.path.expanduser('~/Library/Python/3.*/bin/h8mail')):
                if match not in candidates:
                    candidates.insert(0, match)
            for candidate in candidates:
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    exe = candidate
                    self.debug(f"Auto-detected h8mail at: {exe}")
                    break

        # Build command
        args = [exe, '-t', eventData, '-j', '/dev/stdout']

        config_file = self.opts.get('config_file', '')
        if config_file and os.path.isfile(config_file):
            args.extend(['-c', config_file])

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=self.opts.get('timeout', 120))
        except FileNotFoundError:
            self.error(f"h8mail not found at: {exe}. Install with: pip install h8mail")
            self.errorState = True
            return
        except TimeoutExpired:
            p.kill()
            self.error(f"h8mail timed out after {self.opts.get('timeout', 120)}s")
            return
        except Exception as e:
            self.error(f"Error running h8mail: {e}")
            self.errorState = True
            return

        if p.returncode != 0:
            self.debug(f"h8mail returned non-zero exit code: {p.returncode}")
            if stderr:
                self.debug(f"h8mail stderr: {stderr.decode('utf-8', errors='replace')}")

        output = stdout.decode('utf-8', errors='replace')

        if not output.strip():
            self.debug(f"No output from h8mail for: {eventData}")
            return

        # Parse JSON output
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # h8mail may output non-JSON; try to parse line by line
            self.debug("Could not parse h8mail JSON output, trying line parsing")
            self.parseTextOutput(output, eventData, event)
            return

        # Process h8mail JSON results
        targets = data if isinstance(data, list) else data.get('targets', [data])

        for target_info in targets:
            if self.checkForStop():
                return

            if not isinstance(target_info, dict):
                continue

            breaches = target_info.get('data', target_info.get('breaches', []))
            if not isinstance(breaches, list):
                continue

            for breach in breaches:
                if not isinstance(breach, (dict, list)):
                    continue

                if isinstance(breach, list) and len(breach) >= 2:
                    source = breach[0]
                    cred = breach[1]
                elif isinstance(breach, dict):
                    source = breach.get('source', breach.get('name', 'Unknown'))
                    cred = breach.get('password', breach.get('hash', ''))
                else:
                    continue

                if not cred:
                    continue

                # Determine if it's a password or hash
                if len(cred) in (32, 40, 64, 128) and all(c in '0123456789abcdefABCDEF' for c in cred):
                    evt = SpiderFootEvent(
                        "HASH_COMPROMISED",
                        f"{eventData}:{cred} [{source}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent(
                        "PASSWORD_COMPROMISED",
                        f"{eventData}:{cred} [{source}]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

                evt2 = SpiderFootEvent(
                    "EMAILADDR_COMPROMISED",
                    f"{eventData} [{source}]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)

    def parseTextOutput(self, output, email, event):
        """Parse h8mail text output as fallback."""
        for line in output.split('\n'):
            line = line.strip()
            if not line or email.lower() not in line.lower():
                continue

            # Look for password patterns like email:password
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    evt = SpiderFootEvent(
                        "EMAILADDR_COMPROMISED",
                        f"{email} [h8mail]",
                        self.__class__.__name__,
                        event,
                    )
                    self.notifyListeners(evt)
                    break

# End of sfp_tool_h8mail class
