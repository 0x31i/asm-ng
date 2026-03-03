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
import re
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
            "RAW_RIR_DATA",
        ]

    def _find_h8mail(self):
        """Find the h8mail binary, checking common install locations."""
        exe = self.opts.get('h8mail_path', 'h8mail')

        if exe != 'h8mail' or shutil.which('h8mail'):
            return exe

        candidates = [
            os.path.expanduser(f'~/Library/Python/{sys.version_info.major}.{sys.version_info.minor}/bin/h8mail'),
            os.path.expanduser('~/.local/bin/h8mail'),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'venv', 'bin', 'h8mail'),
            '/usr/local/bin/h8mail',
            '/opt/venv/bin/h8mail',
        ]
        for match in glob.glob(os.path.expanduser('~/Library/Python/3.*/bin/h8mail')):
            if match not in candidates:
                candidates.insert(0, match)
        for candidate in candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                self.debug(f"Auto-detected h8mail at: {candidate}")
                return candidate

        return exe

    def _extract_json(self, output):
        """Extract JSON object from h8mail's mixed stdout (JSON + ANSI banner).

        h8mail writes JSON first, then its colored banner text to stdout.
        We need to find and extract just the JSON portion.
        """
        # Strip ANSI escape codes for cleaner parsing
        ansi_re = re.compile(r'\x1b\[[0-9;]*m')
        clean = ansi_re.sub('', output).strip()

        # Try to find a JSON object or array at the start
        for start_char, end_char in [('{', '}'), ('[', ']')]:
            idx = clean.find(start_char)
            if idx == -1:
                continue

            # Find matching closing bracket by counting depth
            depth = 0
            for i in range(idx, len(clean)):
                if clean[i] == start_char:
                    depth += 1
                elif clean[i] == end_char:
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(clean[idx:i + 1])
                        except json.JSONDecodeError:
                            break

        return None

    def _format_breach_detail(self, email, source, cred=None, cred_type=None):
        """Format a human-readable breach detail string."""
        parts = [f"Email: {email}"]
        parts.append(f"Source: {source}")
        if cred:
            if cred_type == 'hash':
                hash_type = {32: 'MD5', 40: 'SHA1', 64: 'SHA256', 128: 'SHA512'}.get(len(cred), 'Unknown')
                parts.append(f"Hash ({hash_type}): {cred}")
            else:
                parts.append(f"Password: {cred[:3]}{'*' * (len(cred) - 3)}")
        parts.append("Found by: h8mail breach database search")
        return "\n".join(parts)

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

        exe = self._find_h8mail()

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

        # Extract JSON from mixed output (h8mail writes JSON + ANSI banner to stdout)
        data = self._extract_json(output)

        if data is not None:
            self._processJsonResults(data, eventData, event)
        else:
            self.debug("Could not extract JSON from h8mail output, trying text parsing")
            self._processTextResults(output, eventData, event)

    def _processJsonResults(self, data, email, event):
        """Process h8mail JSON results with full breach details."""
        targets = data if isinstance(data, list) else data.get('targets', [data])

        for target_info in targets:
            if self.checkForStop():
                return

            if not isinstance(target_info, dict):
                continue

            # Check if any breaches were found
            pwn_num = target_info.get('pwn_num', 0)
            breaches = target_info.get('data', target_info.get('breaches', []))

            if not isinstance(breaches, list) or not breaches:
                if pwn_num == 0:
                    self.debug(f"h8mail: no breaches found for {email}")
                continue

            # Emit RAW_RIR_DATA with the full structured results
            raw_data = json.dumps(target_info, indent=2)
            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                f"h8mail breach results for {email}:\n{raw_data}",
                self.__class__.__name__,
                event,
            )
            self.notifyListeners(evt)

            # Process each breach entry
            breach_sources = []
            for breach in breaches:
                if not isinstance(breach, (dict, list)):
                    continue

                if isinstance(breach, list) and len(breach) >= 2:
                    source = str(breach[0]).strip()
                    cred = str(breach[1]).strip() if breach[1] else ''
                elif isinstance(breach, dict):
                    source = breach.get('source', breach.get('name', breach.get('breach_name', 'Unknown')))
                    cred = breach.get('password', breach.get('hash', breach.get('credential', '')))
                else:
                    continue

                if source:
                    breach_sources.append(source)

                if cred:
                    # Determine if it's a password or hash
                    is_hash = (len(cred) in (32, 40, 64, 128)
                               and all(c in '0123456789abcdefABCDEF' for c in cred))

                    if is_hash:
                        hash_type = {32: 'MD5', 40: 'SHA1', 64: 'SHA256', 128: 'SHA512'}.get(len(cred), 'hash')
                        detail = self._format_breach_detail(email, source, cred, 'hash')
                        evt = SpiderFootEvent(
                            "HASH_COMPROMISED",
                            f"{email}:{cred} [Breach: {source} | Type: {hash_type} | Tool: h8mail]",
                            self.__class__.__name__,
                            event,
                        )
                        self.notifyListeners(evt)
                    else:
                        detail = self._format_breach_detail(email, source, cred, 'password')
                        evt = SpiderFootEvent(
                            "PASSWORD_COMPROMISED",
                            f"{email}:{cred} [Breach: {source} | Tool: h8mail]",
                            self.__class__.__name__,
                            event,
                        )
                        self.notifyListeners(evt)

                # Emit EMAILADDR_COMPROMISED with breach detail
                evt2 = SpiderFootEvent(
                    "EMAILADDR_COMPROMISED",
                    f"{email} [Breach: {source} | Pwned in {pwn_num} breach(es) | Tool: h8mail]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt2)

            # If breaches had no credential data but pwn_num > 0, still report
            if pwn_num > 0 and not breach_sources:
                evt = SpiderFootEvent(
                    "EMAILADDR_COMPROMISED",
                    f"{email} [Found in {pwn_num} breach(es) | Tool: h8mail]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

    def _processTextResults(self, output, email, event):
        """Parse h8mail text output as fallback when JSON extraction fails.

        Only emit events when actual breach data is found — not from
        h8mail status/banner lines that happen to contain the email.
        """
        # Strip ANSI escape codes
        ansi_re = re.compile(r'\x1b\[[0-9;]*m')
        clean = ansi_re.sub('', output)

        # Check for "Not Compromised" in the recap section
        if 'Not Compromised' in clean:
            self.debug(f"h8mail text output says 'Not Compromised' for {email}")
            return

        # Look for actual breach indicators
        breach_sources = []
        found_creds = []

        for line in clean.split('\n'):
            line = line.strip()
            if not line:
                continue

            # h8mail breach lines look like:
            # [>] source_name: email:password
            # or: [>] Found in breach: BreachName
            # or: email:password [source]

            # Pattern 1: "Found in breach:" or "Found in:" lines
            found_match = re.search(r'[Ff]ound\s+in\s+(?:breach:?\s*)?(.+)', line)
            if found_match and email.lower() not in found_match.group(1).lower():
                breach_sources.append(found_match.group(1).strip())
                continue

            # Pattern 2: email:password lines (actual credential leaks)
            if email.lower() in line.lower() and ':' in line:
                # Extract the part after the email
                parts = line.split(email, 1)
                if len(parts) > 1:
                    remainder = parts[1].strip()
                    if remainder.startswith(':') and len(remainder) > 1:
                        cred = remainder[1:].strip().split()[0]  # Take first word after :
                        if cred and len(cred) > 2 and cred not in ('[', ']', '>', '|'):
                            found_creds.append(cred)

            # Pattern 3: "pwn_num" or breach count
            pwn_match = re.search(r'(\d+)\s+breach', line, re.IGNORECASE)
            if pwn_match:
                count = int(pwn_match.group(1))
                if count > 0 and not breach_sources:
                    breach_sources.append(f"{count} breach(es)")

        # Only emit events if we actually found breach evidence
        if not breach_sources and not found_creds:
            self.debug(f"h8mail text: no breach evidence found for {email}")
            return

        source_str = ', '.join(breach_sources) if breach_sources else 'h8mail'

        for cred in found_creds:
            is_hash = (len(cred) in (32, 40, 64, 128)
                       and all(c in '0123456789abcdefABCDEF' for c in cred))

            if is_hash:
                hash_type = {32: 'MD5', 40: 'SHA1', 64: 'SHA256', 128: 'SHA512'}.get(len(cred), 'hash')
                evt = SpiderFootEvent(
                    "HASH_COMPROMISED",
                    f"{email}:{cred} [Breach: {source_str} | Type: {hash_type} | Tool: h8mail]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent(
                    "PASSWORD_COMPROMISED",
                    f"{email}:{cred} [Breach: {source_str} | Tool: h8mail]",
                    self.__class__.__name__,
                    event,
                )
                self.notifyListeners(evt)

        evt = SpiderFootEvent(
            "EMAILADDR_COMPROMISED",
            f"{email} [Breach: {source_str} | Tool: h8mail]",
            self.__class__.__name__,
            event,
        )
        self.notifyListeners(evt)

# End of sfp_tool_h8mail class
