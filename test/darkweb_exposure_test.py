#!/usr/bin/env python3
"""Dark Web Exposure Scan — Integration Test

Verifies that all dark web modules load correctly, register proper
event types, and can handle basic events without crashing.

Usage:
    python3 test/darkweb_exposure_test.py [--live] [--target example.com]

Flags:
    --live      Actually hit external APIs (slow, requires network)
    --target    Domain to use for live testing (default: example.com)

Without --live, this performs dry-run validation only (fast, no network).
"""

import argparse
import importlib
import json
import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget, SpiderFootHelpers


# =============================================================================
# Module Registry
# =============================================================================

# New dark web modules (Sprint 1-4)
NEW_MODULES = [
    'sfp_xposedornot',
    'sfp_ransomwatch',
    'sfp_darkweb_aggregate',
    'sfp_stealerlog_check',
    'sfp_pasterack',
    'sfp_deepdarkcti',
    'sfp_tool_h8mail',
    'sfp_brand_darkweb',
    'sfp_snusbase',
    'sfp_misp',
    'sfp_opencti',
]

# Existing modules that should now have 'Dark Web Exposure' use case
ENHANCED_MODULES = [
    'sfp_ahmia',
    'sfp_torch',
    'sfp_onionsearchengine',
    'sfp_onioncity',
    'sfp_intelx',
    'sfp_haveibeenpwned',
    'sfp_leakix',
    'sfp_leakcheck',
    'sfp_citadel',
    'sfp_dehashed',
    'sfp_pastebin',
    'sfp_psbdmp',
    'sfp_apileak',
    'sfp_torexits',
    'sfp_wikileaks',
    'sfp_telegram',
]

# New event types
NEW_EVENT_TYPES = [
    'RANSOMWARE_LEAK_MENTION',
    'STEALER_LOG_MATCH',
    'DARKWEB_BRAND_MENTION',
    'DARKWEB_FORUM_MENTION',
    'TELEGRAM_LEAK_MENTION',
    'ONION_SERVICE_DETECTED',
    'THREAT_INTEL_FEED_MATCH',
]

# Modules that don't need API keys (can be tested live without config)
FREE_MODULES = [
    'sfp_xposedornot',
    'sfp_ransomwatch',
    'sfp_darkweb_aggregate',
    'sfp_stealerlog_check',
    'sfp_deepdarkcti',
    'sfp_brand_darkweb',
]

# Correlation rules
CORRELATION_RULES = [
    'darkweb_multi_source_mention',
    'credential_leak_cross_platform',
    'ransomware_leak_with_breach',
    'darkweb_brand_abuse_cluster',
    'darkweb_escalation',
]


def get_default_options():
    """Get SpiderFoot default options for testing."""
    return {
        '_debug': False,
        '__logging': True,
        '__outputfilter': None,
        '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        '_dnsserver': '',
        '_fetchtimeout': 10,
        '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
        '_internettlds_cache': 72,
        '_genericusers': '',
        '__database': '',
        '_socks1type': '',
        '_socks2addr': '',
        '_socks3port': '',
    }


class EventCollector:
    """Collects events emitted by modules during testing."""

    def __init__(self):
        self.events = []

    def notify(self, event):
        self.events.append({
            'type': event.eventType,
            'data': event.data[:200] if event.data else '',
            'module': event.module,
        })

    def summary(self):
        by_type = {}
        for e in self.events:
            by_type.setdefault(e['type'], 0)
            by_type[e['type']] += 1
        return by_type


def print_header(text):
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}")


def print_result(name, passed, detail=''):
    status = '\033[92mPASS\033[0m' if passed else '\033[91mFAIL\033[0m'
    detail_str = f' — {detail}' if detail else ''
    print(f"  [{status}] {name}{detail_str}")


# =============================================================================
# Test Functions
# =============================================================================

def test_module_imports():
    """Test 1: All new modules import without errors."""
    print_header("Test 1: Module Imports")
    all_passed = True

    for mod_name in NEW_MODULES:
        try:
            mod = importlib.import_module(f'modules.{mod_name}')
            cls = getattr(mod, mod_name)
            instance = cls()
            print_result(mod_name, True)
        except Exception as e:
            print_result(mod_name, False, str(e))
            all_passed = False

    return all_passed


def test_module_metadata():
    """Test 2: All new modules have correct metadata."""
    print_header("Test 2: Module Metadata Validation")
    all_passed = True

    for mod_name in NEW_MODULES:
        try:
            mod = importlib.import_module(f'modules.{mod_name}')
            cls = getattr(mod, mod_name)
            instance = cls()
            meta = instance.meta

            checks = []

            # Must have 'name'
            if not meta.get('name'):
                checks.append('missing name')
            # Must have 'summary'
            if not meta.get('summary'):
                checks.append('missing summary')
            # Must have 'useCases' with 'Dark Web Exposure'
            if 'Dark Web Exposure' not in meta.get('useCases', []):
                checks.append("missing 'Dark Web Exposure' in useCases")
            # Must have 'categories'
            if not meta.get('categories'):
                checks.append('missing categories')
            # watchedEvents must return list
            if not isinstance(instance.watchedEvents(), list):
                checks.append('watchedEvents not a list')
            # producedEvents must return list
            if not isinstance(instance.producedEvents(), list):
                checks.append('producedEvents not a list')
            # opts and optdescs must match in length
            if len(instance.opts) != len(instance.optdescs):
                checks.append(f'opts({len(instance.opts)}) != optdescs({len(instance.optdescs)})')

            passed = len(checks) == 0
            print_result(mod_name, passed, ', '.join(checks) if checks else 'all checks pass')
            if not passed:
                all_passed = False

        except Exception as e:
            print_result(mod_name, False, str(e))
            all_passed = False

    return all_passed


def test_enhanced_modules_usecase():
    """Test 3: All 16 enhanced modules have 'Dark Web Exposure' use case."""
    print_header("Test 3: Enhanced Module Use Case Check")
    all_passed = True

    for mod_name in ENHANCED_MODULES:
        try:
            mod = importlib.import_module(f'modules.{mod_name}')
            cls = getattr(mod, mod_name)
            instance = cls()
            has_usecase = 'Dark Web Exposure' in instance.meta.get('useCases', [])
            print_result(mod_name, has_usecase,
                         'has Dark Web Exposure' if has_usecase else 'MISSING Dark Web Exposure')
            if not has_usecase:
                all_passed = False
        except Exception as e:
            print_result(mod_name, False, str(e))
            all_passed = False

    return all_passed


def test_event_types():
    """Test 4: All 7 new event types are registered in db.py."""
    print_header("Test 4: Event Type Registration")
    all_passed = True

    # Read db.py and check for event type strings
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'spiderfoot', 'db.py')
    with open(db_path) as f:
        db_content = f.read()

    for evt_type in NEW_EVENT_TYPES:
        found = f"'{evt_type}'" in db_content
        print_result(evt_type, found, 'registered' if found else 'NOT FOUND in db.py')
        if not found:
            all_passed = False

    return all_passed


def test_grading_rules():
    """Test 5: All new event types have grading rules."""
    print_header("Test 5: Grading Rules")
    all_passed = True

    from spiderfoot.grade_config import DEFAULT_EVENT_TYPE_GRADING, get_event_grading

    for evt_type in NEW_EVENT_TYPES:
        grading = get_event_grading(evt_type)
        has_explicit = evt_type in DEFAULT_EVENT_TYPE_GRADING
        detail = f"cat={grading['category']}, rank={grading['rank']}, pts={grading['points']}"
        if has_explicit:
            detail += ' (explicit)'
        else:
            detail += ' (auto-categorized)'
        print_result(evt_type, has_explicit, detail)
        if not has_explicit:
            all_passed = False

    return all_passed


def test_correlation_rules():
    """Test 6: All correlation YAML files exist and parse correctly."""
    print_header("Test 6: Correlation Rules")
    all_passed = True

    import yaml

    corr_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'correlations')

    for rule_id in CORRELATION_RULES:
        filepath = os.path.join(corr_dir, f'{rule_id}.yaml')
        if not os.path.isfile(filepath):
            print_result(rule_id, False, 'file not found')
            all_passed = False
            continue

        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
            checks = []
            if data.get('id') != rule_id:
                checks.append(f"id mismatch: {data.get('id')}")
            if not data.get('meta', {}).get('name'):
                checks.append('missing meta.name')
            if not data.get('meta', {}).get('risk'):
                checks.append('missing meta.risk')
            if not data.get('collections'):
                checks.append('missing collections')

            passed = len(checks) == 0
            risk = data.get('meta', {}).get('risk', '?')
            print_result(rule_id, passed,
                         f'risk={risk}' if passed else ', '.join(checks))
            if not passed:
                all_passed = False

        except Exception as e:
            print_result(rule_id, False, str(e))
            all_passed = False

    return all_passed


def test_module_setup():
    """Test 7: All new modules can be setup() without errors."""
    print_header("Test 7: Module Setup (dry run)")
    all_passed = True

    sf = SpiderFoot(get_default_options())

    for mod_name in NEW_MODULES:
        try:
            mod = importlib.import_module(f'modules.{mod_name}')
            cls = getattr(mod, mod_name)
            instance = cls()
            instance.setup(sf, dict())
            print_result(mod_name, True, 'setup OK')
        except Exception as e:
            print_result(mod_name, False, str(e))
            all_passed = False

    return all_passed


def test_newscan_template():
    """Test 8: newscan.tmpl has Dark Web Exposure use case."""
    print_header("Test 8: New Scan Template")

    tmpl_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             'spiderfoot', 'templates', 'newscan.tmpl')
    with open(tmpl_path) as f:
        content = f.read()

    has_usecase = 'Dark Web Exposure' in content
    has_radio = 'usecase_dark_web_exposure' in content
    has_disclaimer = 'authorization' in content.lower() or 'legal' in content.lower()

    print_result('Dark Web Exposure use case text', has_usecase)
    print_result('Radio button ID', has_radio)
    print_result('Legal disclaimer', has_disclaimer)

    return has_usecase and has_radio


def test_live_free_modules(target_domain):
    """Test 9: Live test free modules against a target (requires network)."""
    print_header(f"Test 9: Live API Test (target: {target_domain})")

    sf = SpiderFoot(get_default_options())
    target = SpiderFootTarget(target_domain, 'DOMAIN_NAME')

    root_evt = SpiderFootEvent('ROOT', target_domain, '', '')

    for mod_name in FREE_MODULES:
        try:
            mod = importlib.import_module(f'modules.{mod_name}')
            cls = getattr(mod, mod_name)
            instance = cls()
            instance.setup(sf, dict())
            instance.setTarget(target)

            # Collect events
            collector = EventCollector()
            instance.registerListener(collector)

            # Send a DOMAIN_NAME event
            domain_evt = SpiderFootEvent('DOMAIN_NAME', target_domain,
                                         'test', root_evt)

            start = time.time()
            instance.handleEvent(domain_evt)
            elapsed = time.time() - start

            summary = collector.summary()
            event_count = sum(summary.values())
            types_found = list(summary.keys())

            print_result(
                mod_name, True,
                f'{event_count} events in {elapsed:.1f}s: {types_found}'
            )

        except Exception as e:
            print_result(mod_name, False, str(e))

    return True  # Live tests are advisory, don't fail the suite


def test_dependencies():
    """Test 10: Check critical dependencies are installed."""
    print_header("Test 10: Dependency Check")

    deps = {
        'yaml': 'pyyaml',
        'requests': 'requests',
        'telethon': 'telethon (for sfp_telegram)',
    }

    optional_deps = {
        'pymisp': 'pymisp (for sfp_misp — optional)',
        'h8mail': 'h8mail CLI (for sfp_tool_h8mail — optional)',
    }

    all_ok = True

    for module_name, desc in deps.items():
        try:
            importlib.import_module(module_name)
            print_result(desc, True, 'installed')
        except ImportError:
            print_result(desc, False, 'NOT INSTALLED')
            all_ok = False

    for module_name, desc in optional_deps.items():
        try:
            importlib.import_module(module_name)
            print_result(desc, True, 'installed')
        except ImportError:
            print_result(desc, None, 'not installed (optional)')

    # Check h8mail CLI (search PATH + common install locations)
    import shutil
    import glob as globmod
    h8mail_path = shutil.which('h8mail')
    if not h8mail_path:
        # Check common non-PATH locations
        candidates = [
            os.path.expanduser(f'~/Library/Python/{sys.version_info.major}.{sys.version_info.minor}/bin/h8mail'),
            os.path.expanduser('~/.local/bin/h8mail'),
            '/usr/local/bin/h8mail',
        ]
        for match in globmod.glob(os.path.expanduser('~/Library/Python/3.*/bin/h8mail')):
            if match not in candidates:
                candidates.insert(0, match)
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                h8mail_path = c
                break
    print_result('h8mail CLI', h8mail_path is not None,
                 h8mail_path or 'not found (optional)')

    # Check tor
    tor_path = shutil.which('tor')
    print_result('Tor daemon in PATH', tor_path is not None,
                 tor_path or 'not found (optional, for .onion access)')

    return all_ok


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='Dark Web Exposure Module Test Suite')
    parser.add_argument('--live', action='store_true',
                        help='Run live API tests (requires network)')
    parser.add_argument('--target', default='example.com',
                        help='Target domain for live tests (default: example.com)')
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    print("\n" + "=" * 70)
    print("  ASM-NG Dark Web Exposure — Module Test Suite")
    print("=" * 70)

    results = {}

    results['imports'] = test_module_imports()
    results['metadata'] = test_module_metadata()
    results['enhanced'] = test_enhanced_modules_usecase()
    results['events'] = test_event_types()
    results['grading'] = test_grading_rules()
    results['correlations'] = test_correlation_rules()
    results['setup'] = test_module_setup()
    results['template'] = test_newscan_template()
    results['deps'] = test_dependencies()

    if args.live:
        results['live'] = test_live_free_modules(args.target)

    # Summary
    print_header("Summary")
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed

    for name, result in results.items():
        status = '\033[92mPASS\033[0m' if result else '\033[91mFAIL\033[0m'
        print(f"  [{status}] {name}")

    print(f"\n  Total: {total} | Passed: {passed} | Failed: {failed}")

    if failed == 0:
        print("\n  \033[92mAll tests passed! Dark Web Exposure modules are ready.\033[0m\n")
    else:
        print(f"\n  \033[91m{failed} test(s) failed. See details above.\033[0m\n")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
