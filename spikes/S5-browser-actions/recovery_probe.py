#!/usr/bin/env python3
"""Repeat existing S5 refused-navigation fixtures; failures remain failures."""
import argparse
import importlib.metadata
import json
import os
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCENARIOS = (
    'test_form_post_redirect_off_origin_refused',
    'test_fragment_token_redacted_in_url',
    'test_redirect_hop_off_origin_refused',
    'test_redirect_hop_on_origin_keeps_cookie',
)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--browser', type=pathlib.Path, required=True)
    ap.add_argument('--rounds', type=int, default=4)
    args = ap.parse_args()
    if not 1 <= args.rounds <= 20 or not args.browser.is_file():
        ap.error('require an existing browser and 1..20 rounds')
    os.environ['S5_CHROME'] = str(args.browser.resolve())
    # Set the browser before importing the existing skip-decorated fixture.
    sys.path.insert(0, str(ROOT / 'tests'))
    try:
        import test_s5_executor as fixture
        playwright = importlib.metadata.version('playwright')
    except ImportError as exc:
        print('probe prerequisite missing: ' + str(exc), file=sys.stderr)
        return 2
    if not fixture.HAVE_BROWSER:
        print('probe prerequisite missing: Playwright/browser', file=sys.stderr)
        return 2
    browser = subprocess.check_output([str(args.browser), '--version'], text=True).strip()
    print(json.dumps({'browser': browser, 'playwright': playwright,
                      'rounds': args.rounds, 'status': 'fixture-recovery-probe-not-qualification'}), flush=True)
    suite = unittest.TestSuite(fixture.FixtureSite(name)
                              for _ in range(args.rounds) for name in SCENARIOS)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # An unavailable/skipped fixture must not become positive evidence.
    return 0 if result.wasSuccessful() and not result.skipped else 1


if __name__ == '__main__':
    sys.exit(main())
