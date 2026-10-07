# S5-R: refused-navigation recovery reproducer

On Chromium 151.0.7922.173 and Playwright 1.62.0, the existing S5 fixture suite
failed twice: a fresh navigation to `/app.html` was interrupted by a navigation
to `chrome-error://chromewebdata/` after a refused off-origin form/redirect. This
profile differs from RESULT.md's earlier measurement; it needs its own qualification.

Run `python3 spikes/S5-browser-actions/recovery_probe.py --browser /usr/bin/chromium --rounds 4`.
The probe reuses existing synthetic fixture tests, repeats refused form -> fresh
navigation and refused redirect -> fresh navigation, reports versions and returns
nonzero on failures, errors, skips or missing prerequisites. It launches no account
or live-site task. It does not retry an effect or change executor confinement.

The original sequencing probe produced four errors in 16 tests. A failure can
occur in the next test's setup, so checking only the immediate refusal response
misses it. Successful individual scenarios are not proof of reliable recovery.

Investigate `_settle`, `_confine` and `handle` in executor.py. `handle` suppresses
settle/confine exceptions after building its response; `_settle` bounds waiting and
ignores load-state errors. Exact causality is open. A future fix needs explicit
recover-or-hold state and snapshot generations, reviewed at the strongest tier.
Do not repair it with an unconditional retry of a click/form submission: an effect
may have occurred. Preserve declared redirect cookies, POST/303 behavior, popup/
iframe refusal, zero attacker navigation hits and secret-output checks.

The spike also continues non-navigation subresources and relies on production
egress confinement. Navigation fixtures alone do not qualify that boundary;
CRED-4b must test image/script/fetch traffic through actual broker egress. This
PR adds a diagnostic runner only, not a browser implementation or gate pass.
