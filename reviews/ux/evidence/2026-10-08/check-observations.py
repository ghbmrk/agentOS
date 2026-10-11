#!/usr/bin/env python3
"""Check the recorded defects, not product correctness or desired behavior.

A failure after a product fix means the observation needs reassessment; these
are review reproductions and must not become CI assertions preserving defects.
"""
import json
from pathlib import Path
import sys

out = Path(sys.argv[1])
setup = json.loads((out / "setup/probe-results.json").read_text())
checks = []


def observe(name, condition):
    checks.append((name, bool(condition)))


initial = setup["initial_provider_challenge"]
observe("Initial provider sign-in has empty link/code and no start control",
        initial["http_status"] == 200 and initial["empty_provider_link"]
        and initial["empty_provider_code"] and not initial["start_form_visible"])
old = setup["provider_challenge_24h"]
observe("The same provider challenge survives 24 hours without a renew control",
        old["same_code_visible"] and not old["start_form_visible"])
network = setup["network_after_pairing"]
observe("Paired network repair has no visible form and invokes no join",
        not network["network_form_visible"] and network["repair_join_calls"] == 0
        and network["repair_post_status"] == 303)
local = setup["no_cloud_providers"]
observe("No-provider setup has no Local only choice and does not finish",
        not local["local_only_choice"] and local["finish_calls"] == 0)
wait = setup["update_wait"]
observe("Update hold displays generic updating copy with a 10-second refresh",
        wait["generic_update_copy"] and wait["refresh_10s"])

approvals = (out / "approvals.txt").read_text()
observe("Two locked messages are dropped and RUN delivers no task",
        "both were dropped" in approvals and 'BOX ["Nothing is held."]' in approvals
        and "DELIVERED TASKS []" in approvals)
more = [line.split(" ", 2)[2] for line in approvals.splitlines() if line.startswith("MORE ")]
observe("Repeated MORE returns the same truncated list",
        len(more) == 2 and more[0] == more[1]
        and "Rest on the box's Wi-Fi page" in more[0])
observe("A benign source-code sentence is withheld by the code filter",
        'NOTIFY INPUT "The source code has 1234 lines and the build passed."' in approvals
        and "A message was held back because it may contain a code or key" in approvals)

status = {}
for line in (out / "status.txt").read_text().splitlines():
    key, value = line.split("=", 1)
    status[key] = json.loads(value)
observe("Clock note loses the end of Nothing to do",
        status["CLOCK_RAW"].endswith("Nothing to do.")
        and status["CLOCK_STATUS"].endswith("Nothing "))
observe("Multi-exception SMS truncates later recovery guidance",
        "what I can restore" in status["STATUS_MULTI_RAW"]
        and "what I can restore" not in status["STATUS_MULTI_SMS"])
render = (out / "render.txt").read_text()
observe("All six synthetic UI captures return HTTP 200",
        len(render.splitlines()) == 6 and render.count("HTTP 200") == 6)
test_log = (out / "setup-tests.txt").read_text()
observe("Four existing setup tests pass despite the reproduced visible defect",
        test_log.count("--- PASS:") == 4 and "\nPASS\n" in test_log)

for name, passed in checks:
    print(f"{'REPRODUCED' if passed else 'CHANGED/NOT REPRODUCED'}: {name}")
print(f"{sum(passed for _, passed in checks)}/{len(checks)} observations reproduced.")
if not all(passed for _, passed in checks):
    raise SystemExit(1)
