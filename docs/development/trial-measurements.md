# H6: comparable A10 trial measurements

`python3 tools/measure_trials.py --root evidence/ --trials trials.jsonl --output report.json`
validates recorded trials and produces descriptive comparisons. It executes no
model, account action, or command supplied in a trial. This is a collector, not
an A10 qualification runner or a claim of product benefit.

Each JSONL record uses schema 1 and includes run_id, arm (`agentos`, `openclaw`,
`provider-cli`), task_id, workload_sha256, profile_id, start_state_sha256, versions,
route_id, repetition (integer >=1), phase (`first-use`/`repeat-use`), timezone-bearing
started_at/finished_at, owner_active_seconds, necessary_approvals, avoidable_approvals,
failures, fallbacks, judgment (`accepted`/`rejected`/`pending`), judgment_source
(`owner`/`external-reviewer` for a resolved judgment), and evidence (`path`/`sha256`
relative to --root). Use opaque profile/account-policy IDs, not personal account
names. Record independent judgments as evidence; the label alone authenticates none.

Optional resources preserve units: calls=calls, tokens/cached_tokens=tokens,
plan_runs=runs, api_cost=USD, plan_quota=declared-pool-units with an explicit
pool_unit_definition. Percent quota, tokens and API dollars are not converted.
Reports retain measurements per run rather than summing incompatible pools.

A matched set shares task, workload, profile, starting state, repetition and phase
across all three arms. Missing/pending arms prevent a complete comparison. Duplicate
run IDs or arms are refused. Pairwise effort differences include only pairs whose
goals were both accepted. Rejected attempts still count in total effort per accepted
task. First-use and repeat-use results are separated when both appear.

Measure end-to-end time from task initiation, including planning before first effect.
Measure owner-active intervals independently of elapsed time. Counterbalance arm
order, reset external state and independent workspaces, and freeze versions/routes,
concurrency, repeats, gain targets, regression margins and rollback triggers before
qualification. Test synthetic correctness first; obtain independent goal judgments
and owner-reviewed recurring tasks before claiming useful leverage.

Validation refuses negative/boolean/nonfinite metrics, impossible effort, unsupported
units, unknown judgment sources, escaped/missing/tampered evidence, duplicate runs,
partial comparisons and mismatched starting states. SHA checks do not authenticate
producers or prove profile assertions. Ten collector tests use synthetic evidence;
they are not product baselines and do not justify changing model tiers or authority.
