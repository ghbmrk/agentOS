# CRED-2t: Trusted-base statement pinned by a test

**Owner:** either peer. **Class:** release. **Implementation risk:** tier C.
**Board section:** Uncovered requirement IDs (CONV-5, [triage](../docs/conv-5-uncovered.md)); work item #1901.
**Requirements:** CRED-2
**Dependencies:** none (#1902 merged the CONV-5 CRED-2 reclass; SPEC L267 already carries the D-082 wording).

## Goal

CRED-2 is a scope statement, so its only testable content is the sentence itself. Pin it so a later spec edit cannot drop the trusted base or turn the scanning tripwire into a containment claim without a failing test naming the line.

## Scope

`tests/test_cred2_trusted_base.py` (new), this brief. Read-only on SPEC.md. No guard files: **Guard files:** none.

## Acceptance tests

**Acceptance tests:** `tests/test_cred2_trusted_base.py` (three named tests below plus a mutation test), each failing on a dropped member, a containment claim or a removed out-of-scope line.

- `tests/test_cred2_trusted_base.py::test_names_every_trusted_base_member`: CRED-2's text names host kernel, hypervisor, firmware, broker, credentialed-executor sandboxes and the credential-reading processes. Catches: a member dropped, silently shrinking the stated base.
- `tests/test_cred2_trusted_base.py::test_scanning_is_tripwire_not_containment`: the text calls CRED-7 scanning a tripwire and says the spec claims no containment of a compromised credential reader (D-082). Catches: the sentence weakened to a containment claim.
- `tests/test_cred2_trusted_base.py::test_compromise_of_base_out_of_scope`: the text says compromise of the base is out of scope. Catches: the out-of-scope statement removed.

Each failure message names the SPEC.md line. Synthetic text only; mutated copies of the sentence prove each test can fail.

ASSUMPTIONS.md: none added; the test rests on the CRED-2 bullet beginning `- **CRED-2**` in SPEC.md.

## Handoff and estimate

Checkpoint: 30k tokens, an estimate rather than a ceiling.
