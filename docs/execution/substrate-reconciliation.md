# SUB-2: current-main reconciliation for the substrate proposal

This is a review packet, not a normative SPEC change, approval, executor grant
or activation. Preserve the published SUB-1 head and prepare any replacement
SPEC diff from a freshly pinned public main for external L1 review. The user's
peer-substrate premise remains the intended direction; qualified capabilities
and account custody still need the same executor contracts.

## Pinned evidence

| Input | Identity |
|---|---|
| Public main | be5a80c352b03eedc4df0f8e791e97e99ecc2190 |
| Its spec merge parent | ae4f23386ba2a2bf02df28ccb94df5682d07ded1, upstream PR #298 |
| Public SPEC Git blob | 2dc448c8ead5bf88bb898a8467a3b96ea17b3b68 |
| Public SPEC SHA-256 | e88c2ef8bb7ef12c381c53406d28f1edf35a8bb64810d8fc5cdf51504fb98006 |
| Published SUB-1 / PR #260 | a08d14036002ed253442cd905842f36d88e00e5d |
| SUB-1 SPEC SHA-256 | ec7dda93cd41d45b12ede5fed8891cbb3d4651d1da8df721394584750724100d |

The public SPEC was fetched by immutable commit reference through GitHub's
contents API. Hashes identify the compared bytes, not their authenticity or
acceptance. Refresh main and active spec proposals before writing a new diff.
Neither these observations nor read-only patch applicability authorize adoption.

## Concrete reconciliation requirements

| Clause | Observed difference | Required treatment in a new proposal |
|---|---|---|
| CAP-13 | Public main defines **Local leverage**, including local passes, pipelines and owner compute hosts. SUB-1 defines **Peer execution substrates** at the same ID. | Preserve the existing CAP-13 and its references. Choose a fresh ID through L1 coordination; do not renumber the adopted local-leverage requirement or freeze an apparently free ID from this older snapshot. |
| CAP-8 | Current main includes credential-free desktop workers and routes logged-in apps through CRED-4/ADP-5 executors. The older proposal's whole row lacks that addition. | Preserve the adopted desktop-worker isolation and login boundary. Add substrate rules as an extension, not by replacing the row with older bytes. |
| CAP-9 | Current main includes owner compute hosts and local leverage wrapping whichever primary route runs. SUB-1 changes failover equivalence and loses later additions when replayed as a whole row. | Preserve local/host/pipeline behavior; qualify fallback for the complete required capability without converting an unavailable UI operation into a promised equivalent API capability. |
| CAP-12 | Current main exposes local passes and owner-host resources; SUB-1 adds computer-use resources to an older row. | Keep the current resource inventory and add separately declared computer-use admission/qualification information. A resource entry supplies neither authority nor credentials. |
| CAP-11 | Main still says driving a provider's consumer website or app is never a route. SUB-1 proposes a separately qualified computer-use route. | Make the exact requested change explicit for L1 review. Merged web recipes do not silently repeal this provider-specific prohibition. Provider CLI workers remain distinct. |
| CRED-5 | Main still restricts consumer-plan login use to the official unmodified CLI, with broker-held and worker-held modes. | Reconcile the consumer UI premise explicitly without extending the worker-held CLI exception to browser cookies or desktop logins. Coordinate with active #328 plan-custody work rather than duplicating its terms decision. |
| ADP-3 | Merged #298 governs browser submits through ADP-14 web recipes. The old proposal's replacement line lacks that text. | Preserve web-recipe submit gates, then express narrowest adequate capability selection after grant, label, qualification, health and resource admission. |
| CRED-6 / CRED-11 / ADP-14–16 | Main now includes secret-intent gates even under web recipes, label-governed cross-executor transfer, composited desktops and explicit suite-executor opt-in. | Carry these adopted contracts forward; peer substrates do not bypass them, pool accounts together or grant credential custody to agent workers. |
| OP-8 / RES-2 / RES-5 / OP-2 | SUB-1 extends run admission and ambiguous-result recovery beyond metered model egress. | Review enforceable run bounds, advisory UI quota versus real admission, attribution and unknown-effect reconciliation. No refund, alternate-substrate repeat or confidence claim can resolve an unknown effect. |

The read-only identity audit reports five changed capability rows: CAP-8,
CAP-9, CAP-11, CAP-12 and CAP-13. The single label collision is CAP-13. It does
not examine prose clauses, terms or semantic equivalence; the remaining rows
above come from direct inspection of the pinned inputs.

## Reproducible review tool

Run tools/spec_identity.py with --reference pointing to the pinned public SPEC
and --candidate pointing to the pinned SUB-1 SPEC. It reuses tools/trace.py's
ID syntax, bounds inputs, ignores fenced examples, rejects duplicate table IDs,
and reports changed/added/removed table rows plus labels and byte hashes as JSON.
Exit 0 means identical table rows, 1 means review differences, and 2 means
invalid input. No exit code asserts approval. Prose, multiline or escaped-pipe
table representations require manual review; this is deliberately not a
Markdown parser, merge engine, trace replacement or security acceptance gate.

Inputs are read only; candidate code and instructions are never executed.
The CLI performs no Git or network operations and writes only stdout/stderr.
Paths and underlying input errors are not disclosed in its fixed error output.
Standard-library parsing and existing trace syntax avoid another dependency.
Tests first cover collisions, changed bodies, additions/removals, duplicates,
fenced examples, size/label bounds, invalid UTF-8 and unchanged input bytes.

## Review sequence

1. Refresh immutable public main, #260 and active spec heads. Retain the existing
   publication and local heads; do not force-push them or alter prior downloads.
2. Prepare a new L1 diff against that public SPEC, preserving all adopted rows
   and explicitly resolving the provider consumer-UI/custody/fallback conflicts.
3. Compare the new bytes, inspect prose and cross-references, and run regenerated
   trace checks in a disposable copy. Tool success is not qualification.
4. Present the concrete diff and acceptance cases for external L1/security
   review. Runtime routing still needs independently qualified executors,
   declared operations, fixed effect gates, labels, resources and recovery.

No hardware/carrier/browser qualification, daemon activation or merge occurs in
this package. The existing browser #300 and host harness #326 remain active
author work. Notification branches D33–D40 are now visible in drafts #331–338;
those publications were observed, not created by this package. Their storage-
fault availability, custody/restore, base and priority review holds remain.
