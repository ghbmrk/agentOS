# SUB-3: current-main peer-substrate proposal

Separate L1 proposal based on public main
be5a80c352b03eedc4df0f8e791e97e99ecc2190. Nothing here is approved, merged,
qualified or activated. Published SUB-1 #260 remains unchanged at
a08d14036002ed253442cd905842f36d88e00e5d; SUB-2 supplies reconciliation evidence.
This proposal does not require SUB-2 code at runtime.

CAP-14 is provisional, not an allocated ID. At the pinned snapshot, main has
CAP-1–13; 142 open PR inventories show no other added capability-table definition
above CAP-13. L1 must refresh concurrent spec work and confirm allocation before
adoption. CAP-13 Local leverage and all existing IDs retain their meaning.

## Proposed changes

| Clause | Result |
|---|---|
| CAP-14 | The user's exact peer-substrate premise, with qualification, terms, custody, fixed effects, web recipes, labels and unknown-result recovery. |
| CRED-5 / CAP-11 | Provider CLI routes remain distinct from consumer-inference UI routes. Browser/desktop credentials stay broker-owned; the worker-held CLI exception never transfers to them. Qualification supplies no provider permission. |
| CAP-9 | Local leverage, compute hosts and primary ordering remain. Fallback must preserve full capability; a UI-only operation without an admitted equivalent is held/declined, never retried while unresolved. |
| CAP-12 | Computer-use added to the current resource kinds, retaining local passes and owner hosts; no grant, credential or quota authority implied. |
| ADP-3 | Current API/CLI/browser/desktop order and ADP-14 submit rules remain; complete capability, fidelity, evidence and recovery filter narrowest adequate selection. |
| OP-8 | Per-task attribution and enforceable run envelope before UI handoff. Unknown usage cannot be called metering or reserve enforcement; an unenforceable required bound makes the route unavailable. Cancellation does not resolve unknown effects. |

CAP-8 desktop workers, CAP-13 Local leverage, CRED-4/6/11, ADP-14/15/16 and CLI
custody subparagraphs remain byte-identical. Older whole capability rows are
not transplanted onto main.

## Concurrent work and review

#328 proposes terms-silent broker-held **CLI** custody. Its broker-held paragraph
and terms decision are untouched here, and this proposal adds no unconfirmed
terms permission for UI routes. The shared CRED-5 context still needs combined
L1 integration review; unchanged paragraph bytes do not guarantee patch or
semantic compatibility. #330's publication/Tor proposal is not imported.
Browser #300, host #326 and executor qualification remain active author work.

This branch starts from pinned current main. It does not rebase, force-push,
merge or replace published contributions. Its empty dependency list identifies
that public commit as source base, rather than the older notification stack.
SUB-2 and #260 are explanatory references, not Git parents.

## Static evidence and limits

Compare main and this candidate with SUB-2's read-only spec_identity tool:
existing table labels unchanged, CAP-14 added, CAP-9/11/12 bodies modified.
Byte checks also preserve all existing IDs and the adopted clauses above.
Existing trace tests and disposable-copy trace regeneration validate syntax
and references only. No runtime coverage or acceptance test is claimed; no
failing production test is manufactured for a normative-only proposal.

SUB-3-Q on BOARD records release qualification: provider/account/protocol
custody, credential/authority bypass probes, adversarial UI input, resource
enforcement, unknown-effect reconciliation and floor evidence. Existing local
fixtures cannot prove these properties. Strongest independent security review
and exact L1/Mark approval remain required. Low mechanical path risk for
SPEC/docs does not reduce that semantic review requirement.

Findings: blocker — the old CAP-13 collision and loss of adopted clauses are
addressed in this separate proposal; release — SUB-3-Q and L1 allocation/
approval; later — none. No row classified as later is started. No runtime
route, daemon default, deploy or merge occurs.
