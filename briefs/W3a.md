# W3a: Evaluation route

Board section: Integration: wiring merged packages into the box.

Evaluation route (arbitrator on W3a, superseding the `agentos-eval` ruling; DECISIONS 2026-10-05): the replay evaluator will run in `agentosd`, beside the machine manager and journal it needs. Done here: replay machines reach only the evaluator's services (`lateServices.eval`); their model calls go to the vault process through `modelroute.Evaluation`, carrying only the tree's routing rule, which the vault process applies within the `-eval-from` machine's grants as private data (egress K10, replay K1); replay never calls a model itself (replay R10). Each evaluation route must be priced in the vault process's `-prices` table and no dearer, in input or output, than one active route on a granted provider; a dearer or unpriced route is refused before any provider and the tree is not evaluated (security C1, `replay.ErrOverPriceCeiling`). Replay machines are admitted against their own egress limits, never the agent's (L3 R1). The spare meter stays in `agentosd` with the guest meter, and EvalShare reads the scheduler in-process. **For W3 (after its route-type split and import-graph test):** open the evaluator (replay R8), pass `OverPriceCeiling` as the evaluation route's required `OverCeiling`, and keep `eval-` egress denials out of owner alerts and the digest. **For P2-1:** start `agentos-egress` with `-eval-from` naming the agent machine and `-prices` (both default empty: evaluation fails closed)

**Precondition:** W1

**Owner:** this thread

**State on the board before the 2026-10-08 index split:** merged (#62)
