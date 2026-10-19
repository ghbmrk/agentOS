# broker/meter assumptions

| ID | Assumption | Serves | Revisit when |
|---|---|---|---|
| OP-8-plan-nocap-M1 | **Caps are money caps on pay-per-token API routes (OP-8 after #2291).** `MachineCap`, `OverallCap`, task reservations, shares and `DefaultMachineCap`/`DefaultOverallCap` apply only to calls through `Start`/`StartFor`/`Wrap`, which in agentosd are guest model calls to the API-key router. A provider-agent run on a subscription or plan route (CAP-11) never reaches this meter: it is metered by its provider-agent journal entry (#2308: machine, outcome, wall time), the one durable run log OP-11 allows, and admitted against the pool's quota and owner reserve (RES-5). | OP-8, RES-5, CAP-11, OP-11 | A plan provider bills overage that cannot be turned off: SPEC then treats it as an API route, so its runs go through `Start`. |
| OP-8-plan-nocap-M2 | The Defaults stay as the API routes' conservative money caps until the numeric targets freeze before A4; removing them would leave API routes uncapped, which OP-8 forbids. | OP-8 | The A4 freeze sets owner budgets (OP-5). |
