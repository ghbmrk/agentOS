# Guest error text: assumptions

Built for BOARD SR2-3k on the guest-plane error filter (SR2-3g). Each row is
a reading of the spec, or a gap left for a later package, that a reviewer
may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| E1 | **Guest values are ID-shaped (SR2-3k, finding 4, L3 on #324).** `Newf` shows a `Guest` value, or one a type embedding `Guest` carries (the check is in `Guest`'s `Arg` method, release 1 on #398), only when it matches `^[A-Za-z0-9._-]{1,64}$`, the request-ID shape the guest and question tools already require; any other, a host path, a space, non-ASCII or a clipped name ending in "…", is shown as "(not shown)". It replaces rather than rejects, because `Newf` returns text and its callers are already answering an error. The one caller this changes is the guest plane's unknown-tool error, which used to echo any clipped tool name. | RES-4, CAP-8 | A tool that must echo a wider guest value (for example a guest path) needs its own pattern here, reviewed as a new way for text to reach the guest. |
