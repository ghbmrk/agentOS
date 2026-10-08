# PE7-bus: PE7 condition 4, bound to the package that wires the events bus to…

Board section: Integration: wiring merged packages into the box.

PE7 condition 4, bound to the package that wires the events bus to the agent: while the agent sleeps (PE7), an agent-bound owner message wakes it and goes through the G5 requeue; the broker answers STATUS, HELP, RESUME, settings words and question answers without waking it; non-owner inbound events queue until the sleep window ends unless an owner rule marks them urgent. Tests: owner commands do not wake; a queued event is delivered after the wake.

**Precondition:** PE7, events bus wiring

**Owner:** 

**State on the board before the 2026-10-08 index split:** waits on the events-bus package
