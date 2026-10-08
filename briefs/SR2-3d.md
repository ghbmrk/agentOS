# SR2-3d: A too-deep worker can be flattened

Board section: Backlog refill (2026-10-05).

A too-deep worker can be flattened (security F1(b) on #174, M4): once `worker_delete` (#166) is on main, a test that it removes a tree nested past `overlay.MaxTreeDepth` and that its post-delete measure never fails the deletion; #174 keeps #166's `overlay.MaxTreeDepth`

**Needs:** SR2-3i, CAP-8c

**Gate:** security check

**State on the board before the 2026-10-08 index split:** in review (#174, recall thread)
