# W5-D50 assumptions

| # | Assumption | Spec basis | If it changes |
| --- | --- | --- | --- |
| 1 | Linux directory descriptors/openat/renameat address the held directory even if its pathname changes. | OP-1 | Refuse unsupported targets; qualify equivalent substrate before adoption. |
| 2 | Even with D51 bounded nofollow lookup, parent permissions/mounts and directory/lock names remain under trusted custody; same-UID mutation is outside this component's qualification. | OP-1, OP-8 | Hold deployment until independently qualified; inode observations do not prevent hostile name races. |
| 3 | All writers cooperate with one retained lock inode and exactly one Gate per owned lease. | CH-15 | Preserve startup/consumer composition hold; advisory flock is not enforcement against noncooperators. |
| 4 | Existing or failed `.tmp` is unresolved state. Only trusted recovery after full drain may remove it. | OP-1, CH-15 | Do not automatically truncate/adopt/unlink/retry it; review recovery custody explicitly. |
| 5 | File write/fsync/rename/directory-sync success is only the configured filesystem's contract. | OP-1 | Qualify actual crash/media behavior independently; any error is a latched hold, not a refund. |
| 6 | Config pins, clock, strict state, backup/restore and all-user quiescence remain externally trusted. | CH-15, OP-1 | Refuse unsafe composition; descriptor anchoring is not anti-rollback/restore/config authentication or permission revocation. |
| 7 | Synchronous filesystem I/O may block forever; D41 observes latency without cancellation. | OP-8 | Keep independent owner controls/owned startup resource admission; do not start replacement writers after timeout. |

| 8 | Paths within 4095 bytes and 64 parent components without symbolic ancestors are sufficient for the reviewed opt-in deployment. | OP-8, OP-1 | Review compatibility; never silently follow links/canonicalize or relax the bounds. Namespace and ancestor permission custody remain externally qualified. |
