# BACKUP-table-fifo: reading a key table refuses anything but a regular file, and is bounded

Board section: Migration to the capability kernel (D-139). Work item #3998, release finding 3 from the Security review of #3994 (row #3945), https://github.com/ghbmrk/agentOS/pull/3994#issuecomment-6512363969.

**Problem, checked on main 2c3ec6f2:** `broker/backup/target.go` `readFile` opens `<id>.table.<gen>` with `O_RDONLY|O_NOFOLLOW` and then `io.ReadAll`s it. That refuses a link but not a FIFO, a device or a socket, and it puts no limit on the read. The target directory is the owner's choice, and `kernel/proc` `checkDir` accepts any directory, so another user may be able to write there. The read runs as root in agentos-unlock. Failure path: a FIFO planted at a table name blocks `DirTarget.GetTable` forever, and with it the restore that called it. A huge regular file read without a bound can exhaust memory first, even though `table.go` checks the size later.

**Requirements:** STO-1 (backups), REC-1 (restore), with the REV-CHK-links rule that a file the kernel side reads from an owner-chosen directory is checked for what it is before it is read.

1. `readFile` opens with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, runs `fstat` on the descriptor, refuses anything that is not a regular file with an error naming the path's type, then reads at most the largest sealed table plus one byte (a bound the builder derives from `maxTable` and the sealing format in `seal.go`, named as a constant), and refuses a longer file. Reads of a regular file do not block, so `O_NONBLOCK` can stay set.
2. `ASSUMPTIONS.md` records the rule and the bound.

**Scope:** `broker/backup/target.go`, `broker/backup/links_test.go`, `broker/backup/ASSUMPTIONS.md`, this brief.

**Acceptance tests:**
- STO-1: `backup::TestGetTableRefusesFIFO`. A FIFO at `<id>.table.1` returns an error within 1 s instead of blocking. Catches the hang reproduced in the review.
- STO-1: `backup::TestGetTableRefusesDeviceAndSocket`. A unix socket at the name is refused, and so is a character device made with `mknod` when the test runs as root (skipped with a named reason otherwise). Catches a type check that tests only for FIFO.
- STO-1: `backup::TestGetTableBoundsRead`. A sparse regular file one byte over the bound is refused without being read whole. Catches an unbounded read.

**Guard files:** none.

**Dependencies:** none. No open PR touches `broker/backup/`.

**Tier / gate:** tier A (`tools/risk_tier.py` prints A for `broker/backup/target.go`). L3 runs on the strongest model, plus the lens screen and a separate Security accept.

**Usage estimate:** one session, about 40k.
