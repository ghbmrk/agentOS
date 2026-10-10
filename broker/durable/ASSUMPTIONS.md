# durable: assumptions

Built for SIM-fs against OP-4 and RES-4. Each row is a reading a later change could overturn.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| D1 | A rename survives a power cut only after the directory holding the new name is fsynced, and a file's bytes only after the file is fsynced before the rename (ext4 and xfs on Linux). `WriteFile` does write, fsync file, rename, fsync dir; `Rename` fsyncs the new directory and the old one when it differs. | OP-4, RES-4 | A file system with different rules needs its own seam. |
| D2 | A failed directory sync after a successful rename is returned wrapping `ErrDirSync`, never swallowed: the new name is in place but may not be durable. Callers that hold a handle (journal `Rewrite`) swap it before returning the error. localui and localsrv setup saves ignored this error before and now return it. | OP-4 | — |
| D3 | `SweepTemp` assumes one process owns the directory and no `WriteFile` into it is in flight; callers run it at open or start (pubid, pubsend, recall, digest queue). | RES-4 | A shared directory needs a lock or per-writer prefix. |
| D4 | Temporary files are named `.durable-*`. Leftovers under the old names (`.pubid-*`, `.pubsend-*`, `seg-*.tmp`, `*.tmp`) from a crash before this change are no longer swept; they are small, unread, and the boxes in the field are test kits. | RES-4 | Remove them by hand, or add the old pattern to a one-off sweep. |
| D5 | cleanroom keeps its own fault seam (C14, SR3-8): its renames carry `durable:exempt` and its directory sync is `durable.SyncDir` through `syncDirFn`, so its fault tests still inject at each step. | SR3-8 | Fold cleanroom into `durable` once the seam can inject through `fsys`. |
| D6 | `durable` imports only the standard library (`TestLeaf`), so every import fence may allow it without letting a fenced package reach broker state. | ARC-2 import fences | — |
| D7 | `TestNoBareRename` scans non-test `.go` files under `broker/` for `os.`, `syscall.` and `unix.Rename`/`Renameat`/`Renameat2`. Tests may rename freely. Renames through another wrapper (a variable holding `os.Rename`) are not caught. | OP-4 | Move the check to a vet analyzer if wrappers appear. |
