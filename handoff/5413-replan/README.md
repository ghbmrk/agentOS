# #5413 re-plan: an OS uid boundary around every trace stream

Row #5413 (CI-unit-strace-retry-4), escalated after #5426 was rejected at 467e7b00 by the Security
verdict 6789699235 (fourth head, three fix-list rounds). This packet is the step back that verdict
asks for, and the plan the new PR builds.

## Why #5426 did not converge

Every round closed one holder of a trace stream, and the attack moved to the next holder, because
the tracee runs as the same uid as strace and the runner:

| Round | Holder closed | Next holder found |
|---|---|---|
| 1 (8dff695d) | names in the trace directory (unlink, rename, truncate) | symlink, link, mknod, mkdir, a rename above it |
| 2 (6d14dc6d) | trace names during the run (pipe + O_TMPFILE, publish at the end) | strace's `/proc/<pid>/fd` (a fragment hides the next line) |
| 3 (f316175e) | the module's own pipe (`pipe:[ino]` grep) | another module's pipe; dup2 moves the fd so the open names no pipe |
| 4 (467e7b00) | strace's /proc (`chmod go-r`, non-dumpable) | the JOIN sh, which holds the pipe on fd 0 while dumpable |

The class is: a process the module controls shares a uid with a holder of a trace stream. Same-uid
`/proc`, ptrace, `pidfd_getfd` and signals then reach the holder, and a check on the trace can't
see an fd that has been moved. Patching holders one at a time can't close that class.

## The structural fix

The kernel, not a trace check, separates every module from every stream:

1. **The runner and strace run as root.** In CI this is `sudo -E env "PATH=$PATH" python tools/unit_tests.py DIR`.
2. **Each module runs as a user of its own** (`ut-<module>`, its own group, and also in `agentos-tests`).
   A non-root uid keeps no capability, so `ptrace_may_access` denies it, by uid alone:
   - `/proc/<pid>/fd`, `/proc/<pid>/mem`, ptrace and `pidfd_getfd` on strace, the runner and every other module;
   - signals to them.
3. **No module process ever holds a stream.** strace's `-o` fd is not inherited (checked, strace 6.8).
   A root `sh` runs before the uid drop: it gives the module `/dev/null` on fd 0 and joins its fd 2 to
   fd 1, the module's own log. Only then does `setpriv --init-groups --no-new-privs` take the module's
   user. So the first process of the module's uid already has only `/dev/null` and its log.
   no_new_privs keeps setuid and file-capability programs from raising it again. Under the old
   non-root strace, sudo and setuid programs already could not raise a module either.
4. **The trace directory is private.** It must not exist. It is made with mode 0700, owned by sudo's
   caller. Every directory above it must be owned by root or that caller, and writable by no other
   user unless sticky (`private()`). So no module can enter it, link into it, or move it or a
   directory above it. That closes round 1's whole class (names in or above the directory) with
   no syscall list. records_audit's write check stays as a tripwire.
5. **`sweep()`**: after each attempt, `kill(-1)` as the module's user. Any process of that user that
   outlived strace is killed, wherever it moved.
6. **Shared state is only `<TRACE_DIR>.run/go`** (GOCACHE, GOMODCACHE). It belongs to group
   `agentos-tests` through a default ACL, so the Go build cache stays warm across modules. clash_audit
   exempts it, as it already exempts Go's caches. Each module gets its own HOME.

This is the boundary `tools/depaudit.py` already relies on (tools/ASSUMPTIONS.md D9: the scenario
under a distinct uid, no_new_privs). Here it runs on the host instead of in a user namespace,
because the unit tests need the host as it is (the reference root, GOCACHE, sudo-gated skips).

What #5426 added and this plan drops, each made moot by the boundary: the trace pipe and
`O_TMPFILE`, `PR_SET_DUMPABLE`, publishing at the end, the `PIPES` inode grep, `chmod go-r strace`
and `open_to_proc`. From #5426 the plan keeps round 1's reviewed parts: tracing unlink, rename and
truncate for the clash audit, clash_audit reading `.trace.cut`, and the JOIN sh, which now also
gives the module `/dev/null` for stdin.

## Row items and release items

- **Item 1** (forged cut through `/proc/<strace>/fd/2`): closed by the kernel. strace is root, and
  no module process holds strace's stderr. If a cut were faked, both audits would still read the
  cut trace.
- **Item 2** (unlink, rename, truncate): traced and counted by the clash audit. Tampering with a
  trace through them is closed by the private directory.
- **Item 3** (site hooks run before JOIN): the join and the uid drop both happen before Python
  starts.
- **Item 4** (clash_audit and `.trace.cut`): clash_audit reads it.
- **Lens R1** (two guards that each cover only the other): the guards are now (a) the directory
  must be new and (b) the directories above it. Each has its own test, and each test fails with
  its guard removed.
- **Lens R2** (`open_to_proc` and `FileNotFoundError`): moot, since `open_to_proc` is gone.
- **Lens R3** (local runs): the module docstring and the error message both give the
  `sudo -E env "PATH=$PATH" …` command. A plain user is refused; the runner never runs without
  the boundary.

## Feasibility (checked 2026-11-11)

- **GitHub-hosted ubuntu-24.04**: passwordless sudo; `useradd`/`groupadd` (passwd) and `setpriv`
  (util-linux) are in the base image; ci.yml installs `acl` the way it installs strace when missing.
  A new user can't traverse `/home/runner` if it is 0750, so ci.yml runs `chmod o+x` on each
  directory above the worktree. That grants search permission only: a module can open a known
  world-readable path, never list the directory. That is less than today, when modules ran as
  `runner` itself.
- **Locally** (this container, root, strace 6.8): all 81 modules pass as a separate uid with the
  repository read-only to it (test_image_gen needed only `/usr/sbin` on PATH). A cold `go test`
  cache warmed by one uid serves another in 1 s against 19 s cold, through the ACL. The end-to-end
  boundary test passes, and each of these mutants fails it: drop removed, `0</dev/null` removed,
  `2>&1` removed, `--no-new-privs` removed, trace dir 0755, and `kill(-1, 0)` in sweep. The mkdir
  mode survives as an equivalent mutant, since `chmod 0700` follows it.

## Decision

Auto-decided (Mark's rule: no lens gets worse).
- **Security** is better: the whole class closes, and so do the routes to a stream that #5426 left
  as residuals (an io_uring open of a `/proc` fd, `pidfd_getfd`, a moved fd, an outliving process).
  An io_uring open stays unseen for the record check, as before.
- **Leverage** is unchanged.
- **Effort** is the same in CI. Locally the runner needs sudo, which #5426's `chmod go-r` also needed.
- **Simplicity** is better than #5426: one boundary replaces its pipe, inode grep, publish step and
  `/proc` checks. Against main, the runner gains about 140 lines (users, the private directory, sweep).

I considered one shared test uid for all modules. It also keeps every stream out of reach, but
modules could still reach each other's processes. Per-module uids cost only the ACL'd Go directory,
so they win on every lens.

## Hand-off

The branch carries the build. If it stalls, the next builder starts from that branch and reads
tools/ASSUMPTIONS.md `CI-unit-strace-retry-4-a`. The real-boundary test needs root:
`sudo -E env "PATH=$PATH" AGENTOS_REQUIRE_UID_BOUNDARY=1 python3 -m unittest tests.test_unit_tests`.
