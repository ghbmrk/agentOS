# SR2-3q: A runsc failure after the command may have started is not told it did not start

Board section: Release (Security on #396, delta review of e51bb8b).

runsc writes `--internal-pid-file` only after the command starts. A runsc failure between the start and the pid write (a failed pid write, for example a full state dir, is one way) still answers `vm.ErrExecNotStarted`, which reaches the guest as "the command did not start; retry it". A guest that follows that text can run the command twice in its own worker. Answer `ErrExecNotStarted` only when runsc's error shows a failure before the command ran, and otherwise answer `vm.ErrExecFailed` ("may have run"); nothing runsc wrote reaches the guest.

**Needs:** SR2-3j

**Gate:** security check
