# SR2-3p: A command that cannot start is not told to retry

Board section: Release (finding item 3, lens on #396; the CH-12 kind: guest text that asks for an action that cannot work).

`vm.ErrExecNotStarted` reaches the guest as "the command did not start; retry it", which is wrong when the program is missing: a retry fails the same way. Split the cases runsc lets the broker tell apart (program not found versus a runtime failure before start) into separate sentinels and fixed texts, so only a transient failure advises a retry; nothing runsc wrote reaches the guest.

**Needs:** SR2-3j

**Gate:** security check
