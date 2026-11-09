# Namespaced test runs: assumptions

Built for ENF-netns-skip-fu (#5112). Each row is a reading a reviewer may want to change.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| ENF-netns-skip-fu-1 | A namespaced run is the test binary run again with `-test.v`, so its plain output has one `--- PASS: <name> (` or `--- SKIP: ` line (indented for a subtest) per test it ran; `judge` reads those lines. A run that reports no pass for the test's own name fails, so a `-test.run` that matches nothing cannot pass. | #5112 | If the child's output format changes (`-test.v=test2json`, `-json`), `judge` reads the JSON `Action` fields instead. |
| ENF-netns-skip-fu-2 | Any skip line in the run counts, a subtest's included: in CI it fails the parent, elsewhere it skips the parent. A child test that means to leave a case out logs it (`t.Log`), as offload's VLAN case does outside CI. | #5112 | A child that must skip a case in CI needs its own exemption here, with a reason. |
| ENF-netns-skip-fu-3 | The package launches nothing: the caller passes an `Exec` built on its own `os/exec`. So it needs no entry in childproc's gate or in arc2's enforcer map, and only `_test.go` files import it. | ARC-1, ENF decision 1 | A non-test importer would link a package written for tests; the gate does not stop that by itself, so a reviewer checks importers. |
