# cgroup: assumptions

What `broker/cgroup` rests on. Each row is a property of the kernel or of a
caller that the code relies on, which a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| CGROUP-kc3-1 | A child clone3 places in a group (`CLONE_INTO_CGROUP`) lives only if that group was killed (`cgroup.kill`) as many times as the starter's own group. Measured on Linux 6.18.44 (#5135): a write to `cgroup.kill` counts for the group and every group below it at that moment, a group made later starts at zero, and the child of a mismatch dies of SIGKILL before it runs. So `Fresh` and `Child` never hand back a group that was killed: one an earlier run left is killed, emptied and removed, and its removal failing is an error. A new group lives under any starter whose own group was never killed. agentosd's is `broker/` under its delegated root, which nothing here kills, and which agentosd removes and makes new at each start (a leftover that will not go is a start error, #5143), so a kill count systemd's stop left on it is never inherited. | RES-1, RES-2, INF-4 | A starter whose own group was once killed (a group reused after a kill outside agentosd) would see every clone3 child die at birth; `TestRES1Clone3IntoANewGroupAfterKill` shows the rule on CI's kernel. |
