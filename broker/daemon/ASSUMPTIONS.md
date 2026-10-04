# Broker skeleton: assumptions

Built for PLAN P1-2 against SPEC v0.12 (PR #15) on top of the P1-1 journal
(PR #18). Each row is a reading of the spec, or a gap left for a later package,
that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| B1 | Messages from any number other than the owner's get no reply and no effect. A reply would let anyone probe the box or make it spend texts. | CH-3 | Small: `Handler.Handle`. |
| B2 | STATUS and task chat need a session unlock (CH-3 table). The default `Auth` knows the owner's number but keeps sessions locked until the owner channel (P1-5) can verify code-generator codes, so until then the running daemon answers STATUS with the unlock prompt. STOP, RESUME, and HELP need only the owner's number. | CH-3, CH-14 | P1-5 supplies the real `Auth`. |
| B3 | RESUME: a bare `RESUME` texts a 6-digit code from `crypto/rand`; `RESUME <code>` within 15 minutes lifts STOP. The code is single use, void after 3 wrong replies, and voided by a new STOP. CH-18's lockout across all code kinds belongs to P1-5. | CH-10, CH-11, CH-18 | Small: `resumeCmd`. |
| B4 | Control words are strict whole-message matches with a per-word argument grammar, so "stop the newsletter" goes to the agent. When the agent is down, its fixed reply names STOP. | CH-11 | A looser STOP match is a UX/security call for the lens review. |
| B5 | YES and NO answer "No open requests." and UNDO/MORE "No request <id>." until approvals exist (P1-5). Pause/revoke words for pre-allowances and loops are not parsed yet: the spec names no exact words. | CH-11, CH-13 | P1-5 and the ADP-9/LOOP-0 packages. |
| B6 | STOP and STATUS replies are fixed templates. STATUS shows at most three unresolved intents as `action/account`, each passed through a fixed alphabet with no digits or spaces, so no field can carry a code or a control word into a text. | CH-12, CH-19 | Small: `status`, `safeToken`. |
| B7 | Admission: a class may preempt only experiments, and only when it outranks them; newest first; only as many as needed; nothing is preempted if that cannot make room. Foreground and accepted work are never preempted. A PSI reading above the threshold refuses everything but foreground. The daemon refuses preemption until the VM lifecycle (P1-4) can freeze machines, and cgroup enforcement of the budgets is also P1-4. | RES-1, RES-2 | P1-4 supplies the `Preempter` and PSI source. |
| B8 | Socket identity is fixed by which socket a request arrives on: socket directory 0700, sockets 0600, one guest socket per agent machine, a closed op set per socket, requests capped at 64 KiB. No peer-credential check: a machine's VM is given only its own socket (P1-4). | ARC-6, OP-8 | Add `SO_PEERCRED` if host-side processes ever share the directory. |
| B9 | ARC-2 is enforced structurally: `daemon/arc2_test.go` fails if any control-path package imports a network client, a process launcher, a third-party module, or a broker package outside the control path. | ARC-2 | Extend the list when new control-path packages appear. |
