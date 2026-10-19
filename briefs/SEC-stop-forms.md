# SEC-stop-forms: STOP with a code in other forms does not stop, and unlocked sends the live code to the agent (CH-2)

Board section: Backlog refill (2026-10-11). Issue #2475. Defect: SEC-stop-with-code.

Raised by the Security and combined reviews of #2462. `STOP,<code>`, `STOP-<code>`, `<code> STOP`, codes of 5, 7 or 8 digits, `STOP <c> <c2>`, full-width `ＳＴＯＰ` or digits, and (locked) `STOP H3` and `STOP 12345678` did not stop. Unlocked, `STOP,<code>` reached the agent with the live code; locked, `STOP <c> <c2>` unlocked on the trailing code and sent `STOP <c>` to the agent.

**Requirement:** a message whose words (split before folding, then folded with the NFKC stand-in and case-folded) are STOP and otherwise only code-like tokens (digit runs of any length, grid cell labels), with STOP possibly glued to them (`STOP123456`), and separators is STOP. Every message the earlier reader took as STOP still is (Security review of #2486: `STOP £ <code>`). `stopNow` takes it before any code check, counts it in the STOP generation and hands the handler bare `STOP`. No token is checked, spent, counted, echoed or passed on. Any other word keeps CH-11's whole-message rule.

**Acceptance tests:** CH-2: `TestEveryStopFormStopsAndLeaksNoCode` (broker/owner/stopforms_test.go): every form above, locked, unlocked and challenged; each stops, counts one STOP, voids an earlier RESUME code, reaches no agent, echoes no code and leaves the wrong-code count, unlock window, last code step, challenge mode and held message unchanged. CH-11: `TestStopFormKeepsWholeMessageRule`, `TestStopFormChatStillReachesTheAgent`. CH-2 (no regression): `TestStopFormKeepsEveryOldStop`: every message the reader before this package took as STOP, drawn at random from STOP's pieces, codes, separators, currency signs, full-width forms and format characters, is still a STOP form. CH-2 (owner only): `TestStopFormFromAStrangerIsNothing`: a STOP form from any other number stops nothing and is not counted.

**Scope:** broker/owner/channel.go, broker/owner/stopforms_test.go, broker/owner/ASSUMPTIONS.md, briefs/SEC-stop-forms.md.

**Needs:** —

**Gate:** lenses (security, tier A)

**State on the board:** in review
