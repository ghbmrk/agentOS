# HOST-1h: a liveness answer stops before the MOR clear

Board section: Devices, hardware and image (SPEC §13-14). Work item #5267, a release item from #5266 (HOST-1g, #5256).

`tools/hostcheck.py`'s power cut quits QEMU only after the guest answers `alive NONCE` with `HOSTCHECK-ALIVE NONCE`. That proves the guest was running at the quit only if nothing that answers is still running once an orderly exit has begun: a responder that answers during a shutdown, then clears MOR (or skips the clear) and halts inside the one poll before the quit, passes as a power cut. No host-side change closes that window, since the host cannot probe a guest after quitting it; the order has to hold in the guest.

**Requirements:** HW-8 (the `unclean` phase's MOR-left-set disclosure, flag `unclean-end`).

**This package (part 1, buildable now):**
- The stand-in states and keeps the rule: it answers only from its command loop, every exit leaves that loop for good, and the exits that clear MOR (`reboot`, `poweroff`, end of input) clear it only after the loop's last answer; `halt` (the negative test's) leaves MOR set. Fix the `tools/hostcheck_standin.sh:61` comment that said every exit clears MOR.
- `tools/hostcheck.py` states the rule as the contract a guest's responder keeps, next to `ALIVE`, so the image's responder is built against it.
- `tools/ASSUMPTIONS.md` records the assumption the power cut rests on.

**Part 2 (with HOST-1e2, needs the image boot in CI):** the image's responder unit, ordered `After=agentos-mor.service` with `Conflicts=shutdown.target`: systemd stops units in reverse start order, so it stops before that unit's `ExecStop` clears MOR (`Before=` would stop it after the clear and make an ordering cycle; #5744 L3), HOST-1e2's phases file, and a test that the image in shutdown does not answer. #5267 stays open for it.

**Acceptance tests:**
- `tests/test_hostcheck.py::StandinTest::test_a_guest_in_shutdown_does_not_answer`: runs the stand-in's own command loop (stubbed exits) with `alive A`, an exit, then `alive B`; A is answered, B never is, and a MOR clear comes after A. Catches a stand-in whose loop answers after an exit has begun (a mutant that backgrounds `poweroff -f` must fail it).
- `tests/test_hostcheck.py::StandinTest::test_every_exit_clears_mor_first` (existing): still pins which exits clear MOR.

**Scope:** `tools/hostcheck_standin.sh` (comments, and `exit 1` after each `-f` exit from the #5744 Security review), `tools/hostcheck.py` (comments only), `tests/test_hostcheck.py`, `tools/ASSUMPTIONS.md` (one row), this brief.

**Guard files:** none.

**Tier / gate:** tier A (`tools/hostcheck*`): L3 and a separate Security accept if `premerge.py --needs-mark` prints `mark`. One session; estimate 40k tokens.
