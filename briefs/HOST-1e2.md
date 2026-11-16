# HOST-1e2: the host-untouched check on the agentOS image

Board section: Devices, hardware and image (SPEC §13-14). Work item #5746; part 2 of HOST-1e (`briefs/HOST-1e.md`, part 1 #326), and the home of HOST-1h part 2 (#5267; part 1 #5744, `briefs/HOST-1h.md`).

`tools/hostcheck.py qemu --image` boots a raw drive image on a QEMU/OVMF/swtpm host, but nothing has run it on P2-1's image: there is no phases file for it, and the image has no `alive NONCE` responder, so its `unclean` phase cannot cut power. The power cut proves the guest was running at the quit only if the responder stops before the image's MOR clear (`agentos-mor.service`'s `ExecStop`), which the HOST-1h contract in `tools/hostcheck.py` states.

**Requirements:** HW-8 (host untouched; the `unclean` phase's MOR-left-set disclosure, flag `unclean-end`).

**This package (HOST-1e2a, the QEMU half):**
- The responder: `tools/hostcheck_image/responder.sh` and its unit, `hostcheck-responder.service`, ordered `After=agentos-mor.service` with default dependencies (so `Conflicts=` and `Before=shutdown.target`): systemd stops units in reverse start order, so its answers end before the MOR clear. It answers `alive NONCE`, and `poweroff` or `reboot` asks systemd for that exit and keeps answering, so only the unit's stop ends the answers. The unit, the script and two drop-ins (start it from `multi-user.target`; keep `serial-getty@ttyS0` off its console) ride as SMBIOS credentials, as `image/ci_boot.sh`'s checks do, so the shipped image is unchanged: no console reader ships, and `image/mkosi/` is untouched. They live under `tools/`, not `image/`: every unit file under `image/` is read as installed (`broker/kernel/privfile`'s lint, `imageUnits`), and these never are.
- `tools/hostcheck.py`: `--credential NAME=FILE` (passed to the OS boots only) and `--memory MIB`.
- `tools/hostcheck_image/phases.json`: `boot`, `restart` and `unclean`, each OS start marked at OVMF's `BdsDxe: starting Boot` line (before the boot loader, so no guest RTC write falls before the mark).
- A CI job, `image.yml`'s `hostcheck-image`, that runs the three phases on the built image with the stack from the image's Debian snapshot (the same root step as ci.yml's `hostcheck` job), and the image-in-shutdown test.
- `image/ASSUMPTIONS.md` records what the image's power cut rests on.

**Part b (HOST-1e2b, #5815):** the S1 PC procedure (`snapshot --efivarfs` and `--tcti` from a third system, RTC offset against reference time); the pcrlock index if P2-1 pins one; HOST-1d's opted-in disk excluded by the owner's flag. It needs a physical PC and owner steps, so it does not ride with the CI half.

**Release item from the #5744 L3 review:** the stand-in's `reboot -f`, `poweroff -f` and `halt -f` are each already followed by `exit 1` on main (`tools/hostcheck_standin.sh`); nothing is owed.

**Acceptance tests:**
- `tests/test_hostcheck.py::ResponderTest::test_the_unit_stops_before_the_mor_clear`: the unit keeps default dependencies, is `After=agentos-mor.service`, `Conflicts=shutdown.target`, and is never `Before=` it. A mutant with `DefaultDependencies=no` or `Before=agentos-mor.service` fails.
- `tests/test_hostcheck.py::ResponderTest::test_the_responder_answers_and_keeps_answering_after_an_exit`: runs `responder.sh` with a stubbed `systemctl`; `alive` is answered, `poweroff` calls `systemctl --no-block poweroff`, and a later `alive` is still answered.
- `tests/test_hostcheck.py::CmdQemuTest::test_credentials_and_memory_reach_the_os_boots_alone`.
- `tests/test_hostcheck.py::ImageTest::test_the_image_leaves_the_host_untouched` (CI, `HOSTCHECK_IMAGE`): `boot,restart,unclean` pass.
- `tests/test_hostcheck.py::ImageTest::test_the_image_in_shutdown_does_not_answer` (CI): the host sends `alive` every 50 ms from before a `poweroff` until QEMU exits; answers come after the `poweroff` (the responder lived into the shutdown), the next boot's responder prints the last boot's journal, where every answer comes before `agentos-mor: mor=cleared` on its monotonic clock, and MOR is cleared.
- `tests/test_hostcheck.py::HostcheckJobTest::test_the_image_job_takes_the_pinned_stack`.

**Scope:** `tools/hostcheck_image/` (new), `tools/hostcheck.py`, `tests/test_hostcheck.py`, `.github/workflows/image.yml` (the new job and its path filters), `image/ASSUMPTIONS.md` (one row), this brief.

**Guard files:** `.github/workflows/image.yml` (gate file: Security accept).

**Tier / gate:** tier A (`tools/hostcheck*`, a gate file): L3 and a separate Security accept. One session; estimate 120k tokens, with CI image runs.
