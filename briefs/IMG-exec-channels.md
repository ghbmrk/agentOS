# IMG-exec-channels: the code the box runs at boot outside unit Exec lines is held to an allowlist

A release finding from #1543's reviews, filed as #1556. SPEC rows: DEV-2, CH-9. Class release, tier A.

**Why one package.** One check in `image/mkosi/mkosi.finalize`, its allowlist file, and its tests; about 300 lines.

**Today.** The tree check holds `tmpfiles.d` to an allowlist (#1543) and refuses sysctl, networkd and command-line routes to forwarding (I21). Three channels run code as root at boot and are not checked at all: a udev rule (`RUN+=`, `PROGRAM=`, `IMPORT{program}=`, and also `SYSCTL{}=`, which writes a sysctl without running anything), an executable generator (`systemd/system-generators` and `systemd/system-environment-generators`), and `modules-load.d`, which loads a module by name. A rules file carrying `RUN+="/usr/sbin/sysctl -w net.ipv4.ip_forward=1"` passes the whole check today, and so would a changed stock generator.

**Requirement IMG-exec-channels.** Every file in those channels, in every directory systemd 257 reads them from, is on `image/mkosi/exec.allow` by its path in the tree and the SHA-256 of what the box reads, or the build fails with the entry that would allow it, for review.
- Directories: `udev/rules.d` (`*.rules`), `systemd/system-generators` and `systemd/system-environment-generators` (any name), `modules-load.d` (`*.conf`), each under `etc`, `usr/local/lib`, `usr/lib` and a split-`/usr` `lib`. Anything under the same directories in `/run` is refused outright: `/run` is a tmpfs on the box.
- Every file in every directory is listed, not only the one that wins its name. systemd's listings for these channels differ from the flag-0 listing `conf_files` models (generators skip non-executable files without taking the name), so a winner-only list could miss the file that runs; listing all of them fails closed.
- Each file is read as configuration (`Conf.content`): a link other than a mask (exactly `/dev/null`, listed as `mask`, as is an empty file) is refused, and so is a step not root's or that others can write. A link the stock tree ships is allowed only by an exact named exception that hashes the in-image target (expected: Debian kmod's `etc/modules-load.d/modules.conf -> ../modules`); the CI build decides which exist.
- A missing `exec.allow` fails closed. `mkosi.finalize --exec-allowlist ROOT` prints the list for a tree.
- Default picked over the per-line form #1556 suggested: a whole-file hash, one file. A per-line udev list needs a udev rules parser (continuations, comments inside a continuation, line ends, the 16 KiB line cap), and each place it could disagree with udevd is a bypass, as #1543's tmpfiles reviews kept finding; a hash parses nothing, and any changed byte fails.

| ID | Test | Why it fails without the check |
|---|---|---|
| IMG-exec-channels | `ExecAllowTest` (tests/test_image.py): per channel, a listed file passes and an unlisted one fails `check.violations`, including #1556's sysctl `RUN+=` rule; a listed file with one byte changed fails; a file shadowed by a non-executable `/etc` file of the same name still has to be listed; a non-mask link fails, a mask passes; anything under `/run` fails; a missing list fails; the regenerate flag round-trips; the repository's `exec.allow` lists the image's own `60-agentos-tpm.rules` by its hash. | Without the check every unlisted file passes. |

**Acceptance tests:** ExecAllowTest (tests/test_image.py)

**Controls that must keep passing.** All of tests/test_image.py, including TmpfilesAllowTest and TreeAccessTest (new allowlist readers are added to its ALLOWED set), and the image workflow's tree check on both builds.

**Threat check.** The attacker is a package update or an `mkosi.extra` edit that adds or changes code run as root at boot, the route I21 names to turning forwarding on behind a clean configuration (DEV-2, CH-9). Recurring kinds from the security lens this must not repeat: a guard that fails open on a missing or invalid value (a missing list, an unreadable file, a refused directory all fail), and a root-side operation that follows a planted link (the check reads only through `Conf`, never following a link on the build host).

**Out of scope.** Unit `Exec` lines other than the secret-holding units' (they stay outside the model, I21); user generators (they run as the user); the initrd's own copies (built separately, IMG-2); `modules_load=` on the command line (held by `finish_image.py`'s command-line allowlist); `ENV{SYSTEMD_WANTS}` and other udev keys need no separate model, since the whole file is hashed.

**Scope:** `image/mkosi/mkosi.finalize`, `image/mkosi/exec.allow`, `tests/test_image.py`, `image/ASSUMPTIONS.md`, `image/README.md`, this brief.

**Usage estimate:** 120k tokens, checkpoint at 120k. Builder model: strongest (tier A).
