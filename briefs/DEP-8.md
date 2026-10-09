# DEP-8: depaudit refuses a subordinate range that maps the scenario onto a real account (DEP-6-r1)

Release finding from the Security re-signs on #568 (DEP-6, merged at 0479f07): re-sign on b9a02ef, point 2 (comment 6077963620), and re-sign on a68e912, point 1 (comment 6078209969), which was folded into this row. Needed for A9 (evidence integrity: the scenario runs as an id no one else owns, DEP-3a). The BOARD row DEP-6-r1 links here.

**The defect.** `_subordinate` accepts the first `/etc/subuid` (`/etc/subgid`) line for the runner with any start, 0 included, and `_id_maps` maps `SCENARIO_ID` onto that start. `usermod --add-subuids` applies no floor, and newuidmap only checks that the outer id lies inside the caller's grant. So a range at 0 makes the scenario host root, and a range at a login uid makes it that user: the scenario then owns their files, which defeats DEP-3's unused unprivileged id. Today the only guard is the remedy text DEP-6e prints (D14 (3)). This package moves the guard into the code. The remedy text then states exactly what the code checks.

**Why one package.** All of it is one predicate on the range `_id_maps` returns, plus the text that describes that predicate. About 80 lines of code and tests in `tools/depaudit.py` and `tests/test_depaudit.py`. Do not split it.

**Build after DEP-7.** DEP-7 (DEP-3-r1 to r7, building now) edits the same files: `IdMapTest` (DEP-7e gives `SUBGID` its own file), `_inner` and the controls. Building in parallel would make the second merge a tier-A delta that needs another Security re-sign (OPERATING §3). Start from main after DEP-7 merges, and reread `_subordinate`, `_id_maps`, `_sandbox_missing`, `IdMapTest`, `UnavailableTest` and `SUBMOUNT_HELPER` there. Names in this brief are from main at 0479f07. No line numbers are given, because DEP-7 will move them.

## Requirements

Local IDs: there is no SPEC row, and this is a defect in tooling. As in DEP-6 and DEP-7, the tests carry the "local ID, no REQ marker" docstring, and they trace to A9 through DEP-3a.

The **range** is the first line in the file whose owner is the runner (by name or uid, as today), read as `[start, start+count)`. It is the uid range from `SUBUID`, or the gid range from `SUBGID`. The **mapped id** is `start`, the outer id that `SCENARIO_ID` becomes. A range that breaks any rule below is *no usable range*: `_id_maps()` raises `OSError` with a reason, so `sandbox_available()` is false and `depaudit run` exits 2. There is no fallback, either to a later line or to `-r`.

| ID | Rule |
|---|---|
| DEP-8a | **Floor.** `start` must be at least the floor. The uid floor is `max(100000, SUB_UID_MIN)` and the gid floor is `max(100000, SUB_GID_MIN)`, with the value read from `/etc/login.defs` when the key is present. A missing file or a missing key means the floor is 100000. A value that cannot be parsed is a reason (fail closed), not a default. The login.defs path is a module constant, as `SUBUID` is, so tests can point it at a temp file. Taking the max means a host that lowers `SUB_UID_MIN` cannot lower the floor below 100000. That keeps every id systemd reserves below the floor: nobody (65534), systemd-homed (60001–60513) and DynamicUser (61184–65519). |
| DEP-8b | **No real account.** No uid in the uid range belongs to an account, and no gid in the gid range to a group. D13 maps only `start` (count 1), so the check that carries the security property is (1) plus (3) on the mapped id; (2) over the rest of the range is defence in depth. "Account" means three sources, checked in this order: (1) the runner's own `os.geteuid()`/`os.getegid()`, whether or not they have an entry; (2) every account NSS enumerates, from `pwd.getpwall()`/`grp.getgrall()`, best effort (see below); (3) a **fail-closed** direct NSS lookup of the mapped id through `getpwuid_r(start)`/`getgrgid_r(start)` called via ctypes, as `_has_mount_setattr` calls libc. Grow the buffer on `ERANGE` (cap it, e.g. 1 MiB; past the cap is a reason). Return 0 with a NULL result means free; return 0 with a result means taken; any other return means the range is unusable, and the reason names the call and the errno (`errno.errorcode`). Never use `pwd.getpwuid`/`grp.getgrgid` for (3), and never fall back to them. (3) covers the mapped id on hosts that do not enumerate: SSSD and LDAP default to `enumerate = false`, so neither `getent passwd` nor `getpwall()` lists their users, but a lookup by id still finds them. The range ends at or below 4294967294, because 4294967295 is `(uid_t)-1`. |
| DEP-8c | **No other owner.** The range overlaps no line in the same file that belongs to another owner, where "another owner" is any name or uid other than the runner's. Two ranges that only touch (one ends at `s-1`, the next starts at `s`) do not overlap. **Strict parse:** every non-blank line in the file must parse as `name:digits:digits` (name non-empty, no `:` or whitespace; ASCII decimal digits only, no sign, space or base prefix, and no leading `0` unless the field is exactly `0`, for both start and count). shadow reads both fields with `a2ul(…, 0, …)` (`lib/subordinateio.c`), i.e. base 0: `0303240` is octal 100000 and `0x186a0` is hex 100000. The rule makes every line this check accepts read the same in base 0 and base 10, so the check and newuidmap never disagree. Any other non-blank line makes the range unusable, and the reason names the file and the line. Today `_subordinate` skips a line that fails `isdigit()`; shadow's `getulong` may honour some of those (a leading space, `+`, `0x`), so skipping one could hide an overlapping grant. |
| DEP-8d | **First line only.** If the runner's first line breaks a rule, that is the result: never fall through to a later line. Which ids get mapped must not depend on line order without the operator seeing it. |
| DEP-8e | **Reason and remedy match the check.** The `OSError` text names the file, the line as written, and the first rule it breaks, with the numbers involved. Examples: `range 0:65536 for runner in /etc/subuid is not usable: start 0 is below the floor 100000 (SUB_UID_MIN)`, `…: uid 1001 (runner) is in the range`, `…: overlaps alice:100000:65536`. A missing range keeps today's text. `_sandbox_missing`'s remedy then states the same rules and nothing more: START at least the floor (print the number the code computed, and name `SUB_UID_MIN`/`SUB_GID_MIN`); a range that contains no uid or gid that `getent passwd`/`getent group` or a lookup by id returns, and not the runner's own; and a range that overlaps no other owner's line in `/etc/subuid` or `/etc/subgid`. Keep the D13 pointer. If a range exists but is unusable, say "replace it" rather than "add one". Drop "above every uid": the code checks overlap, not "above". |

**Why NSS and not the local files (input 2).** The local files miss NSS/LDAP/SSSD users, systemd-homed users and DynamicUser ids. All of these can own files on the host, and the kernel maps the id, not the source the name came from. `pwd.getpwall()` and `grp.getgrall()` call `getpwent`/`getgrent` through nsswitch: the same source as `getent passwd`/`getent group`, with no subprocess and no PATH lookup. On hosts that use `files` they include the local files. So the remedy says `getent`, and the code calls the libc functions behind it. **Enumeration is not fail-closed and cannot be made so:** `getpwent` returns NULL both at the end of the list and on an NSS error, and CPython's `pwd_getpwall` returns whatever it collected (`Modules/pwdmodule.c`, 3.12). CPython's `getpwuid`/`getgrgid` also raise `KeyError` for any nonzero `getpwuid_r` status but `ERANGE`, so an SSSD or LDAP outage reads as "not found". That is why (3) calls `getpwuid_r`/`getgrgid_r` itself. From glibc's `nss/getXXbyYY_r.c` (read, not run): NOTFOUND returns 0, UNAVAIL and TRYAGAIN return an errno. The builder confirms on CI that a free id gives (0, NULL) and the runner's own euid gives (0, entry); if not, escalate. The systemd ranges lie below the floor and DEP-8a refuses them even when the service that owns them is not running. If the builder finds a case where `getpwall()` and `getent passwd` disagree on CI, say so in the PR. Never fall back to reading only `/etc/passwd`.

**The fail-closed edge (input 2, noted).** The old text, "above every uid in /etc/passwd", cannot be met on a host that has an entry at a very high uid, for example 4294967294. Under DEP-8b's overlap rule that entry blocks only a range that contains it. If a host's ranges are ever all unusable, the run exits 2 with the reason. That is fail closed, and it needs no further action.

## Failing-test-first table

Each test must be shown red at main (after DEP-7), with the failing message cited in the PR, and green at the head. Drive every case through `_id_maps()` with `assertRaises(OSError)` or the expected maps, and assert the reason text with `assertIn`. Patch three things: `SUBUID`/`SUBGID` (as `IdMapTest.ranges` does, with separate files after DEP-7), the login.defs constant, and the account sources (`pwd.getpwall`, `grp.getgrall` via `mock.patch.object`, and a thin module helper that wraps the ctypes `getpwuid_r`/`getgrgid_r` call and returns `(rc, found)`; the policy on `rc` lives outside that helper, so patching it leaves the policy under test). With those patched, no case depends on the CI host's accounts. Two cases run the ctypes helper unpatched against the real NSS: the runner's own euid gives `(0, True)`, and an id with no entry (e.g. 4294967200) gives `(0, False)`.

| ID | Case | Expect | Why red at main |
|---|---|---|---|
| 8a | runner range at `0:65536`, `1000:65536`, `99999:65536`; no login.defs | refused, reason names the floor 100000 | `_subordinate` accepts any start |
| 8a | `100000:65536`, no login.defs | maps `(1000, 100000, 1)` | (passes at main; guards against over-refusal) |
| 8a | login.defs `SUB_UID_MIN 524288`, range `200000:65536` | refused, reason names 524288 | no floor |
| 8a | login.defs `SUB_UID_MIN 65536`, range `99999:65536` | refused (the max holds 100000) | no floor |
| 8a | login.defs `SUB_GID_MIN 300000`, uid range `200000`, gid range `200000` | refused on the gid side only | no floor |
| 8a | login.defs `SUB_UID_MIN abc` | refused, reason names login.defs | no parse |
| 8b | `getpwall` lists uid 150000; range `100000:65536` | refused, names uid 150000 | no account check |
| 8b | runner's euid patched to 120000, with no passwd entry; range `100000:65536` | refused, names the runner | no account check |
| 8b | runner's egid patched to 120000, with no group entry; uid side clean, gid range `100000:65536` | refused on the gid side, names the runner | no account check |
| 8b | `getpwall` empty, the uid lookup of 200000 returns `(0, True)` (an unenumerated SSSD user); range `200000:65536` | refused | no lookup by id |
| 8b | `getgrall` empty, the gid lookup of 200000 returns `(0, True)`; uid side clean, gid range `200000:65536` | refused on the gid side | no lookup by id |
| 8b | the uid lookup returns `(EIO, False)`; then separately `(EAGAIN, False)`; range `200000:65536` | refused, names `getpwuid_r` and `EIO`/`EAGAIN` | at main an NSS error is never seen |
| 8b | the gid lookup returns `(EIO, False)`; then `(EAGAIN, False)`; uid side clean | refused on the gid side, names `getgrgid_r` | as above |
| 8b | ctypes helper unpatched: the runner's own euid; then 4294967200 | `(0, True)`; `(0, False)` | (new helper; confirms the glibc return contract on CI) |
| 8b | `getgrall` lists gid 150000; gid range `100000:65536`, uid side clean | refused on the gid side | no group check |
| 8b | `getpwall` lists 4294967294; range `100000:65536` | maps (an entry outside the range does not block) | (passes at main) |
| 8b | range `4294967200:95` (ends at 4294967294) | maps | (passes at main; pins `<=` on the end bound) |
| 8b | range `4294967200:96` (ends at 4294967295) | refused | no end check |
| 8b | unpatched: the real runner's own euid as the range start, count 1 | refused | accepted at main. Smoke only: on CI (euid 1001) the floor refuses it first, so it does not cover 8b(1); the patched euid/egid cases do (LATER DEP-8 l1) |
| 8c | `alice:150000:65536` and runner `100000:65536` | refused, names `alice:150000:65536` | no overlap check |
| 8c | `alice:165536:65536` and runner `100000:65536` (adjacent) | maps | (passes at main) |
| 8c | `alice:165535:1` and runner `100000:65536` (one-id overlap at the end) | refused, names `alice:165535:1` | no overlap check |
| 8c | gid side: `alice:150000:65536` and runner `100000:65536` in `SUBGID`, `SUBUID` clean | refused on the gid side | no overlap check |
| 8c | `alice:99999:1` and runner `100000:65536` (touches the lower edge) | maps | (passes at main) |
| 8c | `alice:99999:2` and runner `100000:65536` (ends at 100000, one-id overlap at the start) | refused, names `alice:99999:2` | no overlap check |
| 8c | `alice: 150000:65536`, and separately `alice:0x24000:65536`, next to runner `100000:65536` | refused, names the line as unparsable | the line is skipped |
| 8c | `alice:0303240:65536` (octal 100000 to shadow), and separately `alice:0x186a0:65536` (hex 100000), next to runner `100000:65536`; also `alice:150000:065536` (leading zero in count) | refused, names the line as unparsable | read as decimal 303240 or skipped, so no overlap is seen |
| 8d | runner `0:65536` then runner `300000:65536` | refused, names `0:65536` | at main the first line is taken, so this is red only through the floor; keep the case to pin "no fall-through" against a mutant that skips bad lines |
| 8e | `sandbox_available()` with a refused range (the probe binaries present, as in `UnavailableTest`) | `SANDBOX_WHY` has the rule's reason, `replace it`, the computed floor, `getent passwd`, `getent group`, and `/etc/subuid or /etc/subgid`; no `above every uid` | the text says "above every uid" and "add one" |
| 8e | a range that is missing | `add one` with the same rules | (text change) |

**Mutants.** Each must turn a named test red; cite the message in the PR. All of them run locally, because none needs the sandbox.

| Mutant | Fails |
|---|---|
| floor check deleted; `<` → `<=` on the floor; `max` → `min` | 8a cases |
| the floor ignores login.defs, or the gid side uses the uid floor | 8a `524288` and `SUB_GID_MIN` cases |
| the runner's euid check deleted; the egid check deleted | 8b runner euid case; 8b runner egid case |
| the uid lookup by id deleted; the gid lookup by id deleted | 8b SSSD uid case; 8b gid mirror |
| a nonzero lookup return treated as free (uid side; gid side) | 8b `EIO`/`EAGAIN` uid rows; gid rows |
| `getpwall`/`getgrall` check deleted | 8b enumerated cases |
| end bound `<=` → `<`, or the end check deleted | 8b `4294967200:95` / `:96` pair |
| other-owner overlap deleted; `<` vs `<=` at the runner's end | 8c `alice:165536` / `alice:165535:1` pair |
| `<` vs `<=` at the runner's start (`runner.start < other.end`) | 8c `alice:99999:1` / `alice:99999:2` pair |
| leading zeros accepted and read as decimal | 8c `0303240` / `065536` rows |
| overlap checked in `SUBUID` only | 8c gid-side row |
| unparsable lines skipped | 8c `alice: 150000` / `0x24000` rows |
| a bad line skipped instead of refused | 8d |
| the remedy keeps `above every uid` or drops the floor number | 8e |

## Controls and tests that must keep passing

- All built-in controls on `assurance/dep-targets.json`, `control-own-user-namespace` and `control-distinct-uid` in particular. The maps for a usable range are unchanged (D13).
- **`SubmountTest` needs a change.** `SUBMOUNT_HELPER` binds a private `root:1000:1` over `/etc/subuid` and `/etc/subgid` inside its outer namespace. DEP-8a refuses that range, so both `SubmountTest` cases would skip or fail. A suggested route, not a requirement: map the subordinate id to itself in the outer namespace (`--map-users=S:S:1`, and the same for groups), and have the helper write `root:S:1`. Inside the outer namespace S is then the real range start, which passes the floor and the account check, and the nested sandbox maps `1000 → S` as on the host. Confirm on CI that `control-own-user-namespace`'s expected lines still hold inside the nested sandbox. If that route fails, escalate. **Never** add an env var, flag or argument that lowers the floor or skips the checks for tests. Test seams are the module constants and patched functions named above.
- `IdMapTest`'s existing cases use starts 300000 and 400000 and an owner `someone:5000:10`. Patch the account sources there so they do not depend on the host.
- On CI, `assurance.yml` adds `100000-165535` only when the runner has no range. The runner already has `runner:165536:65536`. Both meet the floor. No workflow change is needed. LATER DEP-6 l13 stays as is.

## Threat check for the reviewer

- Every rule can only turn a range unusable. No code path makes `_id_maps()` succeed where main raises, except through the unchanged "first matching line" read.
- No env var, flag or parameter reachable from `depaudit run` lowers the floor, skips a source, or picks another line. A `login.defs` value below 100000 has no effect (the max).
- A failed NSS lookup of the mapped id refuses the range, never reads as free: `getpwuid_r`/`getgrgid_r` via ctypes, where any return but 0 (after `ERANGE` growth) is a reason naming the call and errno. CPython's `pwd.getpwuid`/`grp.getgrgid` cannot give that signal (they raise `KeyError` for every error), so they are not used for it. `getpwall`/`getgrall` are best effort: an NSS error mid-enumeration returns a short list silently, which is why the mapped id never relies on them. If either raises, the range is unusable.
- Every non-blank line parses strictly or refuses the range, so a line newuidmap would honour cannot hide from the overlap check.
- The checks run before the namespace exists, in the runner's own process. The scenario cannot influence them.
- No change to `AS_SCENARIO`, `DROP_CAPS`, `SCENARIO_ID`, the map shape, the controls or `_inner`. A diff there is out of scope.

## Out of scope

- Computing and printing a free range: the remedy states the rules, not a range (D14 (3)).
- Checking every id in the range by direct lookup (65536 NSS calls per run, network-bound under LDAP). Enumeration covers the range on a best-effort basis; the lookup by id covers the mapped id.
- `assurance.yml`'s fixed range (LATER DEP-6 l13). DEP-3 l8/l9 and the DEP-6 later lines.

## Scope

- `tools/depaudit.py`: `_subordinate`, `_id_maps`, new helpers for the floor and the account check, and the remedy string in `_sandbox_missing`.
- `tests/test_depaudit.py`: `IdMapTest`, `UnavailableTest`'s remedy test, and `SUBMOUNT_HELPER` plus `SubmountTest`'s outer map.
- `tools/ASSUMPTIONS.md`: D13 (the range rules, and the SubmountTest outer map if it changes) and D14 (3). In D14 (3), replace "The text is the only guard until the `_id_maps` floor check lands (BOARD DEP-7)" with a pointer to DEP-8.
- `briefs/DEP-8.md` (Delivery notes only), BOARD row DEP-6-r1.

**Needs:** DEP-6 (merged, #568) and DEP-7 (must merge first; see above).

**Done:**
- CI is green, and `dependency-audit` runs `IdMapTest`, `UnavailableTest` and both `SubmountTest` cases unskipped. Grep its log for the new test names, `PASS control-own-user-namespace` and `PASS control-kept-read-only`, and quote them.
- DEP-8a–e are covered, and each mutant is shown red with its message in the PR.
- `depaudit run` on `assurance/dep-targets.json` passes.
- Risk tier A (`python3 tools/risk_tier.py --git origin/main HEAD`).

## Delivery

Builder model: strongest model (risk tier A: `tools/depaudit*`). One package per session, tests first: land each test red at main before the fix, and keep the message for the PR. Locally there is no newuidmap and no subordinate range, and installing them needs a permission prompt, so the `SubmountTest` change is verified on CI only. Do not attempt live probes that need one. Review: L3 on the strongest model with the threat check above, then the UX and Potency lens and a separate Security section (OPERATING §3–4). Security re-signs any later tier-A delta. Estimate/checkpoint: about 60k tokens, not a ceiling (OPERATING §5). Checkpoint: if `SubmountTest` is still red on CI after two fix attempts, stop and escalate with a diagnosis. Do not weaken the rules to pass it.

## Delivery notes
