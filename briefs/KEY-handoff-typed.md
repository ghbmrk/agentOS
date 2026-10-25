# KEY-handoff-typed: the unlock handoff carries anchors as typed passkeys

Board row: issue #3138 (release, from #3137's reviews of #3116). **Tier A**: every path below is under `broker/clerk`, `broker/kernel` or `broker/cmd` (OPERATING §3). It grows the trusted core (`tools/trusted_core.txt` roots `kernel/key`, `cmd/agentos-unlock`; `clerk/handoff` and `kernel/proc` are `known` lines whose lines count), so it needs, before merge:

1. **A D-159 row.** The build PR opens first (draft is fine), then a one-row DECISIONS.md PR adds the next free `D-NNN`: status `active`; text "Trusted-core growth (D-159) for PR #<build PR> (issue #3138): the unlock handoff and the store's anchors entry carry anchors as typed `key.PublicKey`s, so an ES256 hardware key can anchor the box; review checks each line"; source the approved design, as D-163 cites it: D-146 (card cmsg_01R63S2yrPkq32thy8WQCuvDEyNeBfLkrFtSzV7MZ6RNDJ) and SPEC v1.0 KEY-4 (lane message cmsg_01R91wiieBzMSvPKFsAJVvuKLX2vZYRDWFPWAdtdzhU8Fv). `tools/trusted_base.py` reads only base-branch rows naming the PR's own number (D-159 rule 3), so the row merges first; the build PR then carries `Trusted-core: D-NNN`. No card to Mark.
2. **A Security accept** from a fresh session on the strongest model, in its own comment with `<!-- record: security -->` (D-137 shape, OPERATING §7), beside the tier-A L3 and lens screen (§3, §4). Mechanically the scope below is not a gate file: `tools/premerge.py --needs-mark` matches none of it (its `MARK_PATHS` names `tools/trusted_core.txt` and `tools/trusted_base.py`, not the core's code), so `--check` will not demand the accept. #3138 asks for it because the change grows the trusted core and reshapes what the root-run unlock step hands the kernel; this brief makes it required for this PR regardless. If the build ends up touching `tools/trusted_core.txt`, `--needs-mark` prints `mark` and the gate enforces it too.

## Requirements (local IDs, no SPEC row; serve KEY-4 "a real hardware key anchors the box" and D-146)

- **KEY-handoff-typed-a. The handoff carries typed anchors.** `handoff.KernelKeys.Anchors` is `[]key.PublicKey`. `Marshal` writes each anchor as `uint16` length + `PublicKey.Encode()` (the framing `kernel.SetupMsg` uses) under a new tag (`agentos-kernel-keys/v3`); `parseKeys` refuses the v2 tag, a zero-length or overlong entry, a zero-value key, an entry that decodes to no key, a duplicate, more than `MaxAnchors`, and trailing bytes. `maxHandoff` grows to the ES256 bound (16 × (2 + `len("es256\0") + 253 + 1 + 65 + 1`)) and still sits far below a pipe's 64 KiB, so the comment's "the write never waits" stays true; say so in the comment.
- **KEY-handoff-typed-b. The store's anchors entry is versioned; old entries still read.** `ParseAnchors` returns `[]key.PublicKey`. The entry `kernel/anchors` gains a versioned form (a tag line, e.g. `agentos-anchors/v1\n`, then a count byte and the same length-prefixed `Encode()` entries); a value without the tag reads as today's form (1 to `MaxAnchors` distinct 32-byte keys, wrapped with `key.Ed25519`). Add `EncodeAnchors([]key.PublicKey)` as the writer so tests and a later enrollment/KEY-6 rewrite use one form. Note on ambiguity: a legacy value is ambiguous with the tagged one only if its first key starts with the tag's bytes; the store's MAC covers the entry and only enrollment writes it, so this is not an attacker's choice. State that in a one-line comment; do not add a third form.
- **KEY-handoff-typed-c. The kernel takes them as they are.** `broker/kernel/proc/kernelmain.go` passes `keys.Anchors` straight to `KernelConfig.Anchors` and drops its wrapping loop and the "#3116 follow-up" comment. No behaviour change for Ed25519 anchors.
- **KEY-handoff-typed-d. One decoder, next to the encoder.** Add `key.DecodePublicKey([]byte) (PublicKey, error)` in `broker/kernel/key/passkey.go`, the exact inverse of `Encode`: 32 bytes → `Ed25519`; else the prefix `es256\0`, a final `\0`, the 65 bytes before it as the point and the bytes between as the RP ID, through `ES256` (which validates both). Do not split on NUL: a P-256 point can contain `0x00`. Anything else is `ErrMalformed`. This is one growth in `kernel/key` (already a core root); the alternative, decoding in `handoff`, would put a second copy of the format outside the package that owns it. This file is outside the coordinator's first-named scope; it is in this brief's scope.
- Out of scope: writing `kernel/anchors` from enrollment (no production writer exists today; the setup-only start takes the owner's keys into the log, STO-2c-setup), KEY-6 rewrites, any change to `kernel.Setup`/`SetupMsg`.

## Lifecycle (boot; integration owner `cmd/agentos-unlock`, which owns the matrix)

| Stage \ store holds | ES256 + Ed25519 anchors (tagged) | Ed25519 anchors (legacy form) | no entry | damaged entry |
|---|---|---|---|---|
| unlock reads the store | `ParseAnchors` → typed keys | wrapped as `key.Ed25519` | none | refused in fixed words, no kernel |
| handoff over the pipe | v3, round-trips equal (`==`) | v3 | count 0 | not reached |
| kernel start | anchors as given; an ES256 assertion from the owner's key verifies | as today | setup-only (unchanged) | not reached |

## Acceptance tests

**Acceptance tests:**
- a: `broker/clerk/handoff TestTheHandoffCarriesTheKernelsKeys` extended with an ES256 anchor (catches an anchor lost or misread as Ed25519); `TestADamagedHandoffIsRefused` extended with the v2 tag, a zero-length entry, a length past the end, trailing bytes and a duplicate ES256 key (catches a lenient parse); `TestAnchorsAreBounded` for `MaxAnchors` ES256 keys fitting `maxHandoff` and one more refused.
- b: `broker/clerk/handoff TestAnOldAnchorsEntryStillReads` (new; catches a legacy box losing its anchors) and `TestEncodeAnchorsRoundTrips` (new; tagged form with mixed algorithms, refuses an unknown tag version).
- c: `broker/cmd/agentos-unlock TestTheUnlockStepBecomesTheKernel` run with an ES256 anchor in the store, the kernel accepting a signature by that key (catches the chain dropping or rewrapping it; root test, as the existing one); `TestTheUnlockStepFailsClosed` keeps its "short" damaged-entry case. `broker/cmd/agentos-kernel/main_test.go` and `broker/kernel/proc` tests compile against `[]key.PublicKey`.
- d: `broker/kernel/key TestDecodeInvertsEncode` (new; Ed25519, ES256 with a point holding `0x00` bytes, and refusals: 31/33 bytes, missing final NUL, bad prefix, a point off the curve, an RP ID with `:`), catching a NUL-split or lenient decoder.

## Recurring kinds (acceptance criteria)

From `reviews/security/README.md`: "A guard fails open on a missing, invalid or out-of-range value". The table-driven refusals in tests a, b and d are that check for these parsers: zero, short, overlong, past-the-end and duplicate inputs each fail closed. From this package's own history: one fixed read buffer and copies out of it before it is cleared (#2896 L3 item 2); `key.PublicKey` holds strings, so decoding copies by construction. Keep `Wipe` and `ReadKeys` as they are.

## Scope

`broker/clerk/handoff/handoff.go`, `broker/clerk/handoff/handoff_test.go`, `broker/kernel/key/passkey.go`, `broker/kernel/key/passkey_test.go`, `broker/kernel/proc/kernelmain.go`, `broker/kernel/proc/*_test.go` (type changes only), `broker/cmd/agentos-unlock/main.go`, `broker/cmd/agentos-unlock/main_test.go`, `broker/cmd/agentos-kernel/main_test.go` (type change only), `broker/clerk/run/ASSUMPTIONS.md` (row STO-2b-1-y's entry format), this brief. The D-NNN row is its own PR (DECISIONS.md, append-only, exempt from the conflict guard).

**Guard files:** none: no package is added. `clerk/handoff` newly imports `kernel/key`, a core root with no broker imports, so `tools/trusted_core.txt` needs no new `known` line; the builder confirms `tools/trusted_base.py` reports only line growth.

## Dependencies and estimate

Depends on #3137 (merged). Kernel lane, serial: no open PR may touch the scope files when the build starts (D-111). Tier A builder on the strongest model. Estimate ~70k tokens; expected core growth ~+60 lines (decoder ~20, handoff ~40), which the D-NNN row should state.
