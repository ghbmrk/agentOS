# OWN-card-ca: the page authority's fingerprint, the core's name and the address-bar line on every Owner Card

Work item #3167 (SPEC HW-1, CH-9, REC-4). Tier A (`broker/card`, `broker/localui`, `broker/firstboot`). Written 2026-10-27 against main at c88cd8b.

**Waits on #3465** (WIFI-del-f, armed): it edits `broker/card/render.go` and the card tests this build touches (D-111). Start only once it has merged, and rebase on it.

## Why

HW-1: the box generates every Owner Card after the core's page authority, so every card carries its fingerprint; REC-4's rotation works the same way. CH-9: the owner checks the fingerprint a phone shows against the one printed on the card before any reinstall, and the card states in one line that agentOS asks for a code or secret only on a page whose address bar shows the core's name. A card printed without the fingerprint can never get it, because the authority is never rotated (only a compromised restore replaces it, REC-5). Today the card prints the page's address (`BoxPage`, C10) but no fingerprint and no address-bar line.

## What changed since the row was filed

- #3166 (agentosd gets an STO-2 sealer for the authority) was closed as not planned. Under MIG-4-recovery-f (#3253, merged; Mark's card cmsg_01R91wiieBzMSvPKFsAJVvuKCSPvYYMZpQY6nGnEFboyQw), enrollment makes the authority (`agentos-enroll` `putPageCA`) and the kernel holds it and answers `certify`. f2 (#3289) has agentosd's `OpCertify` forward to the kernel. The page (`localui.PageTLS.Renew`) already receives the authority's certificate (`localapi.Certified.Authority`, DER) and checks the leaf against it. That certificate is public, and it is all the card needs.
- `localui` must never link `pageca` (`broker/localui/imports_test.go`, key custody), and it links `card`. So `card` does not import `pageca` either (as `pagename_test.go` already notes): it computes the fingerprint itself, and a test pins it to `pageca.Fingerprint`.

## Order on the new core: the authority is staged before the card (decided)

On the new core the order is circular. Enrollment makes the authority, but it runs only once setup has written the Owner Card's two factors to `/run/agentos-setup` (`agentos-keeper-enroll.service`), that is, after the card is confirmed. HW-1 needs the authority before the card is shown. No code builds the new core's first-boot card flow yet (`broker/clerk/seal/ASSUMPTIONS.md` STO-2c-h: "nothing in the image writes `/run/agentos-setup` yet").

**Chosen: stage the authority first.** HW-1 fixes the order ("after the core's page authority"), so this is an engineering choice within it, not a SPEC change. There is no pre-enrollment signer: before enrollment nothing issues a leaf, and the page stays plain HTTP, as it is today until the enforcer installs trust (§12.1 step 4). **The one path to the card at first boot:** a new keeper unit makes the pair, publishes the certificate, and the owner side reads the published certificate and passes it to `card.DisplayConfig.Authority`. Enrollment then binds what was printed to what the kernel will serve. #3470 (OWN-card-flow) builds it under these invariants:
- **Who makes it.** A new keeper unit (`agentos-keeper-pageca.service`, named `agentos-keeper-*` and listed in `mkosi.finalize`'s `KEEPER_UNITS`) runs at first boot while no store exists. It is not root `agentosd.service`, which sits outside the keeper mask (STO-2c-h, limit 1). It writes the staged pair (certificate and PKCS#8 key) as `/run/agentos-setup/page-ca`, 0600 root, in the 0700 root directory, created with `O_EXCL|O_NOFOLLOW`, and never overwrites it: a rerun with the file present is a no-op. Only that unit and enrollment ever read the key.
- **The published certificate.** The same unit writes the certificate alone (public) to `/run/agentos-page-ca/authority.der`: root-owned, 0644, in a root 0755 directory, also `O_EXCL` and never overwritten, so nothing on the owner side can write or replace it. The owner side (`agentos-localui`) reads it with no-follow, a size bound, and a check that it is a regular file owned by root and not group- or world-writable. Then the card's own check (slice a, item 1) runs. That reader and its wiring into the first-boot card step are #3470's, and they replace slice (a)'s `PageTLS` source at first boot. `PageTLS.Authority()` stays the source for rotation (REC-4), which only happens after enrollment, when the kernel serves the authority.
- **Enrollment binds it.** `agentos-enroll` takes the staged pair (`-page-ca-file`) instead of calling `pageca.New`. Before storing anything, it refuses unless the staged key matches the staged certificate's public key, the certificate passes `pageca`'s own load checks, and the certificate is byte-for-byte equal to the published one. So the kernel holds, and `certify` serves, exactly the authority whose fingerprint the confirmed card carries. `ExecStartPost` removes the staged pair and the published certificate beside the factors, and enrollment zeroes the key bytes it read.
- **Restart before the confirm.** Both files are on tmpfs, so a reboot loses the pair and the unconfirmed card together. The next boot makes a new authority, and so a new fingerprint on a new card. An abandoned setup without a reboot keeps the key in root-only tmpfs: no swap (`systemd.swap=0`), and with no signer no leaf is ever issued from it (later: bound that window if a signer is ever added).

Rejected:
- **Enroll before showing the card.** The store would be sealed to factors nobody has confirmed holding, which is the confirm HW-1 asks for. An unconfirmed card would then mean deleting and re-enrolling the store, spending TPM NV writes and the log anchor's counter at every abandoned setup.
- **Print the fingerprint on a second sheet after enrollment.** The Owner Card itself would not carry the fingerprint, which HW-1 and CH-9 require. That would take an L1 change to HW-1, and it would leave the owner two sheets to keep together.

## Slice (a): this build

1. **The card takes the authority.** `card.DisplayConfig` gains `Authority []byte` (the authority's certificate, DER). `NewDisplay` refuses a nil, unparseable or wrong authority with `card.ErrNoAuthority` before drawing any randomness. Wrong means not a CA (`BasicConstraintsValid`, `IsCA`, `MaxPathLenZero`, exactly as `pageca.go:140` requires), or a name constraint that is not critical or does not permit exactly `PageName`. That check is the card's own reading. It does not replace the phone's check or `pageca`'s, but it stops the card from printing the fingerprint of a certificate that is not the page's authority. A new `card/authority.go` holds `Fingerprint(der)` (SHA-256 of the DER, upper-case hex in groups of four, byte for byte as `pageca.Fingerprint`) and that check.
2. **What the card prints.** On the card's front, beside the Wi-Fi page line (as #3465 leaves it), the card prints `Page name: agentos.internal`, `Page fingerprint:` with the 16 groups in two lines of eight (mono), and the line "agentOS asks for a code or secret only on a page whose address bar shows agentos.internal." Below the fingerprint it prints one more line: "If your phone ever asks you to install or trust a certificate for this page, check that it shows this fingerprint; if it does not, stop and install nothing." The rotation sheet (`rotationHTML`, every rotation whatever its parts, REC-4) prints the same three lines, because the owner may keep only the newest sheet. `HTML` and `rotationHTML` take the fingerprint from the display, not from `Card`, so `Card` stays the set of secrets that `wipeCard` clears. The fingerprint is not a secret: `Display`'s placeholder formatting and the fixed journal strings stay as they are.
3. **The page passes it.** `localui.PageTLS` keeps the authority certificate from its last verified `Renew` and returns a copy from a new `Authority() []byte`. It is nil before the first success and is never cleared by a failed renewal. `cmd/agentos-localui` builds the card step after `pageTLS` and passes `pt.Authority()`, or nil when there is no HTTPS, into `CardBox` and the rotation wiring (`rotwire.go`). In this slice that is the only source. It serves rotation for good, and the old core's first boot until #3470 replaces the first-boot source with the published certificate (above).
4. **No authority, no card (fail closed).** `firstboot.NewCardStep` with a nil `cfg.Authority` builds no display and draws no card randomness. Its `Hold()` returns the fixed `firstboot.ErrNoAuthority` ("I cannot make your Owner Card until my page authority exists"), and `Display()` is nil, so the page shows that line and `setup_finish` still answers `card pending`. It never errors out of `Begin`, so the page does not crash-loop. A rotation started with no authority refuses with the same fixed text before anything is generated or sent to the vault. **Consequence, stated so the reviewer checks it is intended:** every box today has no authority before enrollment, so the old core's vault-backed first boot holds at the card step. That is HW-1's order, since a card printed now could never carry the fingerprint. That setup path is retired at migration step 5, and the new-core flow that supplies the authority is #3470.
5. **Tests that build cards** take a test authority: `pageca.New(pageca.DefaultName, built, nil)` in `_test.go` files only. `imports_test.go` checks the non-test link, which stays free of `pageca`. A shared helper in each package's tests keeps the edit small.

## Lifecycle matrix (integration owner: the new-core first-boot card row; this slice owns the card's side)

| Stage | Authority given | Card step | Printed |
|---|---|---|---|
| First boot, authority known | yes | card generated and shown | name, fingerprint, address-bar line |
| First boot, no authority (every box until #3470) | nil | holds with the fixed text; no randomness drawn | nothing |
| Restart before confirm, before enrollment (#3470) | a new staged authority | new card (F10) | a new fingerprint |
| Restart after enrollment (old-core path, rotation) | same authority from the kernel | new card or sheet | same fingerprint |
| Rotation (REC-4) | yes | rotated parts shown | the same three lines on the sheet |
| Rotation, no authority | nil | refused before generating | nothing |
| Malformed or unconstrained certificate | invalid | refused as no authority | nothing |

## Scope

`broker/card/{authority.go,authority_test.go,display.go,render.go,ASSUMPTIONS.md}` and the card tests that build displays or pages (`card_test.go`, `display_test.go`, `rotation_test.go`, `discardhook_test.go`, `wifidel_test.go`, `pagename_test.go`); `broker/firstboot/{card.go,start.go,claim.go,ASSUMPTIONS.md}` and their tests (`card_test.go`, `claim_test.go`, `start_test.go`, `again_test.go`); `broker/localui/{tls.go,tls_test.go,firstboot.go,rotwire.go,ASSUMPTIONS.md}` and the tests that build card configs (`cardwire_test.go`, `rotwire_test.go`, `rotation_test.go`, `cardsock_test.go`, `localui_test.go`); `broker/cmd/agentos-localui/{main.go,main_test.go}`; the test fixtures in `broker/cmd/agentosd/{setupcard_test.go,setupclaim_test.go}`, `broker/cmd/agentos-seller/seller_test.go`, `broker/e2e/boxe2e/parse_test.go` and `broker/recovery/rotation_display_test.go`, only where they construct a card display; this brief. No `cmd/agentosd` non-test file, so this build takes no slot in the serial agentosd chain. Nothing under `tools/old_core.txt`.

**Guard files:** none. No package is added, and `card` gains only standard-library imports (`crypto/sha256`, `crypto/x509`, `encoding/hex`).

## Acceptance tests

- HW-1, CH-9 (printed): `broker/card/authority_test.go::TestCardPrintsTheAuthoritysFingerprintAndName`: the full card's HTML holds the fingerprint of the given authority, `agentos.internal` and the address-bar line. It catches a card missing any of the three.
- CH-9 (one rendering): `::TestFingerprintMatchesPageca` (equal to `pageca.Fingerprint` for a generated authority). It catches a card and a phone-side page showing different strings.
- HW-1 (fail closed): `::TestNoAuthorityNoCard`. With a nil authority, garbage, a CA without the critical constraint, or one constrained to another name, `NewDisplay` returns `ErrNoAuthority`, and a counting `Rand` shows nothing was read. It catches a fingerprint-less card, or one printing a stranger's certificate.
- REC-4: `broker/card/rotation_test.go::TestRotationSheetPrintsTheFingerprint`, for each single part. It catches a rotation sheet without it.
- `broker/firstboot/card_test.go::TestCardStepHoldsWithoutAuthority`: `Hold()` is `ErrNoAuthority`, `Display()` is nil, and `Begin` succeeds. It catches a crash-loop or a card drawn early.
- `broker/localui/tls_test.go::TestPageTLSKeepsTheVerifiedAuthority`: nil before success; the certificate after; unchanged by a failed renewal; a copy, not shared storage.
- `broker/localui/rotwire_test.go::TestRotationRefusesWithoutAuthority`: no vault call, fixed text.
- `broker/cmd/agentos-localui/main_test.go::TestCardStepGetsThePagesAuthority`: the card step is built after `pageTLS` and shows the fingerprint of the certified authority; with no HTTPS it holds.
- Existing: `broker/localui/imports_test.go` (still no `pageca` in localui's link) and every card, firstboot and localui test with the fixture.

**Recurring kinds to check (security and UX lens READMEs):** a guard that fails open on a missing value (nil authority); raw error text in a fixed-class log or page line; a scope that omits the test files the change forces; owner text that names the page two ways (the card's "Wi-Fi page" from #3465 and "page name" must read as one page).

## ASSUMPTIONS rows

- `broker/card` C19: the card validates and fingerprints the authority certificate it is handed, refuses without one, and prints the name, the fingerprint and the address-bar line on the card and every rotation sheet; it imports no `pageca`.
- `broker/firstboot` F19: with no authority the card step holds with a fixed line and draws nothing; the old core's first boot therefore holds until the new-core flow supplies an authority.
- `broker/localui`: `PageTLS.Authority` is the last verified certificate; the card step and the rotation take it.

## Dependencies

#3465 (merge first). MIG-4-recovery-f1 (#3253, merged) and f2 (#3289) for where the authority lives; slice (a) needs only `localapi.Certified.Authority`, which exists on main. The new-core flow (#3470) supplies the authority on a new-core box; this slice does not wait on it.

**Usage estimate:** about 110k tokens, single session (mostly test fixtures). Checkpoint at 70k: `broker/card` and `broker/firstboot` green.
