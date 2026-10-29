# HW-3t: supported-host text and test (HW-3, HW-7)

Work item #1003. Board section: Devices, hardware and image (SPEC §13-14). SPEC HW-3 (supported hosts), HW-7 (Macs are not boot targets); HW-10 and HW-11 only for what the text must not promise. Source of the row: `docs/conv-5-uncovered.md` (HW-3, HW-7 and the HW-3t acceptance row). Tier C, one session, tests first (CLAUDE.md).

## The gap

TRACE.md lists HW-3 and HW-7 as uncovered. The owner's guide (`docs/owners-guide.md`) tells the owner what to do when the PC does not start from the drive, but never says which PCs can start it at all. An owner with a Snapdragon laptop, a 2010 desktop or a Mac follows the boot-key steps, gets nothing, and has no sentence that says "this PC cannot run agentOS". Nothing in the repository checks that the image stays UEFI-only.

- **Failure path:** a host outside HW-3 meets the owner as a silent non-start, or a later image change adds a legacy-BIOS boot path that starts agentOS half-way on a pre-UEFI PC, and no test notices.

## Decisions (the brief's; a builder who finds one wrong stops and comments on #1003)

1. **The refusal is the firmware's, and the words are the guide's.** An unsupported host cannot run any agentOS code: pre-UEFI firmware finds no boot entry (the image has `BiosBootloader=none`), and Apple or ARM firmware will not load an x86-64 EFI binary. So no runtime host check is built; it would never run where it matters. "Refused with the plain-words reason" (conv-5's failure path) means: the image stays UEFI-only and x86-64 (decision 3), and the guide's "did not start" paragraph points the owner to the supported-host list. A refusal by the signed flasher before it writes a stick belongs to HW-10's flasher row, not here.
2. **Guide only; the printed card is unchanged.** conv-5 named "owners-guide and card text". The card (`broker/card/render.go`) already has the boot-key table and no room to spare, and touching it would lift this row out of tier C. The card's "did not start" line stays as it is; the guide carries the list.
3. **The image half is a read-only test.** The test reads `image/mkosi/mkosi.conf` and the image workflow; it changes neither (image/ is tier A). Pinning `Architecture=x86-64` in mkosi.conf is worth doing, but it is an image change: the builder comments it on #1003 as a follow-up for the image queue, and does not make it here.
4. **No promises beyond the spec.** The text names no VM option for Macs (HW-7 says post-MVP) and does not promise the Mac or Windows helper app (HW-11, queued after G1 as HELPER-c). "Roughly the last decade" stays a plain-words guide ("most PCs sold in about the last ten years"), not a cut-off date or a model list.

## Package

**Scope:** `docs/owners-guide.md` (one new section and one sentence in "Starting agentOS on your PC"), `tests/test_supported_hosts.py` (new).
**Builds:**
- A section "Which PCs can run agentOS" in the guide, after "Starting agentOS on your PC", in the guide's plain voice (no "UEFI" or "x86-64" without a plain gloss). One list item per class, each with an HTML comment marker in the style of the existing `<!-- host-change: … -->` items:
  - `<!-- host: supported -->` PCs with an Intel or AMD processor and current firmware (UEFI), which covers most Windows 10 and 11 PCs sold in about the last ten years.
  - `<!-- host: unsupported windows-on-arm -->` Windows laptops with an ARM processor, such as Snapdragon models.
  - `<!-- host: unsupported pre-uefi -->` older PCs whose firmware predates UEFI (legacy BIOS only).
  - `<!-- host: unsupported mac -->` Macs, Intel or Apple silicon: a Mac cannot start agentOS from the drive.
- In "Starting agentOS on your PC", the paragraph that says "the PC did not start from the drive" gains one sentence: if the boot menu does not offer the drive either, check the PC against "Which PCs can run agentOS".
- `tests/test_supported_hosts.py`, marked `# REQ: HW-3, HW-7` so `tools/trace.py` counts it; regenerate TRACE.md only if CI's trace check asks for it.

**Acceptance tests:**
1. HW-3: `test_supported_hosts.GuideTest.test_supported_class_named`: the guide has exactly one `host: supported` marker, and its item names Intel or AMD and UEFI. Catches a guide that drops or duplicates the supported line.
2. HW-3: `test_supported_hosts.GuideTest.test_unsupported_classes_named`: the guide has exactly one marker each for `windows-on-arm`, `pre-uefi` and `mac`, each item non-empty and saying the PC cannot run (or start) agentOS. Catches a silently dropped exclusion.
3. HW-7: `test_supported_hosts.GuideTest.test_mac_not_a_boot_target_and_no_vm_promise`: the `mac` item says it cannot start agentOS, and no host item mentions a virtual machine. Catches a text that promises HW-7's post-MVP option.
4. HW-3: `test_supported_hosts.GuideTest.test_did_not_start_points_to_list`: the "did not start from the drive" paragraph names the "Which PCs can run agentOS" section, and that heading exists. Catches the failure path losing its plain-words reason.
5. HW-3: `test_supported_hosts.ImageTest.test_uefi_only`: `image/mkosi/mkosi.conf` sets `BiosBootloader=none`, `Bootloader=systemd-boot` and `ShimBootloader=signed`, and sets `Architecture=` only to `x86-64` if at all. Catches a legacy-BIOS or non-x86-64 boot path added to the image.
6. HW-3: `test_supported_hosts.ImageTest.test_image_built_on_x86_64`: every job in `.github/workflows/image.yml` runs on an x86-64 runner (no `-arm` runner label), since mkosi builds for the build host's architecture while decision 3's pin is outstanding. Catches an ARM runner silently producing an ARM image.

Each test fails first against today's guide (1 to 4) or against a planted one-line mutant of a copied mkosi.conf or workflow (5, 6: the test takes a path, so a mutant can be fed in; keep the mutant cases in the test file).

**Also run:** `cd broker && go test ./hostchange/` (its test parses the guide's `host-change` markers; the new `host:` markers must not collide), `python3 tools/doclint.py`, and `python -m unittest tests.test_ci_scope` (the new test reads `image/` and `.github/` files; if CI-PATHS needs the reads recorded, follow its message).

**Size:** about 35k tokens, tier C, Sonnet 5.5. **Depends on:** nothing.
