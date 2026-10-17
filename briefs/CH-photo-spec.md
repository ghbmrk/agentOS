# CH-photo-spec: photos from the owner as agent input

Tier B (SPEC text). Builder: Opus 5.5. Usage estimate: 60k tokens. Needs Mark's approval of the SPEC diff (L1 spec-diff PR).

**Why.** Mark: "A core interaction will be sending photos and having the guest act on information from it." He chose "Text + Wi-Fi" on the Decisions card (2026-10-17 13:21Z): a photo upload on the Wi-Fi page first, picture texts from the owner's number once modem MMS is qualified, only the owner's photos kept, and photos untrusted, never authority or approval. His later answer (13:33Z) made a photo attached to a text, as to a friend, the owner's normal interaction, so picture texts are the primary path and the Wi-Fi upload does not gate them. Today the spec has no inbound photo path: ARC-6's model endpoint and inbound API carry text only, and CH-20 covers outbound MMS only.

## Requirements
- **CH-22** The flow and its two intake paths (picture texts primary, behind HW-2; Wi-Fi upload as the full-resolution extra, not gating them), the MMS bearer's limit, locked-session holding (CH-14), and the owner's route: a photo attached to a text, carried only by carrier MMS, with mail not photo intake (owner's answer 2026-10-17 13:33Z, cmsg_01R91wiieBzMSvPKFsAJVvuKU3QH716cMAGrswGsH9ayRu). The interim notice for dropped picture texts is the separate silent-drop fix, referenced, not specified.
- **CH-23** Owner-only intake, types and limits, decoding in a confined process with re-encoding and metadata removal, and how a picture text's text part is handled.
- **CH-24** Delivery to the guest (inbound API plus a broker tool), the `private` label, how the guest acts on a photo, image-capable routes only, and the no-route case.
- **CH-25** A photo authorizes nothing: never a control word, code, grant or verified field.
- **CH-26** Storage as an OP-11 content store, 30-day default retention, owner deletion as a CAP-3 erase.
- **CH-27** What the owner is told, in fixed one-segment texts.
- **HW-2** Extended to MMS send and receive with its cellular-data bearer, qualified per modem model (L3 fix-list, PR #2148).
- ARC-6 (a) and (c), OP-11's content-store list and the §6.3 paragraph name the new path; a §16 change-log row.

## Acceptance
**Acceptance tests:** none: text-only SPEC change; no requirement gains code, so checks are doclint and the L3 wording review below. The build rows (Wi-Fi upload, picture texts) carry the tests.

Text-only: `python3 tools/doclint.py` passes; `python3 tools/risk_tier.py --git origin/main HEAD` prints B or C; a fresh L3 checks the wording against ARC-6, REV-5, REV-6, CH-3, CH-10, CH-14, CH-21, CAP-3, OP-11. Failure path: a photo of a typed "YES 4821" or a payee's account number is read as an approval or a verified recipient.

## Scope
`SPEC.md` (HW-2, ARC-6, OP-11, §6.3, new §6.4 CH-22 to CH-27, change log), this brief.
