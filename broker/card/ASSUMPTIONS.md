# Owner Card: assumptions

Built for PLAN P2-2 against SPEC v0.12 (§3.1, ONB-7, CH-4, CRED-8). Each row is a
reading of the spec, or a gap left for a later package, that a reviewer may want
to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| C1 | Typed values use one 32-symbol alphabet with no I, O, 0 or 1 (5 bits each), grouped in fours: Wi-Fi password 16 symbols (80 bits, so the WPA2 opt-in's offline-crackable handshake still holds), setup secret 26 (130 bits), recovery key 32 (160 bits). The vault passphrase is 7 words from EFF's large list (90.3 bits; §3.1 asks at least 80). The grid seed is 32 random bytes. | §3.1, CH-7, CRED-8 | Constants in `card.go`. |
| C2 | The setup code is 8 symbols (40 bits) derived from the setup secret by HMAC-SHA-256, so the card prints "the setup secret and its short setup code". It only pairs the owner's number (localui, rate-limited) and never unlocks anything. P2-2 uses the setup secret only through its code; ID-1's other uses of it (re-running setup after a reset) belong to recovery (P2-8). | §3.1, ID-1, CRED-8, ONB-6 | `SetupCodeFor`. |
| C3 | The vault passphrase QR code holds the passphrase text itself, and `NormalizePassphrase` (lower case, single spaces) is the form the passphrase slot (P2-4) derives from. **For P2-4:** a page served over plain HTTP is not a secure context, so browsers deny it the camera; scanning "on the local page" needs a photo upload (`<input type=file capture>`) decoded on the box, or the phone camera app. A QR holding a URL with the passphrase would leave it in browser history and its cloud sync, so this package does not do that. | CRED-8, CH-6 | Payload format in `render.go`. |
| C4 | The paper grid is printed from `owner.GridCell` and `owner.GridLabels` (10x10, 6 digits, O6), so the card and the channel cannot disagree. | CH-4, CH-18 | Owner channel's grid constants. |
| C5 | `WaitMinutes` (3) is provisional until S1 measures boot-to-Wi-Fi on real PCs and ONB-4's target is frozen. | ONB-4, ONB-7 | One constant; the quick-start reads it. |
| C6 | Boot keys are vendor documentation, not yet checked on hardware [Inference]; S1's checklist confirms them. | ONB-7, HW-6 | `BootKeys`. |
| C7 | The card says, beside the passphrase, "If this drive was out of your hands, unlock it only on your trusted PC" (HW-5a's point-of-use text), and to keep the card apart from the drive (risk 10). | HW-5a, CRED-8 | Text only. |
| C8 | Out of scope: provisioning a drive from a card (vault slots, grid seed into the vault: P2-4, P2-8), the DIY first-boot card (HW-1, §8.4), and rotating card secrets from the local UI (REC-4). `Generate` and `HTML` are what those packages call. | HW-1, REC-4 | Later packages. |
| C9 | Reuse: QR encoding is `rsc.io/qr` v0.2.0 (BSD-3, no dependencies of its own, Go authors' encoder); the word list is EFF's file embedded byte for byte, pinned by SHA-256 in a test. Output was checked to decode with OpenCV's QR reader during development. | — | — |
